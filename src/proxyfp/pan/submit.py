"""Iterate the submission queue and drive the PAN form via Playwright."""

from __future__ import annotations

import random
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from playwright.sync_api import Page, TimeoutError as PWTimeout, sync_playwright

from proxyfp import store
from proxyfp.pan.form import (
    PORTAL_URL,
    PROXY_CATEGORY_ID,
    PROXY_CATEGORY_NAME,
    SELECTORS,
)
from proxyfp.pan.login import SESSION_PATH

SCREENSHOT_DIR = Path("state/screenshots")


class NotAuthenticatedError(RuntimeError):
    pass


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _human_type(page: Page, selector: str, text: str) -> None:
    """Type text into `selector` one char at a time with small randomized delays.

    Why: the portal sits behind reCAPTCHA and bot detection; instantaneous
    `fill()` and predictable cadence are both flagged. Per-keystroke jitter
    looks closer to a human.
    """
    loc = page.locator(selector).first
    loc.click()
    loc.fill("")
    for ch in text:
        page.keyboard.type(ch)
        time.sleep(random.uniform(0.05, 0.18))


def _check_authenticated(page: Page) -> None:
    if page.locator(SELECTORS.logged_in_indicator).count() > 0:
        return
    if page.locator(SELECTORS.login_indicator).count() > 0:
        raise NotAuthenticatedError(
            "PAN portal is asking us to log in. Run `proxyfp pan login` and retry."
        )
    raise NotAuthenticatedError(
        "PAN portal session is not logged in (no logout link found). "
        "Run `proxyfp pan login` and retry."
    )


def _build_comment(target: str, contributing: list[dict[str, Any]]) -> str:
    return "This site provides a proxy."


def _submit_one(page: Page, target: str, comment: str, dry_run: bool) -> dict[str, Any]:
    SCREENSHOT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = int(time.time())
    safe_target = target.replace("://", "_").replace("/", "_")[:80]
    screenshot = SCREENSHOT_DIR / f"{stamp}_{safe_target}.png"

    page.goto(PORTAL_URL, wait_until="domcontentloaded")
    _check_authenticated(page)

    _human_type(page, SELECTORS.url_input, target)
    time.sleep(random.uniform(0.3, 0.8))
    page.locator(SELECTORS.url_submit).first.click()
    page.locator(SELECTORS.request_change_button).first.wait_for(timeout=20_000)
    page.locator(SELECTORS.request_change_button).first.click()

    # Change form: open category dropdown, filter, pick the proxy category.
    page.locator(SELECTORS.add_category_btn).first.wait_for(timeout=20_000)
    page.locator(SELECTORS.add_category_btn).first.click()
    _human_type(page, SELECTORS.category_search_input, "Proxy")
    time.sleep(random.uniform(0.2, 0.5))
    item = page.locator(SELECTORS.category_list_item.format(id=PROXY_CATEGORY_ID)).first
    item.wait_for(timeout=10_000)
    item.click()
    # Confirm the pill was added before proceeding.
    page.locator(SELECTORS.category_pill.format(name=PROXY_CATEGORY_NAME)).first.wait_for(timeout=5_000)

    # Dropdown stays open after selection and Escape doesn't close it;
    # click a neutral spot on the page to dismiss it.
    page.locator("h1").first.click()
    time.sleep(random.uniform(0.2, 0.5))

    _human_type(page, SELECTORS.comment_textarea, comment)

    if dry_run:
        page.screenshot(path=str(screenshot), full_page=True)
        return {"status": "dry_run", "screenshot_path": str(screenshot), "ticket_id": None}

    page.locator(SELECTORS.form_submit).first.click()
    try:
        page.locator(SELECTORS.confirmation_locator).first.wait_for(timeout=20_000)
        status = "submitted"
    except PWTimeout:
        status = "submitted_unconfirmed"
    page.screenshot(path=str(screenshot), full_page=True)
    confirmation_text = ""
    try:
        confirmation_text = page.locator(SELECTORS.confirmation_locator).first.inner_text(timeout=2_000)
    except PWTimeout:
        pass
    return {
        "status": status,
        "screenshot_path": str(screenshot),
        "ticket_id": None,
        "confirmation": confirmation_text,
    }


def submit_queue(
    queue: list[dict[str, Any]],
    dry_run: bool = False,
    throttle_min_s: float = 3.0,
    throttle_max_s: float = 15.0,
) -> None:
    if not SESSION_PATH.exists():
        raise NotAuthenticatedError(f"{SESSION_PATH} missing. Run `proxyfp pan login` first.")

    already = {row["target"] for row in store.read(store.SUBMISSIONS) if row.get("status", "").startswith("submitted")}
    queue = [q for q in queue if q["target"] not in already]
    if not queue:
        print("Nothing to submit (queue empty after idempotency filter).")
        return

    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=not dry_run)
        ctx = browser.new_context(storage_state=str(SESSION_PATH))
        page = ctx.new_page()

        for i, item in enumerate(queue):
            target = item["target"]
            comment = _build_comment(target, item.get("contributing", []))
            try:
                result = _submit_one(page, target, comment, dry_run)
                row = {
                    "target": target,
                    "submitted_at": _now(),
                    **result,
                    "evidence_summary": comment,
                }
                store.append(store.SUBMISSIONS, row)
                print(f"[{i + 1}/{len(queue)}] {target}: {result['status']}")
            except NotAuthenticatedError:
                browser.close()
                raise
            except Exception as e:
                store.append(
                    store.SUBMISSIONS,
                    {
                        "target": target,
                        "submitted_at": _now(),
                        "status": "error",
                        "error": str(e),
                        "screenshot_path": None,
                    },
                )
                print(f"[{i + 1}/{len(queue)}] {target}: ERROR {e}")

            if i + 1 < len(queue):
                time.sleep(random.uniform(throttle_min_s, throttle_max_s))

        browser.close()
