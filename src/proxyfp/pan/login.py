"""Headed Playwright login. The user signs in, then we persist storage state."""

from __future__ import annotations

from pathlib import Path

from playwright.sync_api import sync_playwright

SESSION_PATH = Path("state/pan_session.json")
PORTAL_URL = "https://urlfiltering.paloaltonetworks.com/"


def login() -> Path:
    SESSION_PATH.parent.mkdir(parents=True, exist_ok=True)
    with sync_playwright() as pw:
        browser = pw.chromium.launch(headless=False)
        ctx = browser.new_context()
        page = ctx.new_page()
        page.goto(PORTAL_URL)
        print(
            "\n  >>> Sign in to Palo Alto, then press Enter here to save the session.\n",
            flush=True,
        )
        input()
        ctx.storage_state(path=str(SESSION_PATH))
        browser.close()
    print(f"Saved session to {SESSION_PATH}")
    return SESSION_PATH
