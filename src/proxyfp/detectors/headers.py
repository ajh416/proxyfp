"""Header-echo probe: ask the target to fetch our canary with tracer headers;
if the canary sees those headers (possibly modified), the target is proxying.

This detector relies on having already identified a proxy form URL via the
landing detector (e.g. Glype's browse.php). For raw HTTP proxies the canary
detector covers CONNECT/absolute-form. Here we just record whether the target
accepts a URL-in-query pattern that produces a canary hit.
"""

from __future__ import annotations

import os
import uuid
from urllib.parse import urlencode

import httpx

from proxyfp.detectors import ProbeResult

NAME = "headers"
CANARY_BASE = os.environ.get("CANARY_BASE_URL", "").rstrip("/")


def _canary_url(nonce: str) -> str:
    return f"{CANARY_BASE}/probe?{urlencode({'nonce': nonce, 'via': 'headers'})}"


async def probe(target: str, client: httpx.AsyncClient) -> ProbeResult:
    if not CANARY_BASE:
        return ProbeResult(target, NAME, signal="disabled", weight=0.0, error="CANARY_BASE_URL not set")

    nonce = uuid.uuid4().hex
    tracer_headers = {
        "X-Proxyfp-Nonce": nonce,
        "Via": "1.1 proxyfp-probe",
        "X-Forwarded-For": "203.0.113.7",
    }
    # Try common "fetch a URL" patterns observed on proxy landing pages.
    candidates = [
        f"{target.rstrip('/')}/browse.php?u={_canary_url(nonce)}",
        f"{target.rstrip('/')}/index.php?q={_canary_url(nonce)}",
        f"{target.rstrip('/')}/nph-proxy.cgi/{_canary_url(nonce)}",
    ]
    attempts: list[dict] = []
    for url in candidates:
        try:
            resp = await client.get(
                url, headers=tracer_headers, follow_redirects=True, timeout=20.0
            )
            attempts.append({"url": url, "status": resp.status_code})
        except httpx.HTTPError as e:
            attempts.append({"url": url, "error": str(e)})

    # Confirmation comes from the canary server, not here — see canary.py.
    # This detector just records the nonce it emitted; the scorer correlates.
    return ProbeResult(
        target,
        NAME,
        signal="headers_emitted",
        weight=0.0,
        evidence={"nonce": nonce, "attempts": attempts},
    )
