"""Landing-driven service-worker detector.

`stack.py` probes a fixed list of well-known SW paths (uv/uv.sw.js, etc.).
This detector instead parses the landing page for its actual
`navigator.serviceWorker.register("<path>")` call, fetches the registered
worker, and classifies the body. That catches forks that rename the SW
path or serve it from an unconventional location.

Labels:
  sw_ultraviolet / sw_scramjet / sw_rammerhead -> 0.9  (named stack)
  sw_fetch_proxy_generic                       -> 0.75 (unnamed but
    intercepts fetch and rewrites URLs / uses Bare or atob)
  otherwise no hit
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from proxyfp.detectors import ProbeResult

NAME = "service_worker"
LANDING_MAX_BYTES = 512 * 1024
SW_MAX_BYTES = 512 * 1024

_REGISTER_RX = re.compile(
    r"""navigator\s*\.\s*serviceWorker\s*\.\s*register\s*\(\s*['"]([^'"]+)['"]""",
    re.IGNORECASE,
)

_NAMED_STACKS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"UVServiceWorker|__uv\$config|BareClient", re.IGNORECASE), "sw_ultraviolet"),
    (re.compile(r"ScramjetServiceWorker|__scramjet\$config", re.IGNORECASE), "sw_scramjet"),
    (re.compile(r"rammerhead|RH_SESSION", re.IGNORECASE), "sw_rammerhead"),
)

_FETCH_HANDLER_RX = re.compile(
    r"""(?:addEventListener\s*\(\s*['"]fetch['"]|self\s*\.\s*onfetch\s*=)""",
    re.IGNORECASE,
)

_REWRITE_HINTS_RX = re.compile(
    r"""(?:
        bareServer | bareClient | BareClient |
        atob\s*\( |
        new\s+URL\s*\([^)]*event\s*\.\s*request\s*\.\s*url |
        decodeURIComponent\s*\([^)]*request\.url
    )""",
    re.IGNORECASE | re.VERBOSE,
)


async def probe(target: str, client: httpx.AsyncClient) -> ProbeResult:
    try:
        landing = await client.get(target, follow_redirects=True, timeout=15.0)
    except httpx.HTTPError as e:
        return ProbeResult(target, NAME, signal="fetch_failed", weight=0.0, error=str(e))

    landing_url = str(landing.url)
    html = landing.text[:LANDING_MAX_BYTES]
    sw_paths = list(dict.fromkeys(_REGISTER_RX.findall(html)))
    if not sw_paths:
        return ProbeResult(
            target, NAME, signal="no_sw_register", weight=0.0,
            evidence={"final_url": landing_url},
        )

    attempts: list[dict] = []
    for path in sw_paths[:4]:
        sw_url = urljoin(landing_url, path)
        try:
            resp = await client.get(sw_url, follow_redirects=True, timeout=15.0)
        except httpx.HTTPError as e:
            attempts.append({"path": path, "error": str(e)})
            continue
        if resp.status_code != 200 or not resp.content:
            attempts.append({"path": path, "status": resp.status_code})
            continue
        body = resp.text[:SW_MAX_BYTES]

        for rx, label in _NAMED_STACKS:
            if rx.search(body):
                return ProbeResult(
                    target, NAME, signal=label, weight=0.9,
                    evidence={"sw_url": sw_url, "landing_url": landing_url},
                )

        if _FETCH_HANDLER_RX.search(body) and _REWRITE_HINTS_RX.search(body):
            return ProbeResult(
                target, NAME, signal="sw_fetch_proxy_generic", weight=0.75,
                evidence={"sw_url": sw_url, "landing_url": landing_url},
            )

        attempts.append({"path": path, "status": 200, "matched": False})

    return ProbeResult(
        target, NAME, signal="sw_no_proxy_signal", weight=0.0,
        evidence={"final_url": landing_url, "attempted": attempts},
    )
