"""Path-probe detector for JS-based proxy stacks.

Modern web proxies (UniUB, Ultraviolet, Scramjet, Rammerhead, Womginx, etc.)
render client-side, so regex-over-HTML misses them. But they all ship
recognizable static assets at predictable paths. Fetching a handful of those
paths and matching on the response body is a high-signal, low-cost probe.

Each probe is a (path, regex, label, weight) tuple. We stop at the first hit
(they're ordered by specificity).
"""

from __future__ import annotations

import re
from urllib.parse import urljoin

import httpx

from proxyfp.detectors import ProbeResult

NAME = "stack"

PROBES: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
    (
        "manifest.json",
        re.compile(r'"(short_name|name)"\s*:\s*"UniUB\s*v?\d*"', re.IGNORECASE),
        "uniub_manifest",
        0.95,
    ),
    (
        "math/config.js",
        re.compile(r"__uv\$config", re.IGNORECASE),
        "uniub_uv_config",
        0.95,
    ),
    (
        "scripts/sw.js",
        re.compile(r"(UVServiceWorker|ScramjetServiceWorker)"),
        "uniub_sw",
        0.95,
    ),
    (
        "uv/uv.config.js",
        re.compile(r"__uv\$config"),
        "ultraviolet_config",
        0.9,
    ),
    (
        "uv/uv.sw.js",
        re.compile(r"UVServiceWorker"),
        "ultraviolet_sw",
        0.9,
    ),
    (
        "scramjet/scramjet.config.js",
        re.compile(r"ScramjetConfig|__scramjet\$config"),
        "scramjet_config",
        0.9,
    ),
    (
        "rammerhead.js",
        re.compile(r"rammerhead|RH_SESSION", re.IGNORECASE),
        "rammerhead",
        0.9,
    ),
    # Womginx / generic service-worker proxies: last-resort lookup.
    (
        "service-worker.js",
        re.compile(r"(UVServiceWorker|ScramjetServiceWorker|rammerhead)", re.IGNORECASE),
        "generic_sw_proxy",
        0.85,
    ),
)


async def probe(target: str, client: httpx.AsyncClient) -> ProbeResult:
    base = target if target.endswith("/") else target + "/"
    attempted: list[dict] = []
    for path, rx, label, weight in PROBES:
        url = urljoin(base, path)
        try:
            resp = await client.get(url, follow_redirects=True, timeout=10.0)
        except httpx.HTTPError as e:
            attempted.append({"path": path, "error": str(e)})
            continue
        if resp.status_code != 200 or not resp.content:
            attempted.append({"path": path, "status": resp.status_code})
            continue
        body = resp.text[:256 * 1024]
        if rx.search(body):
            return ProbeResult(
                target,
                NAME,
                signal=label,
                weight=weight,
                evidence={"path": path, "status": resp.status_code, "matched": True},
            )
        attempted.append({"path": path, "status": resp.status_code, "matched": False})

    return ProbeResult(
        target,
        NAME,
        signal="no_stack_match",
        weight=0.0,
        evidence={"attempted": attempted},
    )
