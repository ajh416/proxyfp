from __future__ import annotations

import httpx

from proxyfp.detectors import ProbeResult
from proxyfp.signatures.landing_patterns import match

NAME = "landing"
MAX_BYTES = 512 * 1024


async def probe(target: str, client: httpx.AsyncClient) -> ProbeResult:
    try:
        resp = await client.get(target, follow_redirects=True, timeout=15.0)
    except httpx.HTTPError as e:
        return ProbeResult(target, NAME, signal="fetch_failed", weight=0.0, error=str(e))

    html = resp.text[:MAX_BYTES]
    matches = match(html)
    if not matches:
        return ProbeResult(
            target,
            NAME,
            signal="no_match",
            weight=0.0,
            evidence={"status": resp.status_code, "final_url": str(resp.url)},
        )

    top_sig, top_hits = max(matches, key=lambda m: (m[0].weight, m[1]))
    return ProbeResult(
        target,
        NAME,
        signal=top_sig.name,
        weight=top_sig.weight,
        evidence={
            "status": resp.status_code,
            "final_url": str(resp.url),
            "hits": top_hits,
            "all_matches": [{"name": s.name, "hits": h} for s, h in matches],
        },
    )
