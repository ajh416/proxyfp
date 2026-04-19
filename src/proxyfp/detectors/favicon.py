from __future__ import annotations

import base64
import json
from pathlib import Path
from urllib.parse import urljoin

import httpx
import mmh3

from proxyfp.detectors import ProbeResult

NAME = "favicon"
_DB = json.loads((Path(__file__).parent.parent / "signatures" / "favicons.json").read_text())
KNOWN: dict[str, str] = _DB["hashes"]


def shodan_hash(raw: bytes) -> int:
    """Shodan-compatible favicon hash: mmh3 over base64 of the file (with \\n every 76 chars)."""
    b64 = base64.encodebytes(raw).decode()
    return mmh3.hash(b64)


async def probe(target: str, client: httpx.AsyncClient) -> ProbeResult:
    url = urljoin(target.rstrip("/") + "/", "favicon.ico")
    try:
        resp = await client.get(url, follow_redirects=True, timeout=10.0)
    except httpx.HTTPError as e:
        return ProbeResult(target, NAME, signal="fetch_failed", weight=0.0, error=str(e))

    if resp.status_code != 200 or not resp.content:
        return ProbeResult(
            target,
            NAME,
            signal="no_favicon",
            weight=0.0,
            evidence={"status": resp.status_code},
        )

    h = shodan_hash(resp.content)
    label = KNOWN.get(str(h))
    if label:
        return ProbeResult(
            target,
            NAME,
            signal=f"favicon_{label}",
            weight=0.9,
            evidence={"hash": h, "label": label, "size": len(resp.content)},
        )
    return ProbeResult(
        target,
        NAME,
        signal="favicon_unknown",
        weight=0.0,
        evidence={"hash": h, "size": len(resp.content)},
    )
