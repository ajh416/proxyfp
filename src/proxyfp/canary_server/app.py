"""Canary server: records every inbound request that carries a proxyfp nonce.

Deploy this on a public VPS or Cloudflare Worker at e.g. canary.example.com.
The fingerprinter coerces targets to fetch `/probe?nonce=<uuid>&via=<kind>`;
any request that arrives with that nonce from an IP other than the
fingerprinter's own public IP is strong evidence of proxying.

Env vars:
  CANARY_HMAC_KEY  — shared secret required for GET /hits
  CANARY_LOG_PATH  — JSONL append path (default: /var/log/canary.jsonl)
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request

LOG_PATH = Path(os.environ.get("CANARY_LOG_PATH", "/var/log/canary.jsonl"))
HMAC_KEY = os.environ.get("CANARY_HMAC_KEY", "")

app = FastAPI(title="proxyfp canary")


def _require_key(authorization: str | None = Header(default=None)) -> None:
    if not HMAC_KEY:
        raise HTTPException(status_code=503, detail="canary not configured")
    expected = f"Bearer {HMAC_KEY}"
    if authorization != expected:
        raise HTTPException(status_code=401, detail="unauthorized")


def _record(row: dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as f:
        f.write(json.dumps(row, separators=(",", ":"), sort_keys=True))
        f.write("\n")


@app.get("/probe")
async def probe(request: Request, nonce: str = "", via: str = "") -> dict[str, str]:
    row = {
        "ts": time.time(),
        "nonce": nonce,
        "via": via,
        "source_ip": request.client.host if request.client else "",
        "xff": request.headers.get("x-forwarded-for", ""),
        "forwarded": request.headers.get("forwarded", ""),
        "via_header": request.headers.get("via", ""),
        "nonce_header": request.headers.get("x-proxyfp-nonce", ""),
        "ua": request.headers.get("user-agent", ""),
        "host": request.headers.get("host", ""),
        "path": str(request.url.path) + ("?" + str(request.url.query) if request.url.query else ""),
    }
    _record(row)
    return {"ok": "1"}


@app.get("/hits", dependencies=[Depends(_require_key)])
async def hits(since: float = 0.0) -> dict[str, list[dict[str, Any]]]:
    out: list[dict[str, Any]] = []
    if not LOG_PATH.exists():
        return {"hits": out}
    with LOG_PATH.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("ts", 0) >= since and row.get("nonce"):
                out.append(row)
    return {"hits": out}


@app.get("/")
async def index() -> dict[str, str]:
    # Benign landing page — don't advertise what this is.
    return {"status": "ok"}
