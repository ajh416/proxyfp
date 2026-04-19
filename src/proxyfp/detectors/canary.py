"""Canary egress detector — strongest signal in the pipeline.

Attempts to coerce the target into fetching a canary URL under our control.
After probing, we query the canary server's /hits API to see which nonces
actually arrived and from which source IPs. A nonce echoed from a source IP
that is *not* ours implies the target proxied the request.

Transports attempted (in order):
  1. HTTP CONNECT tunnel (classic proxy)
  2. Absolute-form GET (HTTP/1.1 GET http://canary/... Host: canary)
  3. SOCKS5 / SOCKS4 on 1080, 3128, 8080, 8888
  4. URL-in-query via detected proxy forms (see headers.py)

Correlation with the canary server is done in a follow-up step (post-fingerprint);
see `confirm_from_canary()`.
"""

from __future__ import annotations

import asyncio
import os
import socket
import uuid
from urllib.parse import urlparse

import httpx

from proxyfp.detectors import ProbeResult

NAME = "canary"
CANARY_BASE = os.environ.get("CANARY_BASE_URL", "").rstrip("/")
CANARY_KEY = os.environ.get("CANARY_HMAC_KEY", "")
SOCKS_PORTS = (1080, 3128, 8080, 8888)
CONNECT_TIMEOUT = 8.0


def _nonce() -> str:
    return uuid.uuid4().hex


def _canary_url(nonce: str, via: str) -> str:
    return f"{CANARY_BASE}/probe?nonce={nonce}&via={via}"


async def _try_connect(host: str, port: int, nonce: str) -> dict:
    """Attempt HTTP CONNECT to our canary through target:port."""
    canary_host = urlparse(CANARY_BASE).hostname or ""
    canary_port = 443 if CANARY_BASE.startswith("https") else 80
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError) as e:
        return {"transport": f"CONNECT:{port}", "error": str(e)}

    req = (
        f"CONNECT {canary_host}:{canary_port} HTTP/1.1\r\n"
        f"Host: {canary_host}:{canary_port}\r\n"
        f"X-Proxyfp-Nonce: {nonce}\r\n"
        f"\r\n"
    )
    try:
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(256), timeout=CONNECT_TIMEOUT)
        status_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
        return {"transport": f"CONNECT:{port}", "response": status_line}
    except (OSError, asyncio.TimeoutError) as e:
        return {"transport": f"CONNECT:{port}", "error": str(e)}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _try_absolute_form(host: str, port: int, nonce: str) -> dict:
    """Send HTTP/1.1 request with absolute-form URI (proxy semantics)."""
    url = _canary_url(nonce, f"abs-{port}")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError) as e:
        return {"transport": f"abs:{port}", "error": str(e)}

    canary_host = urlparse(CANARY_BASE).hostname or ""
    req = (
        f"GET {url} HTTP/1.1\r\n"
        f"Host: {canary_host}\r\n"
        f"X-Proxyfp-Nonce: {nonce}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    )
    try:
        writer.write(req.encode())
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=CONNECT_TIMEOUT)
        status_line = data.split(b"\r\n", 1)[0].decode(errors="replace")
        return {"transport": f"abs:{port}", "response": status_line}
    except (OSError, asyncio.TimeoutError) as e:
        return {"transport": f"abs:{port}", "error": str(e)}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _try_socks5(host: str, port: int, nonce: str) -> dict:
    """Minimal SOCKS5 no-auth handshake — we're just checking if the server speaks it."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=CONNECT_TIMEOUT
        )
    except (OSError, asyncio.TimeoutError) as e:
        return {"transport": f"socks5:{port}", "error": str(e)}
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        reply = await asyncio.wait_for(reader.read(2), timeout=CONNECT_TIMEOUT)
        if len(reply) == 2 and reply[0] == 5:
            return {"transport": f"socks5:{port}", "handshake": reply.hex(), "nonce": nonce}
        return {"transport": f"socks5:{port}", "handshake": reply.hex() if reply else ""}
    except (OSError, asyncio.TimeoutError) as e:
        return {"transport": f"socks5:{port}", "error": str(e)}
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def probe(target: str, _client: httpx.AsyncClient) -> ProbeResult:
    if not CANARY_BASE:
        return ProbeResult(target, NAME, signal="disabled", weight=0.0, error="CANARY_BASE_URL not set")

    parsed = urlparse(target)
    host = parsed.hostname
    if not host:
        return ProbeResult(target, NAME, signal="no_host", weight=0.0)

    nonce = _nonce()
    candidate_ports = sorted({parsed.port or (443 if parsed.scheme == "https" else 80), *SOCKS_PORTS})

    tasks: list = []
    for p in candidate_ports:
        tasks.append(_try_connect(host, p, nonce))
        tasks.append(_try_absolute_form(host, p, nonce))
        tasks.append(_try_socks5(host, p, nonce))

    attempts = await asyncio.gather(*tasks, return_exceptions=False)

    # We do not know yet whether the canary received the nonce — that check
    # happens in confirm_from_canary(). Emit a low-weight row with the nonce
    # so the scorer can correlate later.
    return ProbeResult(
        target,
        NAME,
        signal="canary_emitted",
        weight=0.0,
        evidence={"nonce": nonce, "attempts": attempts, "host": host},
    )


async def confirm_from_canary(client: httpx.AsyncClient) -> dict[str, list[dict]]:
    """Query the canary server for hits. Returns {nonce: [hit, ...]}.

    The canary server is expected to expose GET /hits?since=<ts> requiring the
    shared HMAC key as a bearer token.
    """
    if not CANARY_BASE or not CANARY_KEY:
        return {}
    resp = await client.get(
        f"{CANARY_BASE}/hits",
        headers={"Authorization": f"Bearer {CANARY_KEY}"},
        timeout=15.0,
    )
    resp.raise_for_status()
    hits: list[dict] = resp.json().get("hits", [])
    by_nonce: dict[str, list[dict]] = {}
    our_ips = _local_ips()
    for h in hits:
        if h.get("source_ip") in our_ips:
            continue  # ignore our own direct hits
        by_nonce.setdefault(h["nonce"], []).append(h)
    return by_nonce


def _local_ips() -> set[str]:
    ips: set[str] = set()
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            ips.add(info[4][0])
    except OSError:
        pass
    # Also fetch our public IP via the canary's echo endpoint if configured;
    # for now rely on the canary server to tag self-hits.
    return ips
