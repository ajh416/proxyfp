"""TLS fingerprint detector (stub).

Real JA4S capture requires a TLS library that exposes server-hello internals
(ja4 reference impl, or tshark/pyshark). For now this detector records the
negotiated version + cipher suite via httpx's transport info as a lightweight
proxy for "something weird" and leaves proper JA4S wiring as a TODO.

Do not rely on this detector for classification until it's replaced with real
JA4S. Its weight is intentionally 0.0.
"""

from __future__ import annotations

import ssl
from urllib.parse import urlparse

from proxyfp.detectors import ProbeResult

NAME = "tls"


async def probe(target: str, _client) -> ProbeResult:
    parsed = urlparse(target)
    if parsed.scheme != "https":
        return ProbeResult(target, NAME, signal="not_https", weight=0.0)

    host = parsed.hostname
    port = parsed.port or 443
    if not host:
        return ProbeResult(target, NAME, signal="no_host", weight=0.0)

    import asyncio

    try:
        ctx = ssl.create_default_context()
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=10.0
        )
        ssl_obj = writer.get_extra_info("ssl_object")
        info = {
            "version": ssl_obj.version() if ssl_obj else None,
            "cipher": ssl_obj.cipher() if ssl_obj else None,
        }
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return ProbeResult(target, NAME, signal="tls_ok", weight=0.0, evidence=info)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as e:
        return ProbeResult(target, NAME, signal="tls_error", weight=0.0, error=str(e))
