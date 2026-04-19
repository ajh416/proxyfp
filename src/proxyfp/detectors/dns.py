from __future__ import annotations

import asyncio
import socket
from urllib.parse import urlparse

from proxyfp.detectors import ProbeResult

NAME = "dns"


async def probe(target: str, _client) -> ProbeResult:
    host = urlparse(target).hostname
    if not host:
        return ProbeResult(target, NAME, signal="no_host", weight=0.0)

    loop = asyncio.get_running_loop()
    try:
        addrs = await loop.getaddrinfo(host, None)
    except socket.gaierror as e:
        return ProbeResult(target, NAME, signal="dns_fail", weight=0.0, error=str(e))

    ips = sorted({a[4][0] for a in addrs})
    rdns: list[str] = []
    for ip in ips[:4]:
        try:
            name, _, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
            rdns.append(name)
        except (socket.herror, socket.gaierror):
            rdns.append("")

    # ASN lookup is best-effort; cymruwhois is synchronous so run in executor.
    asns: list[dict] = []
    try:
        from cymruwhois import Client

        def _lookup() -> list[dict]:
            c = Client()
            out = []
            for r in c.lookupmany(ips):
                out.append({"ip": r.ip, "asn": r.asn, "owner": r.owner, "cc": r.cc})
            return out

        asns = await loop.run_in_executor(None, _lookup)
    except Exception as e:  # network or import issue — contextual only
        asns = [{"error": str(e)}]

    return ProbeResult(
        target,
        NAME,
        signal="dns_enriched",
        weight=0.0,
        evidence={"ips": ips, "rdns": rdns, "asn": asns},
    )
