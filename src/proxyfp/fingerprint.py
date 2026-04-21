"""Run every detector against every target, concurrently, writing to probes.jsonl."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from proxyfp import store
from proxyfp.detectors import ProbeResult, dns, favicon, landing, service_worker, stack, tls

DETECTORS = (landing, stack, service_worker, favicon, tls, dns)
USER_AGENT = "Mozilla/5.0 (compatible; proxyfp/0.1)"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize(raw: str) -> str:
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        return ""
    if "://" not in raw:
        raw = "http://" + raw
    return raw


async def _run_one(target: str, client: httpx.AsyncClient, sem: asyncio.Semaphore) -> list[ProbeResult]:
    async with sem:
        tasks = [det.probe(target, client) for det in DETECTORS]
        results: list[ProbeResult] = []
        for coro in asyncio.as_completed(tasks):
            try:
                results.append(await coro)
            except Exception as e:  # detector crashed; don't kill the target
                results.append(
                    ProbeResult(target, "unknown", signal="detector_exception", weight=0.0, error=str(e))
                )
        return results


async def fingerprint_all(targets: list[str], concurrency: int = 8) -> None:
    targets = [t for t in (_normalize(x) for x in targets) if t]
    already = store.load_keys(store.PROBES, "target", "detector")
    sem = asyncio.Semaphore(concurrency)
    limits = httpx.Limits(max_keepalive_connections=concurrency * 2, max_connections=concurrency * 4)
    # For fingerprinting we intentionally skip TLS verification: we're probing
    # sketchy proxy sites, many of which have bad certs, and we don't rely on
    # trust here.
    async with httpx.AsyncClient(
        headers={"User-Agent": USER_AGENT},
        limits=limits,
        verify=False,
        http2=True,
    ) as client:
        tasks = [_run_one(t, client, sem) for t in targets]
        for done in asyncio.as_completed(tasks):
            results = await done
            now = _now()
            for r in results:
                if (r.target, r.detector) in already:
                    continue
                store.append(store.PROBES, r.to_row(now))
