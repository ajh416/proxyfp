"""Certificate Transparency harvester.

Streams new certificate issuances from the Certstream WebSocket feed, filters
hostnames by (proxy-suggestive token + free-tier platform suffix), and
appends unique matches to an output file that `proxyfp fingerprint` can
consume directly.

Why both conditions? Tokens alone ("proxy", "unblock") are too noisy;
platform suffixes alone match every indie project on Vercel. The
intersection is a tight filter for "someone just deployed a proxy on a
free tier" which is where the student-discoverable long tail lives.
"""

from __future__ import annotations

import asyncio
import json
import signal
import sys
from pathlib import Path
from typing import Iterable

CERTSTREAM_URL = "wss://certstream.calidog.io/"

# Tokens that suggest a proxy/unblocker site. Case-insensitive substring
# match against the hostname. Keep proxy-adjacent; broaden only together
# with a platform gate.
DEFAULT_TOKENS: tuple[str, ...] = (
    "ultraviolet", "scramjet", "rammerhead", "womginx", "bareserver",
    "unblock", "unblocker", "webproxy", "proxysite", "anonymweb",
    "schoolproxy", "incogni", "cloak", "holyunblocker", "holy-unblocker",
    "ephemeral-proxy", "interstellar", "nebula-proxy", "celestial-proxy",
    "shuttle-proxy", "titanium-proxy", "utopia-proxy", "hideme-web",
    "freebrowse", "pr0xy", "proxied", "browse-anon", "bypass-school",
)

# Free-tier / shared-hosting suffixes where proxy forks concentrate.
DEFAULT_PLATFORMS: tuple[str, ...] = (
    ".vercel.app",
    ".pages.dev",
    ".onrender.com",
    ".netlify.app",
    ".koyeb.app",
    ".replit.app",
    ".repl.co",
    ".glitch.me",
    ".fly.dev",
    ".hf.space",
    ".deno.dev",
    ".workers.dev",
    ".railway.app",
)


class Matcher:
    """Matches hostnames that contain any token AND end in any platform suffix.

    Hyphens in both the hostname and the token list are normalized away
    before comparison, so `school-proxy` and `schoolproxy` are equivalent.
    """

    def __init__(self, tokens: Iterable[str], platforms: Iterable[str]):
        self._tokens = tuple(t.lower().replace("-", "") for t in tokens)
        self._platforms = tuple(p.lower() for p in platforms)

    def match(self, host: str) -> bool:
        h = host.lower()
        if not any(h.endswith(p) for p in self._platforms):
            return False
        stripped = h.replace("-", "")
        return any(t in stripped for t in self._tokens)


def build_matcher(
    tokens: Iterable[str] = DEFAULT_TOKENS,
    platforms: Iterable[str] = DEFAULT_PLATFORMS,
) -> Matcher:
    return Matcher(tokens, platforms)


def iter_hostnames(message: dict) -> Iterable[str]:
    if message.get("message_type") != "certificate_update":
        return ()
    data = message.get("data") or {}
    leaf = data.get("leaf_cert") or {}
    names = leaf.get("all_domains") or []
    out: list[str] = []
    for n in names:
        if not isinstance(n, str):
            continue
        host = n.lstrip("*.").lower().strip()
        if host:
            out.append(host)
    return out


class Sink:
    """Append-only deduped sink backed by a file (or stdout)."""

    def __init__(self, path: Path | None):
        self.path = path
        self.seen: set[str] = set()
        if path and path.exists():
            self.seen = {ln.strip() for ln in path.read_text().splitlines() if ln.strip()}
            path.parent.mkdir(parents=True, exist_ok=True)
        elif path:
            path.parent.mkdir(parents=True, exist_ok=True)

    def add(self, host: str) -> bool:
        if host in self.seen:
            return False
        self.seen.add(host)
        line = host + "\n"
        if self.path is None:
            sys.stdout.write(line)
            sys.stdout.flush()
        else:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line)
        return True


async def run_ct(
    output: Path | None,
    tokens: Iterable[str] = DEFAULT_TOKENS,
    platforms: Iterable[str] = DEFAULT_PLATFORMS,
    url: str = CERTSTREAM_URL,
) -> None:
    import websockets  # imported lazily so `proxyfp` CLI loads without it

    matcher = build_matcher(tokens, platforms)
    sink = Sink(output)
    stop = asyncio.Event()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    backoff = 1.0
    while not stop.is_set():
        try:
            async with websockets.connect(url, max_size=4 * 1024 * 1024) as ws:
                backoff = 1.0
                while not stop.is_set():
                    raw = await asyncio.wait_for(ws.recv(), timeout=60.0)
                    try:
                        msg = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    for host in iter_hostnames(msg):
                        if matcher.match(host):
                            sink.add(host)
        except asyncio.TimeoutError:
            continue
        except Exception as e:
            print(f"[ct] reconnect in {backoff:.1f}s after error: {e}", file=sys.stderr)
            try:
                await asyncio.wait_for(stop.wait(), timeout=backoff)
            except asyncio.TimeoutError:
                pass
            backoff = min(backoff * 2, 60.0)
