# proxyfp

`proxyfp` fingerprints websites that act as open web proxies or anonymizers and
submits confirmed hits to Palo Alto Networks' URL categorization portal under
the `Proxy-Avoidance-and-Anonymizers` category.

It targets the class of sites that exist specifically to bypass network
controls: hosted Glype / PHProxy / CGIProxy installs, and modern JavaScript
stacks like Ultraviolet, Scramjet, Rammerhead, UniUB. Detection is entirely
passive: landing-page regexes, favicon hashes (Shodan-compatible `mmh3`),
and predictable static-asset paths.

## Pipeline

```
input.txt -> fingerprint -> score -> (review) -> pan submit
                  |                                 |
           state/probes.jsonl              state/submissions.jsonl
```

1. **fingerprint** runs every detector against every input URL in parallel
   and appends one JSONL row per `(target, detector)` pair to
   `state/probes.jsonl`. Re-runs are idempotent: already-probed pairs are
   skipped.
2. **score** reads the probes and buckets each target into `auto_submit`,
   `review`, or `drop`.
3. **pan submit** drives a real browser (Playwright + Chromium) against
   `urlfiltering.paloaltonetworks.com` and fills out the "Request Change"
   form once per queued target.

## Install

```sh
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'
playwright install chromium
```

## Quick start

```sh
# 1. Fingerprint a list of candidate URLs / domains (one per line).
proxyfp fingerprint --input targets.txt

# 2. Score and split into auto-submit / manual-review queues.
proxyfp score

# 3. One-time: sign into the Palo Alto portal (opens a real browser).
proxyfp pan login

# 4. Dry-run submission (fills the form, screenshots, does NOT click Submit).
proxyfp pan submit --dry-run

# 5. Real submissions.
proxyfp pan submit
```

## How detection works

Each detector lives in `src/proxyfp/detectors/` and exports an async
`probe(target, client) -> ProbeResult`. A `ProbeResult` carries a short
`signal` label and a `weight` in `[0.0, 1.0]` that reflects how confident
that detector is about its verdict. The scorer combines weights across
detectors to bucket targets.

| Detector | Weight range | What it looks for |
|---|---|---|
| `landing` | up to 0.95 | Regex patterns in the landing HTML for known stacks (Glype, PHProxy, CGIProxy, Privoxy, 3proxy, UniUB, Ultraviolet, Scramjet, Rammerhead, plus a generic "enter a URL" form at 0.45). Signatures live in `signatures/landing_patterns.py`. |
| `favicon` | 0.9 on match | Shodan-compatible `mmh3` hash of `/favicon.ico`, compared against a known-stack dictionary in `signatures/favicons.json`. |
| `stack` | 0.85 to 0.95 | Fetches a small list of predictable static-asset paths (`math/config.js`, `uv/uv.config.js`, `scramjet/scramjet.config.js`, `rammerhead.js`, etc.) and matches regexes against the response body. Necessary because modern JS proxies render client-side, so HTML-only detection misses them. |
| `service_worker` | 0.75 or 0.9 | Parses the landing page for its actual `navigator.serviceWorker.register(path)` call, fetches the registered worker, and classifies the body. 0.9 for a named stack (UV/Scramjet/Rammerhead) found anywhere the fork happened to put its SW; 0.75 for a generic fetch-intercepting worker that rewrites URLs (Bare, `atob`, etc.) but doesn't match a known stack. Catches forks that rename the SW path or serve it from unconventional locations. |
| `dns` | 0.0 | Resolves the target, does rDNS and ASN lookups. Context only; used in review rows. |
| `tls` | 0.0 | Records TLS version + cipher. Stub for future JA4S integration. |

### Scoring and bucketing

Defined in `src/proxyfp/score.py`:

- score = `max(weight across detectors)`, plus a +0.1 corroboration bonus
  if two or more detectors produced weights in `[0.3, 0.85)`.
- Buckets:
  - `auto_submit` requires score >= 0.8 **and** at least one "strong"
    signal (weight >= 0.85). Both conditions must hold, so a corroboration
    bonus alone can't push a target into auto-submit.
  - `review` requires 0.5 <= score < 0.8. These land in `state/review.jsonl`
    for a human to inspect with `proxyfp review`.
  - Everything else is dropped.

`state/auto_submit.jsonl` is regenerated from scratch each time `score`
runs, so re-running is safe.

### Submission

The PAN portal uses a custom Fuel UX "pillbox" form, not native HTML
inputs, and sits behind reCAPTCHA and bot detection.
`src/proxyfp/pan/submit.py` works around this by:

- Reusing a Playwright `storage_state` captured by `proxyfp pan login`, so
  there is never an automated login.
- Typing into inputs one character at a time with 50 to 180 ms random
  jitter per keystroke (see `_human_type`). Instant `fill()` and
  predictable cadence both get flagged.
- Sleeping a uniform random delay between targets (default 3 to 15
  seconds, configurable via `--throttle-min` / `--throttle-max`).
- Screenshotting every attempt to `state/screenshots/` for auditability.
- Idempotency: any target already present in `state/submissions.jsonl`
  with a `submitted*` status is skipped.

Every selector lives in `src/proxyfp/pan/form.py` as a single frozen
dataclass. When the portal UI changes, that file is the only thing to
patch.

## State layout

Everything is append-only JSONL under `state/`:

- `state/probes.jsonl`: one row per `(target, detector, run_at)`.
- `state/review.jsonl`: targets in the review bucket awaiting a human.
- `state/auto_submit.jsonl`: regenerated each `score` run; consumed by `pan submit`.
- `state/submissions.jsonl`: one row per submission attempt, with status and screenshot path.
- `state/pan_session.json`: Playwright storage state for the PAN portal.
- `state/screenshots/`: full-page PNGs of every submission attempt.

## Development

```sh
pytest                                  # all tests
pytest tests/test_score.py              # one file
pytest tests/test_score.py::test_name   # one case
ruff check .                            # lint (line-length 100, py311)
```

Tests are offline: `respx` mocks httpx, and HTML fixtures live in
`tests/fixtures/`.

### Adding a new proxy family

Most new targets fit one of two templates:

1. **Server-rendered** (Glype-style): add a `Signature` entry to
   `signatures/landing_patterns.py` with regexes unique enough that a
   news article mentioning the software wouldn't match.
2. **Client-rendered** (modern JS proxies): add a `(path, regex, label,
   weight)` tuple to `PROBES` in `detectors/stack.py`. Order matters;
   entries are tried top-to-bottom and the first hit wins.

For a distinctive favicon, hash it with `detectors.favicon.shodan_hash`
and add the result to `signatures/favicons.json`.

### Adding a new detector

Create a module under `src/proxyfp/detectors/` that exports:

- `NAME`: short string used as the row's `detector` field.
- `async def probe(target, client) -> ProbeResult`.

Register it by adding the module to `DETECTORS` in
`src/proxyfp/fingerprint.py`. Detectors must never raise: catch exceptions
and return a `ProbeResult` with `weight=0.0` and an `error` field. The
runner will wrap unhandled exceptions too, but detector-local handling
produces better evidence.

## Ethics and scope

This tool is aimed at sites whose stated purpose is to bypass URL
filtering. All detection is passive: ordinary HTTP GETs against the
landing page, favicon, and a few well-known static paths. Landing fetches
cap at 512 KB and are never persisted.

Operate it against networks you're authorized to analyze, respect
`robots.txt` and rate limits when extending it, and keep the review queue
populated by a human rather than widening the auto-submit criteria.

## Layout

```
src/proxyfp/
  cli.py                     Typer app; entry point `proxyfp`.
  fingerprint.py             Detector runner.
  score.py                   Bucketing.
  store.py                   JSONL state helpers.
  detectors/                 One module per detector.
  signatures/                Regex + favicon-hash signature data.
  pan/                       Palo Alto portal automation.
tests/
state/                       Runtime output (gitignored).
```
