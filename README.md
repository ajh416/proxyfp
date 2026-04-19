# proxyfp

Fingerprint sites as web proxies / anonymizers and submit confirmed hits to Palo Alto's URL categorization (`proxy-avoidance-and-anonymizers`).

## Install

```sh
uv venv && source .venv/bin/activate
uv pip install -e '.[dev]'
playwright install chromium
```

## Pipeline

```
input.txt → fingerprint → score → (review) → submit
                ↓                              ↓
         state/probes.jsonl          state/submissions.jsonl
```

## Quick start

```sh
# 1. Deploy the canary server somewhere public; set CANARY_BASE_URL and CANARY_HMAC_KEY
export CANARY_BASE_URL=https://canary.example.com
export CANARY_HMAC_KEY=$(openssl rand -hex 32)

# 2. Fingerprint a list of candidate URLs/domains
proxyfp fingerprint --input targets.txt

# 3. Score and split into auto-submit / manual-review queues
proxyfp score

# 4. One-time: sign into urlfiltering.paloaltonetworks.com (headed Chromium)
proxyfp pan login

# 5. Dry-run submission (fills form, screenshots, does NOT click final submit)
proxyfp pan submit --dry-run

# 6. Real submissions
proxyfp pan submit
```

## Layout

See `/Users/adam/.claude/plans/i-want-to-fingerprint-deep-knuth.md` for the full design.
