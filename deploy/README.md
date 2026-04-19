# Canary deploy — VPS + nginx + Cloudflare

One-time setup. Uvicorn binds to `127.0.0.1:8787`; nginx reverse-proxies from your Cloudflare-fronted hostname.

## 1. Generate the shared secret (ONCE)

```sh
openssl rand -hex 32
```

Copy the output. You'll paste the same value in two places: `/etc/canary.env` on the VPS, and your local shell (the fingerprinter needs it to fetch `/hits`). If you ever regenerate, both sides must update.

## 2. On the VPS

```sh
# Create a dedicated user and install dir
sudo useradd --system --home /opt/canary --shell /usr/sbin/nologin canary
sudo mkdir -p /opt/canary /var/lib/canary
sudo chown -R canary:canary /opt/canary /var/lib/canary

# Deploy the code (adjust to your workflow — git clone, rsync, etc.)
sudo -u canary git clone <your-repo> /opt/canary/src
sudo -u canary python3 -m venv /opt/canary/.venv
# Base install only — canary server needs fastapi+uvicorn, nothing else.
# Do NOT install the [fingerprint] extra here; that's for your laptop.
sudo -u canary /opt/canary/.venv/bin/pip install /opt/canary/src

# Env file with the key from step 1
sudo cp /opt/canary/src/deploy/canary.env.example /etc/canary.env
sudo vim /etc/canary.env            # paste the real key
sudo chmod 640 /etc/canary.env
sudo chown root:canary /etc/canary.env

# systemd unit
sudo cp /opt/canary/src/deploy/canary.service /etc/systemd/system/canary.service
sudo systemctl daemon-reload
sudo systemctl enable --now canary
sudo systemctl status canary        # should be "active (running)"
curl -s http://127.0.0.1:8787/      # => {"status":"ok"}
```

## 3. nginx

```sh
sudo cp /opt/canary/src/deploy/canary.nginx.conf /etc/nginx/sites-available/canary
sudo vim /etc/nginx/sites-available/canary     # set server_name
sudo ln -s /etc/nginx/sites-available/canary /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

In Cloudflare: add an A/AAAA record for `canary.yourdomain.com` → VPS IP, proxied (orange cloud). SSL/TLS mode "Full" is enough since Cloudflare → origin is HTTP inside the tunnel; if you want Full (strict), drop a CF Origin Cert into nginx.

## 4. Smoke test from your laptop

```sh
curl -sS https://canary.yourdomain.com/probe?nonce=smoketest\&via=manual
# => {"ok":"1"}

curl -sS -H "Authorization: Bearer <THE KEY>" https://canary.yourdomain.com/hits | jq .
# => {"hits":[{"nonce":"smoketest",...}]}
```

If both work, you're done.

## 5. Point the fingerprinter at it

On the laptop (or wherever you run `proxyfp`):

```sh
export CANARY_BASE_URL=https://canary.yourdomain.com
export CANARY_HMAC_KEY=<same key from step 1>
```

Put these in your shell rc or a `.envrc` (direnv) so they persist across sessions.

## Operations

- **Logs:** `journalctl -u canary -f` and `/var/log/nginx/canary.*.log`.
- **Hit file:** `/var/lib/canary/hits.jsonl` — append-only; rotate with logrotate if it grows.
- **Updates:** `cd /opt/canary/src && sudo -u canary git pull && sudo systemctl restart canary`.
- **Restart on reboot:** already handled — `systemctl enable` took care of that in step 2.

## Key rotation

If the key leaks:
1. Generate a new one.
2. Update `/etc/canary.env` on the VPS, `sudo systemctl restart canary`.
3. Update `CANARY_HMAC_KEY` in your laptop shell.

Nonces are not secret; only the `/hits` endpoint uses the key, so rotation doesn't invalidate historical canary data.
