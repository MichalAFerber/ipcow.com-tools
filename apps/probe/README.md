# ipcow probe server

A small per-stack network agent (Go, stdlib only — a single static binary). Two instances
run on Hetzner, one per family, fronted by Caddy for automatic HTTPS:

| Host | Box | `PROBE_STACK` | DNS |
| --- | --- | --- | --- |
| `ipv4.ipcow.com` | `tgwab-ipcow-ipv4` (138.201.119.247) | `ipv4` | A only, **grey-cloud** |
| `ipv6.ipcow.com` | `tgwab-ipcow-ipv6` (2a01:4f8:c013:5039::1) | `ipv6` | AAAA only, **grey-cloud** |

> **DNS must be DNS-only (grey cloud).** If proxied through Cloudflare, the IP echo
> reflects Cloudflare's edge, not the visitor, and the forced-stack trick breaks.

## Endpoints

| Route | Auth | Purpose |
| --- | --- | --- |
| `GET /` | public (CORS) | IP echo — `{ "ip", "stack" }`. The site hero calls this directly. |
| `GET /healthz` | public | liveness |
| `GET /probe/dns?host=` | `X-Probe-Key` | resolve A/AAAA |
| `GET /probe/tcp?host=&port=` | `X-Probe-Key` | TCP connect timing |
| `GET /probe/http?url=` | `X-Probe-Key` | HTTP GET status + timing |
| `GET /probe/ping?host=` | `X-Probe-Key` | ICMP ping (avg rtt) |
| `GET /probe/smtp?host=&port=25` | `X-Probe-Key` | SMTP banner (mostly the v4 box) |
| `GET /speedtest/download?bytes=` | public (CORS) | streams N bytes for a download test |
| `POST /speedtest/upload` | public (CORS) | discards the body, reports bytes + timing |
| `GET /ws` | public (CORS) | WebSocket echo (connectivity test) |

Probe endpoints return structured JSON including `ok`, `stack`, `elapsed_ms`, and a
human-readable `error` on socket failures (surfaced to users as the Ookla-style alert).
Every operation is pinned to the box's stack (`tcp4`/`tcp6`, `ip4`/`ip6`).

## Build

One dependency (`github.com/coder/websocket`); `go build` fetches it.

```bash
cd apps/probe
go build -o ipcow-probe .
# or cross-compile from your laptop:
GOOS=linux GOARCH=amd64 go build -o ipcow-probe .
```

## Deploy (per box)

```bash
# 1. Binary
sudo mkdir -p /opt/ipcow-probe
scp ipcow-probe root@<box>:/opt/ipcow-probe/

# 2. Config
scp .env.example root@<box>:/etc/ipcow-probe.env
sudo editor /etc/ipcow-probe.env      # set PROBE_STACK + the shared PROBE_KEY

# 3. Service
scp deploy/ipcow-probe.service root@<box>:/etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now ipcow-probe

# 4. TLS / reverse proxy
sudo PROBE_DOMAIN=ipv4.ipcow.com caddy run --config Caddyfile   # or run Caddy as a service
```

On the **IPv6-only box**, build Caddy with the Cloudflare DNS module and use the
DNS-01 challenge (see the commented block in the `Caddyfile`) — HTTP-01 can't validate
without a v4 path.

## Auth

Every `/probe/*` call must carry `X-Probe-Key: $PROBE_KEY`. Generate once with
`openssl rand -hex 32`, put it in `/etc/ipcow-probe.env` on **both** boxes, and store the
same value as a secret on the web app (`PROBE_KEY`) so the `/api/probe` route can sign its
fan-out requests.

## Verify

```bash
curl https://ipv4.ipcow.com/                                   # {"ip":"<your v4>","stack":"ipv4"}
curl https://ipv6.ipcow.com/                                   # {"ip":"<your v6>","stack":"ipv6"}
curl -H "x-probe-key: $KEY" "https://ipv4.ipcow.com/probe/dns?host=example.com"
```
