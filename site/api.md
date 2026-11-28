---
title: HTTP API
nav_order: 4
---

# HTTP API

```bash
npm run api   # listens on :8787
```

| Method | Path | Result |
|---|---|---|
| `GET` | `/v1/challenge` | proof-of-work challenge |
| `POST` | `/v1/scan` | traffic light result |
| `GET` | `/health` | liveness |
| `GET` | `/` | the traffic light page from `web/` |

## Scan

```http
POST /v1/scan
Content-Type: application/json

{ "url": "example.com", "lang": "en", "pow": { "...": "solution of /v1/challenge" } }
```

Languages: `de`, `en`, `pt`, `pt-BR`.

## Abuse protection

- **Proof of work:** the browser solves a small puzzle before each scan
  (difficulty 16 ≈ 65,000 hashes, under 2 s). Each challenge is valid for exactly one scan.
  No third-party service, no cookie, no tracking.
- **Per client:** 3/minute, 10/hour, 30/day; IPv6 counts per /64.
- **Per target:** 20/hour per registrable domain (subdomains count together).
  Cached results (10 minutes) do not count.
- **Global:** 300 scans/hour, at most 4 at a time (otherwise `503` with `Retry-After`,
  no quota used).
- **Opt-out:** domains whose operators do not want scans go into `BLOCKED_DOMAINS`.

Counters live in the memory of one process. With several instances they belong in a
shared store (for example Redis).

## Environment

| Variable | Meaning |
|---|---|
| `PORT` | default `8787` |
| `ALLOWED_ORIGINS` | comma-separated CORS origins |
| `TRUST_PROXY=1` | behind your own reverse proxy (otherwise the proxy IP is counted) |
| `POW_SECRET` | fixed key so challenges survive a restart |
| `POW_DIFFICULTY` | default `16` |
| `BLOCKED_DOMAINS` | comma-separated opt-out list |
