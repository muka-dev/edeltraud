---
title: Self-hosting
nav_order: 5
---

# Self-hosting with Docker

The API image needs no browser and runs the free quick check:

```bash
docker build -t edeltraud-api .
docker run -d --name edeltraud -p 8787:8787 \
  -e TRUST_PROXY=1 -e POW_SECRET="$(openssl rand -hex 32)" \
  edeltraud-api
curl http://localhost:8787/health
```

`Dockerfile.worker` adds Playwright and Chromium for the `report` and `deep` plans.

## Behind Caddy

```caddyfile
scan.example.com {
  encode zstd gzip
  reverse_proxy edeltraud:8787
}
```

Set `TRUST_PROXY=1` so rate limits count the client, not the proxy.
The Compose file of the hosted service in [`deploy/`](https://github.com/muka-dev/edeltraud/tree/main/deploy) serves as an example.

## Hardening notes

- The container runs as the unprivileged `node` user.
- Outgoing requests are SSRF-checked: private, loopback and link-local addresses are refused,
  also after redirects and DNS resolution.
- Keep `BLOCKED_DOMAINS` for operators who opt out.
