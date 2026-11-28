---
title: Checks
nav_order: 6
---

# Checks

Every check is a module with an ID. *Collectors* fetch data, *analyzers* are pure
functions over that data, *probes* send requests and are only run after proof of
ownership. The full catalogue with status per plan (in German) is in
[`docs/spec/pruefkatalog.md`](https://github.com/muka-dev/edeltraud/blob/main/docs/spec/pruefkatalog.md).

## Security, passive

| ID | What it looks for |
|---|---|
| `secrets.frontend` | secret keys in bundles and HTML: OpenAI, Anthropic, Stripe `sk_live_`, Supabase `service_role`, AWS, Google, GitHub, private keys |
| `sourcemaps.exposed` | publicly reachable source maps |
| `headers.security` | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, frame protection |
| `headers.csp-quality` | `unsafe-inline`, `*`, missing `object-src`, report-only |
| `cookies.flags` | Secure, HttpOnly, SameSite, lifetime of session cookies |
| `tls.basics` | certificate valid, expiry, http→https, HSTS preload |
| `deps.vulnerable` | libraries with known vulnerabilities, where the version is visible |
| `deps.server` | server software from headers (for example PHP end of life) |
| `build.dev-mode` | development build, debug output, Vite dev server in production |
| `next.data-leak` | keys, connection URLs, e-mail lists, hashes in `__NEXT_DATA__` and RSC payloads |
| `errors.verbose` | stack traces, framework error pages, SQL errors on 404/500 |
| `sri.missing` | third-party scripts without Subresource Integrity |
| `mixed.content` | http resources on https pages |
| `dns.mail` | missing or lax SPF and DMARC |
| `dns.dangling` | CNAME to services that no longer exist (takeover risk) |
| `wellknown.*` | security.txt, robots.txt, sitemap, manifest |

## AI-specific

| ID | What it looks for |
|---|---|
| `ai.client-llm-call` | the browser calls an LLM API directly (cost abuse, exposed key) |
| `ai.system-prompt-exposed` | system prompts and business logic in the bundle |

## Supabase and Firebase

| ID | Mode | What it looks for |
|---|---|---|
| `supabase.config` | passive | project URL and `anon` key found |
| `supabase.*` probes | active | tables readable with the `anon` key (max. 1 row), exposed RPCs, public storage |
| `firebase.config` | passive | Firebase web config found |
| `firebase.*` probes | active | Realtime Database `/.json`, Firestore collections and storage readable without login |

## Active, general

| ID | What it looks for |
|---|---|
| `paths.sensitive` | `/.env`, `/.git/config`, backups, `/admin`, debug routes |
| `api.*` | discovered API endpoints reachable without login (GET only), CORS policy |

## Privacy hints

| ID | What it looks for |
|---|---|
| `privacy.third-party` | all third parties with their country |
| `privacy.consent-before-tracking` | trackers or cookies before any consent |
| `privacy.google-fonts` | fonts loaded directly from Google |
| `privacy.legal-pages` | imprint and privacy policy linked and reachable |

Privacy findings are hints for a human review, not a legal assessment.

## Traffic light

Rule `v2` from `src/core/verdict.ts`:

- **Red:** at least 1 critical or at least 2 high findings.
- **Yellow:** 1 high or at least 3 medium findings.
- **Green:** none of the above, and the scan was complete.
- **Grey:** the scan was incomplete. Never shown as green.

Low and info findings never change the light.
