---
title: Home
nav_order: 1
---

# EDEL.TRAUD.AI
{: .fs-9 }

*Look before you trust.* An open-source scanner for the typical flaws of web apps built with
Lovable, Cursor, Claude Code, Bolt, v0 and similar tools.
{: .fs-6 .fw-300 }

[Get started](getting-started){: .btn .btn-primary .mr-2 }
[Source on GitHub](https://github.com/muka-dev/edeltraud){: .btn .mr-2 }
[Try the hosted quick check](https://scan.m-ko.de){: .btn }

---

## What it finds

AI coding tools ship working apps fast, and they repeat the same mistakes:
secret API keys in the frontend bundle, Supabase tables without row level security,
open Firebase databases, LLM calls straight from the browser, public source maps,
missing security headers, debug builds in production.

EDEL.TRAUD.AI reads what an app delivers publicly and reports these flaws with a
traffic light (*Ampel*), a severity and steps to fix them. Active checks (for example
reading a Supabase table with the public `anon` key) only run after the owner has
proved control of the domain.

## Three ways to use it

| | |
|---|---|
| **CLI** | `edeltraud https://example.com --plan ampel --lang en` |
| **Library** | `import { scan } from './src/core/scan.ts'` |
| **HTTP API** | `npm run api`, then `POST /v1/scan` |

## Principles

- **Passive by default.** Without proof of ownership only public content is read; nothing is attacked.
- **SSRF-safe fetching** with request and time budgets per plan.
- **No tracking, no third parties.** Abuse protection uses proof of work, not CAPTCHAs.
- **Four languages:** German, English, Portuguese (PT and BR).
- **Honest results.** An incomplete scan shows a grey light, never green.

## Open core

This repository is the open core under AGPL-3.0. The hosted service at
[scan.m-ko.de](https://scan.m-ko.de) adds the designed report, ready-made fix prompts,
payment and the weekly WatchDog. Without those parts the report shows the steps to fix
each finding without a prompt.
