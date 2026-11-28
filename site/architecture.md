---
title: Architecture
nav_order: 7
---

# Architecture

```text
plan (YAML) ──► processor ──► dependency graph ──► modules ──► findings ──► verdict ──► presentation
                    │                                 ▲
                    └── budget, SSRF-safe HTTP, DNS, TLS, optional browser
```

| Folder | Content |
|---|---|
| `src/core/` | processor, plans, dependency graph, traffic light rule, types |
| `src/modules/` | `collect/` (network), `analyze/` (pure functions), `probe/` (active) |
| `src/fetch/` | HTTP with SSRF protection and budget, replay for tests |
| `src/i18n/` | texts in de, en, pt, pt-BR |
| `src/report/` | presentation (traffic light, locked findings, text) |
| `src/cli/`, `src/api/` | command line and HTTP API |
| `plans/` | `ampel`, `report`, `deep`, `watch` |
| `test/` | `node:test`, fixtures without real keys |

## How a scan runs

1. The plan names modules and their parameters, and sets the budget (time, requests, browser).
2. Each module declares in its manifest what it `requires`, `uses` and `provides`
   (facts such as `fact:stack.supabase` and artifacts such as `artifact:js-bundle`).
   The processor orders the modules into a graph from these keys.
3. `when` conditions skip modules that do not apply, for example Supabase probes without Supabase.
4. Collectors and probes get HTTP, DNS, TLS and, if allowed, a browser. Analyzers get only
   the artifacts and facts, which keeps them pure and easy to test.
5. Findings carry severity, confidence, location and a `messageKey` with variables.
   Texts are looked up in the language catalogues at presentation time.
6. The verdict turns the counts into a traffic light; incomplete scans never turn green.

The detailed design document (in German) is
[`docs/spec/architektur.md`](https://github.com/muka-dev/edeltraud/blob/main/docs/spec/architektur.md).

## Using it as a library

```ts
import { scan } from './src/core/scan.ts';

const { result } = await scan({ url: 'https://example.com', plan: 'ampel' });
console.log(result.verdict.light);
```
