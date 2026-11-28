---
title: CLI
nav_order: 3
---

# CLI

```text
edeltraud <url> [options]
edeltraud ownership <host> [--account <id>]   token and instructions for the deep check
```

| Option | Meaning |
|---|---|
| `--plan <name>` | `ampel` (default), `report`, `deep`, `watch` |
| `--lang <de\|en\|pt\|pt-BR>` | output language (default `de`) |
| `--json` | print the presented result as JSON |
| `--raw` | print the full `ScanResult` as JSON |
| `--pdf <file>` | write the report as PDF (needs Playwright/Chromium) |
| `--record <file>` | save all HTTP exchanges as a replay fixture |
| `--owner-token <t>` | verify ownership (DNS TXT or `/.well-known` file) before active checks |
| `--account <id>` | account the ownership token belongs to (default `cli`) |
| `--verbose` | log module errors to stderr |

Commands for the WatchDog, paid jobs and the designed HTML report belong to the
hosted service and are not part of the open core.

## Plans

A plan is a YAML file in `plans/` that lists modules, their parameters and the budget.

| Plan | Mode | Browser | Budget | Purpose |
|---|---|---|---|---|
| `ampel` | passive | no | 15 s, 12 requests | free quick check, shows 3 findings |
| `report` | passive | yes | 120 s, 400 requests | all passive modules |
| `deep` | passive + active | yes | 300 s, 800 requests | after proof of ownership |
| `watch` | passive (+ active) | yes | 120 s, 400 requests | weekly repeat |

## Proof of ownership

Active checks need a token bound to the host and an account:

```bash
npm run scan -- ownership example.com
# set the DNS TXT record or the /.well-known file as shown, then:
npm run scan -- https://example.com --plan deep --owner-token <token>
```

## Recording fixtures

`--record fixture.json` stores every HTTP exchange. Tests replay these files, so a
scan becomes reproducible without network. Remove keys and personal data before
committing a fixture.
