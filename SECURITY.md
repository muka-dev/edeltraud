# Security policy

## Reporting a vulnerability in EDEL.TRAUD.AI

Please do **not** open a public issue. Report privately via
[GitHub Security Advisories](https://github.com/muka-dev/edeltraud/security/advisories/new).

Helpful: affected version or commit, steps to reproduce, impact.
You get a first answer within 7 days. Fixes are released as soon as possible and
credited unless you prefer otherwise.

## In scope

- SSRF bypasses in `src/fetch/` (private, reserved or metadata addresses reachable)
- Ways to run active probes without proof of ownership
- Bypasses of rate limits or proof of work in `src/api/`
- Injection in rendered reports or the traffic light page

## Out of scope

- Findings the scanner reports about *other* apps: please contact their operators.
- The hosted service at scan.m-ko.de beyond the code in this repository.

## Supported versions

Only the latest `main` is supported.
