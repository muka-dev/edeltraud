# Contributing to EDEL.TRAUD.AI

Thanks for helping. Docs: https://muka-dev.github.io/edeltraud/

## Workflow

1. Open an issue first for larger changes (new check, new plan, API change).
2. Fork, branch from `main`, keep pull requests small.
3. `npm run check` must pass (typecheck + tests, Node.js ≥ 22.18).
4. Fill in the pull request checklist.

## New checks

See [Writing a check](https://muka-dev.github.io/edeltraud/writing-a-module). In short:
module file, entry in `src/modules/index.ts`, texts in de/en/pt/pt-BR, fixture test.

## Rules for texts

- No promises: a result is no certificate, no guarantee and no legal assessment.
- German texts address nobody: neither *du* nor *Sie*; rephrase impersonally.
- No real secrets, personal data or third-party URLs in fixtures, issues or PRs.

## Active checks

Probes that send requests beyond reading public content must have `mode: 'active'`.
They run only after proof of ownership, only read, and stay within the plan budget.

## Licence

By contributing you agree that your contribution is licensed under AGPL-3.0-only.
