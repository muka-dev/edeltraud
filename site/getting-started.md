---
title: Getting started
nav_order: 2
---

# Getting started

## Requirements

- Node.js **22.18 or newer**. TypeScript runs directly (type stripping), there is no build step.
- Optional: Playwright with Chromium for the `report` plan (headless browser) and PDF output.

## Install

```bash
git clone https://github.com/muka-dev/edeltraud.git
cd edeltraud
npm install
npm run check      # typecheck + tests
```

## First scan without network

The demo scans a built-in test app from a replay fixture:

```bash
npm run demo             # traffic light, German
npm run demo report en   # full report, English
```

## Scan a real app

Only scan your own apps or apps you have permission to check.

```bash
npm run scan -- https://example.com --plan ampel --lang en
```

Exit codes: `0` green or yellow, `1` red, `2` usage error, `3` incomplete (grey light).

## Next steps

- [CLI reference](cli) for all options
- [HTTP API](api) to embed the scanner
- [Self-hosting](self-hosting) with Docker
- [Checks](checks) for the list of modules
