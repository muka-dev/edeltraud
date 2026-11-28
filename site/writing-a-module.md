---
title: Writing a check
nav_order: 8
---

# Writing a check

A new check needs four things:

1. a file under `src/modules/analyze/` (or `collect/`, `probe/`),
2. an entry in `src/modules/index.ts`,
3. texts in **all** language catalogues in `src/i18n/` (de, en, pt, pt-BR),
4. a fixture test in `test/`.

The tests fail if a `messageKey` is missing in one language or if a German text
addresses the reader (no *du*, no *Sie*) or promises security.

## Example: an analyzer

```ts
import { finding } from '../../core/finding.ts';
import type { CheckModule } from '../../core/types.ts';
import type { SourceMapProbe } from '../collect/sourcemaps.ts';

export const sourcemapsExposed: CheckModule = {
  manifest: {
    id: 'sourcemaps.exposed',      // stable, never renamed
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:sourcemap'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const exposed = ctx.artifacts.list('sourcemap')
      .map((a) => a.data as SourceMapProbe)
      .filter((p) => p.isSourceMap);
    if (!exposed.length) return {};
    return {
      findings: [
        finding(sourcemapsExposed.manifest, {
          kind: 'exposed',
          severity: 'medium',
          confidence: 'confirmed',
          location: { url: exposed[0]!.url },
          messageKey: 'sourcemaps.exposed',
          vars: { count: String(exposed.length) },
        }),
      ],
    };
  },
};
```

## Rules

- **Analyzers are pure.** No network; they read artifacts and facts only.
- **Probes are active** (`mode: 'active'`) and only run after proof of ownership.
  Read, never write; at most one row; GET only on discovered endpoints.
- **No real secrets in fixtures.** Use obviously fake values.
- **Confidence matters.** Use `possible` when a version or header alone suggests a risk.
- **Add the module to a plan** in `plans/*.yaml` so it actually runs.

Run `npm run check` before opening a pull request.
