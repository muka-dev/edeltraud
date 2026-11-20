import { finding } from '../../core/finding.ts';
import type { CheckModule } from '../../core/types.ts';
import type { SourceMapProbe } from '../collect/sourcemaps.ts';

/** Publicly reachable source maps reveal the original source code. One finding for all maps. */
export const sourcemapsExposed: CheckModule = {
  manifest: {
    id: 'sourcemaps.exposed',
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
    const exposed = ctx.artifacts.list('sourcemap').map((a) => a.data as SourceMapProbe).filter((p) => p.isSourceMap);
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
