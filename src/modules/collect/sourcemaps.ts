import type { Artifact, CheckModule } from '../../core/types.ts';
import type { BundleData } from '../util.ts';

export interface SourceMapProbe {
  bundle: string;
  url: string;
  status: number;
  /** The response really is a source map, not an SPA fallback page. */
  isSourceMap: boolean;
  /** Only when headOnly is false. */
  content?: string;
}

/**
 * Checks whether source maps of the loaded bundles are publicly reachable.
 * Reads only the first bytes and verifies the content, because SPA hosts answer any
 * path with index.html and status 200.
 */
export const collectSourcemaps: CheckModule<{ headOnly: boolean; maxMaps: number }> = {
  manifest: {
    id: 'collect.sourcemaps',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:js-bundle'],
    provides: ['artifact:sourcemap'],
    params: {
      headOnly: { type: 'boolean', default: true },
      maxMaps: { type: 'number', default: 3, min: 1, max: 100 },
    },
    budget: { ms: 20_000 },
  },
  async run(ctx, params) {
    const bundles = ctx.artifacts
      .list('js-bundle')
      .map((a) => a.data as BundleData)
      .filter((b) => b.source === 'external')
      .slice(0, params.maxMaps);
    const artifacts: Artifact[] = [];
    for (const b of bundles) {
      const ref =
        b.headers['sourcemap'] ?? b.headers['x-sourcemap'] ??
        b.code.match(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)\s*$/m)?.[1];
      if (ref?.startsWith('data:')) {
        artifacts.push({ type: 'sourcemap', key: b.url + '#inline', data: { bundle: b.url, url: b.url, status: 200, isSourceMap: true } satisfies SourceMapProbe });
        continue;
      }
      const url = new URL(ref ?? b.url.replace(/[?#].*$/, '') + '.map', b.url).toString();
      try {
        const res = await ctx.http!.fetch({ url, maxBytes: params.headOnly ? 2048 : 20 * 1024 * 1024 });
        const head = res.body.trimStart().slice(0, 2048);
        const isSourceMap = res.status === 200 && head.startsWith('{') && /"(mappings|sources|version)"\s*:/.test(head);
        const probe: SourceMapProbe = { bundle: b.url, url, status: res.status, isSourceMap };
        if (!params.headOnly && isSourceMap) probe.content = res.body;
        artifacts.push({ type: 'sourcemap', key: url, data: probe });
      } catch {
        /* unreachable map: nothing exposed */
      }
    }
    return { artifacts };
  },
};
