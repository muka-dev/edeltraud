import type { Artifact, CheckModule } from '../../core/types.ts';
import { extractChunkRefs, extractScripts, sameSite, type BundleData, type PageData } from '../util.ts';

/**
 * Loads the JavaScript the start page (and pages from collect.crawl) ships: external scripts of the same site, inline
 * scripts, and (optionally) lazily loaded chunks referenced from those bundles.
 * Third-party scripts (CDNs, analytics) are not loaded: their keys are not the app's.
 */
export const collectBundles: CheckModule<{ maxBundles: number; followLazyChunks: boolean; maxBytesPerBundle: number }> = {
  manifest: {
    id: 'collect.bundles',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    uses: ['artifact:subpage'],
    provides: ['artifact:js-bundle'],
    params: {
      maxBundles: { type: 'number', default: 5, min: 1, max: 200 },
      followLazyChunks: { type: 'boolean', default: false },
      maxBytesPerBundle: { type: 'number', default: 3 * 1024 * 1024, min: 10_000, max: 20 * 1024 * 1024 },
    },
    budget: { ms: 60_000 },
  },
  async run(ctx, params) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const host = new URL(page.finalUrl).hostname;
    const artifacts: Artifact[] = [];
    const external: string[] = [];
    const inlineSeen = new Set<string>();
    // Start page first, then crawled pages: their scripts are only new ones (the same inline config counts once).
    for (const p of [page, ...ctx.artifacts.list('subpage').map((a) => a.data as PageData)]) {
      const s = extractScripts(p.html, p.finalUrl);
      external.push(...s.external);
      s.inline.forEach((code, i) => {
        if (inlineSeen.has(code)) return;
        inlineSeen.add(code);
        const key = `${p.finalUrl}#inline-${i + 1}`;
        artifacts.push({
          type: 'js-bundle',
          key,
          data: { url: key, source: 'inline', status: 200, headers: {}, code, truncated: false } satisfies BundleData,
        });
      });
    }

    const queue = [...new Set(external.filter((u) => sameSite(new URL(u).hostname, host)))];
    const seen = new Set(queue);
    let loaded = 0;
    const notChecked = [];
    while (queue.length && loaded < params.maxBundles) {
      const url = queue.shift()!;
      try {
        const res = await ctx.http!.fetch({ url, maxBytes: params.maxBytesPerBundle });
        loaded++;
        if (res.status !== 200) continue;
        const data: BundleData = { url, source: 'external', status: res.status, headers: res.headers, code: res.body, truncated: res.truncated };
        artifacts.push({ type: 'js-bundle', key: url, data });
        if (params.followLazyChunks) {
          for (const ref of extractChunkRefs(res.body, url)) {
            if (!seen.has(ref) && sameSite(new URL(ref).hostname, host)) {
              seen.add(ref);
              queue.push(ref);
            }
          }
        }
      } catch (e) {
        notChecked.push({ module: 'collect.bundles', reason: 'error' as const, detail: `${url}: ${e instanceof Error ? e.message : e}` });
        if (e instanceof Error && e.name === 'BudgetExceededError') break;
      }
    }
    if (queue.length) {
      notChecked.push({ module: 'collect.bundles', reason: 'budget' as const, detail: `${queue.length} further scripts not loaded` });
    }
    return { artifacts, notChecked };
  },
};
