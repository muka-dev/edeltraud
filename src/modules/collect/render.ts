import type { CheckModule } from '../../core/types.ts';

/**
 * Loads the start page once in a headless browser, without any interaction, and keeps
 * requests, cookies, storage keys, console output, links and the rendered DOM.
 * Everything recorded happened before a visitor could answer a consent banner.
 */
export const collectRender: CheckModule<{ waitMs: number; maxRequests: number; audit: boolean }> = {
  manifest: {
    id: 'collect.render',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'privacy',
    requires: [],
    uses: ['artifact:page'],
    provides: ['artifact:render'],
    params: {
      waitMs: { type: 'number', default: 4000, min: 0, max: 15_000 },
      maxRequests: { type: 'number', default: 300, min: 10, max: 1000 },
      /** Also run axe-core and measure lab performance (a11y.axe, perf.*). */
      audit: { type: 'boolean', default: false },
    },
    budget: { browser: true, ms: 60_000 },
  },
  async run(ctx, params) {
    if (!ctx.browser) return { notChecked: [{ module: 'collect.render', reason: 'unsupported', detail: 'no browser available' }] };
    const page = ctx.artifacts.list('page')[0]?.data as { finalUrl: string } | undefined;
    const url = page?.finalUrl ?? ctx.target.url;
    try {
      const data = await ctx.browser.render(url, { waitMs: params.waitMs, maxRequests: params.maxRequests, timeoutMs: 30_000, audit: params.audit });
      // Blocked internal addresses are not a gap in the scan of this app; the request limit is.
      const notChecked = data.limitReached
        ? [{ module: 'collect.render', reason: 'budget' as const, detail: `request limit of ${params.maxRequests} reached while rendering` }]
        : [];
      return { artifacts: [{ type: 'render', key: data.finalUrl, data }], notChecked };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      const unsupported = (e as { code?: string }).code === 'EDELTRAUD_NO_BROWSER';
      return { notChecked: [{ module: 'collect.render', reason: unsupported ? 'unsupported' : 'error', detail: msg.slice(0, 200) }] };
    }
  },
};
