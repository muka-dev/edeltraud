import type { Artifact, CheckModule, NotChecked } from '../../core/types.ts';
import type { PageData } from '../util.ts';

/** Fixed probe paths: deterministic so that replays stay stable. */
export const ERROR_PROBE_PATHS = ['/edeltraud-check-404', '/api/edeltraud-check-404'] as const;

export interface ErrorPageData {
  url: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  body: string;
}

/** Requests two non-existent URLs on the app's origin and keeps the error pages. A plain GET of a missing page. */
export const collectErrorpages: CheckModule = {
  manifest: {
    id: 'collect.errorpages',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    provides: ['artifact:error-page'],
    params: {},
    budget: { requests: 2, ms: 10_000 },
  },
  async run(ctx) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const origin = new URL(page.finalUrl).origin;
    const artifacts: Artifact[] = [];
    const failed: string[] = [];
    for (const path of ERROR_PROBE_PATHS) {
      const url = origin + path;
      try {
        const res = await ctx.http!.fetch({ url, maxBytes: 256 * 1024, followRedirects: true });
        const data: ErrorPageData = { url, finalUrl: res.finalUrl, status: res.status, headers: res.headers, body: res.body };
        artifacts.push({ type: 'error-page', key: url, data });
      } catch (e) {
        failed.push(`${path}: ${e instanceof Error ? e.message : String(e)}`.slice(0, 100));
      }
    }
    const notChecked: NotChecked[] = failed.length
      ? [{ module: 'collect.errorpages', reason: 'error', detail: failed.join('; ').slice(0, 200) }]
      : [];
    return { artifacts, notChecked };
  },
};
