import type { CheckModule } from '../../core/types.ts';
import type { PageData } from '../util.ts';

const TLS_CODES = /CERT_|ERR_TLS|ERR_SSL|SELF_SIGNED|UNABLE_TO_VERIFY|HOSTNAME_MISMATCH|ALTNAME|DEPTH_ZERO/;

/** Loads the start page (following redirects) and checks whether plain http redirects to https. */
export const collectPage: CheckModule<{ checkHttpRedirect: boolean }> = {
  manifest: {
    id: 'collect.page',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'operations',
    requires: [],
    provides: ['artifact:page', 'artifact:http-redirect', 'artifact:page-error'],
    params: { checkHttpRedirect: { type: 'boolean', default: true } },
    budget: { requests: 2, ms: 12_000 },
  },
  async run(ctx, params) {
    const http = ctx.http!;
    const artifacts = [];
    const notChecked = [];
    try {
      const res = await http.fetch({ url: ctx.target.url, maxBytes: 2 * 1024 * 1024 });
      if (res.status >= 400) {
        // An error page says nothing about the app. Downstream modules are skipped, the verdict becomes 'unknown'.
        artifacts.push({ type: 'page-error', key: ctx.target.url, data: { message: `HTTP ${res.status}`, tls: false } });
        notChecked.push({ module: 'collect.page', reason: 'error' as const, detail: `HTTP ${res.status}` });
        return { artifacts, notChecked };
      }
      const page: PageData = {
        url: res.url,
        finalUrl: res.finalUrl,
        status: res.status,
        headers: res.headers,
        setCookies: res.setCookies,
        html: res.body,
        redirects: res.redirects,
      };
      artifacts.push({ type: 'page', key: res.finalUrl, data: page });
    } catch (e) {
      const msg = e instanceof Error ? `${(e as NodeJS.ErrnoException).code ?? ''} ${e.message}`.trim() : String(e);
      artifacts.push({ type: 'page-error', key: ctx.target.url, data: { message: msg, tls: TLS_CODES.test(msg) } });
      notChecked.push({ module: 'collect.page', reason: 'error' as const, detail: msg.slice(0, 200) });
    }

    if (params.checkHttpRedirect && ctx.target.url.startsWith('https://')) {
      const httpUrl = 'http://' + ctx.target.url.slice('https://'.length);
      try {
        const res = await http.fetch({ url: httpUrl, followRedirects: false, maxBytes: 4096 });
        artifacts.push({
          type: 'http-redirect',
          key: httpUrl,
          data: { status: res.status, location: res.headers['location'] ?? null },
        });
      } catch (e) {
        // Port 80 closed is fine: nothing is served unencrypted.
        artifacts.push({ type: 'http-redirect', key: httpUrl, data: { status: 0, location: null, error: String(e) } });
      }
    }
    return { artifacts, notChecked };
  },
};
