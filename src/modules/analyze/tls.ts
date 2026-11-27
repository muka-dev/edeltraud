import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, TlsInfo } from '../../core/types.ts';
import type { PageData } from '../util.ts';

/** Encryption basics: https reachable, certificate accepted, http redirects to https. */
export const tlsBasics: CheckModule = {
  manifest: {
    id: 'tls.basics',
    version: '0.2.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:page', 'artifact:page-error', 'artifact:http-redirect', 'artifact:tls'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = tlsBasics.manifest;
    const out: Finding[] = [];
    const err = ctx.artifacts.list('page-error')[0]?.data as { message: string; tls: boolean } | undefined;
    if (err?.tls) {
      out.push(finding(m, { kind: 'cert-error', severity: 'high', confidence: 'confirmed', location: { url: ctx.target.url }, messageKey: 'tls.cert-error', vars: { detail: err.message.slice(0, 120) } }));
    }
    const page = ctx.artifacts.list('page')[0]?.data as PageData | undefined;
    if (page && page.finalUrl.startsWith('http://')) {
      out.push(finding(m, { kind: 'http-only', severity: 'high', confidence: 'confirmed', location: { url: page.finalUrl }, messageKey: 'tls.http-only' }));
    }
    const redir = ctx.artifacts.list('http-redirect')[0];
    if (redir) {
      const d = redir.data as { status: number; location: string | null };
      const ok = d.status === 0 || (d.status >= 300 && d.status < 400 && (d.location ?? '').startsWith('https://'));
      if (!ok) {
        out.push(finding(m, { kind: 'no-redirect', severity: 'medium', confidence: 'confirmed', location: { url: redir.key }, messageKey: 'tls.no-redirect', vars: { status: String(d.status) } }));
      }
    }
    const info = ctx.artifacts.list('tls')[0]?.data as TlsInfo | undefined;
    if (info) {
      const DAY = 86_400_000;
      const from = info.validFrom ? Date.parse(info.validFrom) : NaN;
      const to = info.validTo ? Date.parse(info.validTo) : NaN;
      const now = Date.parse(info.checkedAt);
      if (!Number.isNaN(from) && !Number.isNaN(to) && !Number.isNaN(now)) {
        const remaining = to - now;
        // Short-lived certificates (6-day, 45-day) are normal: the threshold scales with the lifetime.
        const threshold = Math.min(14 * DAY, 0.2 * (to - from));
        // remaining < 0: expired, covered by cert-error.
        if (remaining >= 0 && remaining < threshold) {
          out.push(finding(m, {
            kind: 'cert-expiring',
            severity: remaining < threshold / 2 ? 'high' : 'medium',
            confidence: 'confirmed',
            location: { url: ctx.target.url },
            messageKey: 'tls.cert-expiring',
            vars: { days: String(Math.floor(remaining / DAY)), date: new Date(to).toISOString().slice(0, 10) },
          }));
        }
      }
      if (info.legacy['TLSv1'] === true || info.legacy['TLSv1.1'] === true) {
        out.push(finding(m, { kind: 'legacy-protocol', severity: 'low', confidence: 'confirmed', location: { url: ctx.target.url }, messageKey: 'tls.legacy-protocol', vars: { protocols: 'TLS 1.0, TLS 1.1' } }));
      }
    }
    if (!page && !err) return { notChecked: [{ module: m.id, reason: 'dependency', detail: 'page not loaded' }] };
    return { findings: out };
  },
};
