import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding } from '../../core/types.ts';
import type { PageData } from '../util.ts';

/** Encryption basics: https reachable, certificate accepted, http redirects to https. */
export const tlsBasics: CheckModule = {
  manifest: {
    id: 'tls.basics',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:page', 'artifact:page-error', 'artifact:http-redirect'],
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
    if (!page && !err) return { notChecked: [{ module: m.id, reason: 'dependency', detail: 'page not loaded' }] };
    return { findings: out };
  },
};
