import { finding, mask } from '../../core/finding.ts';
import type { CheckModule, Finding, RenderData } from '../../core/types.ts';
import { decodeJwtPayload, sameSite } from '../util.ts';

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const SK = /\bsk-[A-Za-z0-9_-]{8,}/g;
const BEARER = /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g;
const LONG = /\b(?:[A-Fa-f0-9]{32,}|[A-Za-z0-9+/_-]{40,}={0,2})/g;

/** Masks anything that looks like a token or key, then shortens. */
export function sanitize(text: string, max = 120): string {
  const s = text
    .replace(JWT, (x) => mask(x))
    .replace(BEARER, (x) => 'Bearer ' + mask(x.replace(/^Bearer\s+/, '')))
    .replace(SK, (x) => mask(x))
    .replace(LONG, (x) => mask(x));
  return s.length > max ? s.slice(0, max - 1) + '…' : s;
}

function secretIn(text: string): string | undefined {
  for (const m of text.matchAll(JWT)) {
    const p = decodeJwtPayload(m[0]);
    if (p && p['role'] === 'service_role') return m[0];
  }
  return text.match(SK)?.[0] ?? text.match(BEARER)?.[0];
}

/** Uncaught exceptions, console errors, failed same-site requests, secrets in console output. */
export const opsErrorsConsole: CheckModule = {
  manifest: {
    id: 'ops.errors-console',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'operations',
    requires: [],
    uses: ['artifact:render'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = opsErrorsConsole.manifest;
    const r = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
    if (!r) return {};
    const loc = { url: r.finalUrl };
    const out: Finding[] = [];

    const errors = [...r.pageErrors, ...r.console.filter((c) => c.type === 'error').map((c) => c.text)];
    if (errors.length) {
      out.push(finding(m, {
        kind: 'console-errors', severity: 'low', confidence: 'confirmed', location: loc,
        messageKey: 'ops.console-errors', vars: { count: String(errors.length), sample: sanitize(errors[0]!) },
      }));
    }

    const failed = r.requests.filter((q) => {
      let u: URL;
      try {
        u = new URL(q.url);
      } catch {
        return false;
      }
      if (u.protocol !== 'http:' && u.protocol !== 'https:') return false;
      if (/\/favicon\.ico$/i.test(u.pathname)) return false;
      if (!sameSite(u.hostname, ctx.target.host)) return false;
      if (q.failure !== null) return !/^blocked|ERR_ABORTED/i.test(q.failure);
      return q.status !== null && q.status >= 400;
    });
    if (failed.length) {
      const f = failed[0]!;
      const u = new URL(f.url);
      out.push(finding(m, {
        kind: 'failed-requests', severity: 'low', confidence: 'confirmed', location: { url: f.url },
        messageKey: 'ops.failed-requests',
        vars: { count: String(failed.length), sample: sanitize(`${f.status ?? f.failure} ${f.method} ${u.origin}${u.pathname}`) },
      }));
    }

    const texts = [...r.console.map((c) => c.text), ...r.pageErrors];
    for (const t of texts) {
      const s = secretIn(t);
      if (s) {
        out.push(finding(m, {
          kind: 'console-secret', severity: 'medium', category: 'security', confidence: 'likely', location: loc,
          evidence: mask(s), messageKey: 'ops.console-secret', discriminator: mask(s),
        }));
        break;
      }
    }
    return { findings: out };
  },
};
