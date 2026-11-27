import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, Severity } from '../../core/types.ts';
import type { PageData } from '../util.ts';

/** Parses a CSP into directive (lowercase) → sources. The first occurrence of a directive wins, as in browsers. */
export function parseCsp(text: string): Map<string, string[]> {
  const out = new Map<string, string[]>();
  for (const part of text.split(';')) {
    const toks = part.trim().split(/\s+/).filter(Boolean);
    if (!toks.length) continue;
    const name = toks[0]!.toLowerCase();
    if (!out.has(name)) out.set(name, toks.slice(1));
  }
  return out;
}

function metaCsp(html: string): string | null {
  for (const m of html.matchAll(/<meta\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/\bhttp-equiv\s*=\s*["']?content-security-policy["'\s/>]/i.test(tag)) continue;
    const c = tag.match(/\bcontent\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
    const v = c?.[1] ?? c?.[2];
    if (v) return v;
  }
  return null;
}

const WILDCARD = /^(?:\*|https?:|data:|\*\.[a-z0-9-]+)$/i;

/** Quality of the Content-Security-Policy: weak script policy, wildcards, missing object-src. No CSP at all is reported by headers.security. */
export const headersCspQuality: CheckModule = {
  manifest: {
    id: 'headers.csp-quality',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = headersCspQuality.manifest;
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const loc = { url: page.finalUrl };
    const out: Finding[] = [];
    const add = (kind: string, severity: Severity, key: string, vars?: Record<string, string>) =>
      out.push(finding(m, { kind, severity, confidence: 'confirmed', location: loc, messageKey: key, ...(vars ? { vars, discriminator: Object.values(vars).join(',') } : {}) }));

    const text = page.headers['content-security-policy'] || metaCsp(page.html);
    if (!text) {
      if (page.headers['content-security-policy-report-only']) add('report-only', 'info', 'csp.report-only');
      return { findings: out };
    }
    const csp = parseCsp(text);
    const script = csp.get('script-src') ?? csp.get('default-src');
    if (!script) add('no-script-src', 'medium', 'csp.no-script-src');
    else {
      const low = script.map((s) => s.toLowerCase());
      const strict = low.some((s) => s.startsWith("'nonce-") || s.startsWith("'sha256-") || s === "'strict-dynamic'");
      if (low.includes("'unsafe-inline'") && !strict) add('unsafe-inline', 'medium', 'csp.unsafe-inline');
      if (low.includes("'unsafe-eval'")) add('unsafe-eval', 'low', 'csp.unsafe-eval');
      for (const s of script) if (WILDCARD.test(s)) add('wildcard', 'medium', 'csp.wildcard', { source: s });
    }
    if (!(csp.get('object-src') ?? csp.get('default-src'))) add('object-src', 'low', 'csp.object-src');
    return { findings: out };
  },
};
