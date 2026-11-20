import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, Severity } from '../../core/types.ts';
import type { PageData } from '../util.ts';

/** Security headers of the start page. Missing CSP is common and rated low on its own. */
export const headersSecurity: CheckModule = {
  manifest: {
    id: 'headers.security',
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
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const h = page.headers;
    const csp = h['content-security-policy'] ?? '';
    const https = page.finalUrl.startsWith('https://');
    const loc = { url: page.finalUrl };
    const out: Finding[] = [];
    const add = (kind: string, severity: Severity, key: string, vars?: Record<string, string>) =>
      out.push(finding(headersSecurity.manifest, { kind, severity, confidence: 'confirmed', location: loc, messageKey: key, ...(vars ? { vars } : {}) }));

    if (!csp) add('csp-missing', 'low', 'headers.csp');
    if (https && !/max-age=\d{6,}/i.test(h['strict-transport-security'] ?? '')) add('hsts-missing', 'medium', 'headers.hsts');
    if (!/nosniff/i.test(h['x-content-type-options'] ?? '')) add('nosniff-missing', 'low', 'headers.nosniff');
    if (!h['x-frame-options'] && !/frame-ancestors/i.test(csp)) add('frame-missing', 'low', 'headers.frame');
    if (!h['referrer-policy']) add('referrer-missing', 'info', 'headers.referrer');
    if (!h['permissions-policy']) add('permissions-missing', 'info', 'headers.permissions');
    const leak = h['x-powered-by'] ?? (/\d/.test(h['server'] ?? '') ? h['server'] : undefined);
    if (leak) add('version-disclosure', 'info', 'headers.version', { value: leak });
    return { findings: out };
  },
};

const SESSION_COOKIE = /sess|auth|token|sid|jwt|login|remember|sb-|supabase|next-auth|__Secure-|__Host-/i;

/** Flags of cookies set by the start page. Session-like cookies weigh more. */
export const cookiesFlags: CheckModule = {
  manifest: {
    id: 'cookies.flags',
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
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const https = page.finalUrl.startsWith('https://');
    const out: Finding[] = [];
    for (const line of page.setCookies) {
      const name = line.split('=')[0]!.trim();
      const attrs = line.toLowerCase();
      const missing = [
        https && !/;\s*secure/.test(attrs) ? 'Secure' : '',
        !/;\s*httponly/.test(attrs) ? 'HttpOnly' : '',
        !/;\s*samesite=/.test(attrs) ? 'SameSite' : '',
      ].filter(Boolean);
      if (!missing.length) continue;
      const session = SESSION_COOKIE.test(name);
      out.push(
        finding(cookiesFlags.manifest, {
          kind: 'cookie-flags',
          severity: session ? 'medium' : 'low',
          confidence: 'confirmed',
          location: { url: page.finalUrl, selector: `cookie:${name}` },
          messageKey: 'cookies.flags',
          vars: { name, missing: missing.join(', ') },
        }),
      );
    }
    return { findings: out };
  },
};
