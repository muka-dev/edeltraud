import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, Severity } from '../../core/types.ts';
import { realMx, type DnsData } from '../collect/dns.ts';

/** Mail authentication of the registrable domain: SPF and DMARC. Without them anyone can send mail in the domain's name. */
export const dnsMail: CheckModule = {
  manifest: {
    id: 'dns.mail',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:dns'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = dnsMail.manifest;
    const d = ctx.artifacts.list('dns')[0]?.data as DnsData | undefined;
    if (!d) return {};
    if (d.platform) return { notChecked: [{ module: m.id, reason: 'condition', detail: `app on provider domain ${d.platform}` }] };

    const hasMx = realMx(d.mx).length > 0;
    const loc = { url: ctx.target.url, selector: `dns:${d.domain}` };
    const vars = { domain: d.domain };
    const out: Finding[] = [];
    const add = (kind: string, severity: Severity, key: string, extra: Record<string, string> = {}, evidence?: string) =>
      out.push(finding(m, { kind, severity, confidence: 'confirmed', location: loc, messageKey: key, vars: { ...vars, ...extra }, ...(evidence ? { evidence } : {}) }));

    const failed = (type: string) => d.errors.some((e) => e.startsWith(type + ' '));
    if (!failed('TXT')) {
      if (d.spf.length === 0) add('spf-missing', hasMx ? 'medium' : 'low', 'dns.spf-missing');
      else if (d.spf.length > 1) add('spf-multiple', 'medium', 'dns.spf-multiple');
      else {
        const policy = spfAllPolicy(d.spf[0]!);
        if (policy) add('spf-lax', 'medium', 'dns.spf-lax', { policy }, d.spf[0]!.slice(0, 200));
      }
    }
    if (!failed('TXT') || d.dmarc.length > 0) {
      if (d.dmarc.length === 0) add('dmarc-missing', hasMx ? 'medium' : 'low', 'dns.dmarc-missing');
      else if (dmarcPolicy(d.dmarc[0]!) === 'none') add('dmarc-none', 'low', 'dns.dmarc-none', {}, d.dmarc[0]!.slice(0, 200));
    }
    return { findings: out };
  },
};

/** Returns the lax 'all' mechanism ('+all', 'all', '?all') of an SPF record, else null (redirect=, ~all, -all). */
function spfAllPolicy(record: string): string | null {
  for (const tok of record.trim().split(/\s+/)) {
    const mm = tok.toLowerCase().match(/^([+\-~?]?)all$/);
    if (!mm) continue;
    const q = mm[1]!;
    if (q === '+') return '+all';
    if (q === '') return 'all';
    if (q === '?') return '?all';
    return null;
  }
  return null;
}

function dmarcPolicy(record: string): string | null {
  const mm = record.match(/(?:^|;)\s*p\s*=\s*([a-z]+)/i);
  return mm ? mm[1]!.toLowerCase() : null;
}
