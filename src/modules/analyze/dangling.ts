import { finding } from '../../core/finding.ts';
import type { CheckModule } from '../../core/types.ts';
import type { DnsData } from '../collect/dns.ts';

/** CNAME targets of services known for subdomain takeover (a deleted app/bucket/site can be re-claimed by anyone). */
const TAKEOVER_TARGETS: RegExp[] = [
  /(^|\.)herokuapp\.com$/,
  /(^|\.)github\.io$/,
  /(^|\.)netlify\.app$/,
  /(^|\.)vercel\.app$/,
  /(^|\.)azurewebsites\.net$/,
  /(^|\.)cloudapp\.net$/,
  /(^|\.)s3([.-][a-z0-9-]+)?\.amazonaws\.com$/,
  /(^|\.)surge\.sh$/,
  /(^|\.)pages\.dev$/,
  /(^|\.)fly\.dev$/,
  /(^|\.)ghost\.io$/,
];

/** First CNAME target on a takeover-prone service, lower-case without trailing dot, else null. */
export function takeoverTarget(cnames: readonly string[]): string | null {
  for (const raw of cnames) {
    const t = raw.trim().toLowerCase().replace(/\.$/, '');
    if (TAKEOVER_TARGETS.some((re) => re.test(t))) return t;
  }
  return null;
}

/**
 * Dangling CNAME: the host points to a takeover-prone service but has no A/AAAA answer, so the target
 * most likely no longer exists. Derived from the dns artifact only; no connection to the target.
 */
export const dnsDangling: CheckModule = {
  manifest: {
    id: 'dns.dangling',
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
    const m = dnsDangling.manifest;
    const d = ctx.artifacts.list('dns')[0]?.data as DnsData | undefined;
    if (!d || d.cname.length === 0) return {};
    if (d.a.length > 0 || d.aaaa.length > 0) return {};
    // A failed A/AAAA query is not proof of a missing target.
    if (d.errors.some((e) => e === `A ${d.host}` || e === `AAAA ${d.host}`)) return {};
    const target = takeoverTarget(d.cname);
    if (!target) return {};
    return {
      findings: [
        finding(m, {
          kind: 'dangling',
          severity: 'high',
          confidence: 'likely',
          location: { url: ctx.target.url, selector: `dns:${d.host}` },
          evidence: `${d.host} CNAME ${target}, no A/AAAA`,
          messageKey: 'dns.dangling',
          vars: { host: d.host, target },
          discriminator: target,
        }),
      ],
    };
  },
};
