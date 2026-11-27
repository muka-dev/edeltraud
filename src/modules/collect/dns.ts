import type { Artifact, CheckModule, DnsRecordType, NotChecked } from '../../core/types.ts';

const TWO_LEVEL = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.br', 'net.br', 'org.br', 'app.br', 'dev.br', 'com.pt', 'co.at', 'or.at', 'gv.at',
  'com.au', 'co.nz', 'co.jp', 'com.mx', 'com.ar', 'co.za',
]);

/** Hosting providers whose domain the app lives on: mail/DNS records there are not the app owner's. Longest suffix wins. */
const PLATFORMS = [
  'lovable.app', 'lovableproject.com', 'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'web.app', 'firebaseapp.com',
  'github.io', 'onrender.com', 'herokuapp.com', 'fly.dev', 'railway.app', 'up.railway.app', 'replit.app', 'repl.co',
  'stackblitz.io', 'bolt.host', 'supabase.co', 'glitch.me', 'surge.sh', 'azurewebsites.net', 'amplifyapp.com', 'cloudfront.net',
  'appspot.com', 'run.app', 'deno.dev',
].sort((a, b) => b.length - a.length);

/** Registrable domain by a small suffix list (no full public suffix list): last two labels, three for known two-level suffixes. */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const last2 = labels.slice(-2).join('.');
  return labels.slice(TWO_LEVEL.has(last2) ? -3 : -2).join('.');
}

/** Returns the provider suffix if the host is on a platform domain, else null. */
export function platformOf(host: string): string | null {
  const h = host.toLowerCase().replace(/\.$/, '');
  return PLATFORMS.find((p) => h === p || h.endsWith('.' + p)) ?? null;
}

export interface DnsData {
  host: string;
  domain: string;
  platform: string | null;
  a: string[];
  aaaa: string[];
  cname: string[];
  mx: string[];
  spf: string[];
  dmarc: string[];
  caa: string[];
  /** Query names ('TYPE name') that failed; analyzers skip checks that depend on them. */
  errors: string[];
}

/** Null MX ('0 .') means: this domain sends and receives no mail. */
export function realMx(mx: string[]): string[] {
  return mx.filter((r) => !/^\d+\s+\.?$/.test(r.trim()));
}

/** DNS records of the host and its registrable domain (mail authentication, CAA). Names only, no connection to the target. */
export const collectDns: CheckModule = {
  manifest: {
    id: 'collect.dns',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'security',
    requires: [],
    provides: ['artifact:dns', 'fact:dns.mx', 'fact:dns.platform'],
    params: {},
    budget: { ms: 10_000 },
  },
  async run(ctx) {
    const id = collectDns.manifest.id;
    if (!ctx.dns) return { notChecked: [{ module: id, reason: 'unsupported' }] };
    const dns = ctx.dns;
    const host = ctx.target.host.toLowerCase();
    const domain = registrableDomain(host);
    const platform = platformOf(host);
    const errors: string[] = [];
    const q = async (name: string, type: DnsRecordType): Promise<string[]> => {
      try {
        return await dns.resolve(name, type);
      } catch {
        errors.push(`${type} ${name}`);
        return [];
      }
    };
    const data: DnsData = { host, domain, platform, a: [], aaaa: [], cname: [], mx: [], spf: [], dmarc: [], caa: [], errors };
    data.a = await q(host, 'A');
    data.aaaa = await q(host, 'AAAA');
    data.cname = await q(host, 'CNAME');
    if (!platform) {
      data.mx = await q(domain, 'MX');
      data.spf = (await q(domain, 'TXT')).filter((t) => /^\s*v=spf1(\s|$)/i.test(t));
      data.dmarc = (await q(`_dmarc.${domain}`, 'TXT')).filter((t) => /^\s*v=DMARC1\b/i.test(t));
      data.caa = await q(domain, 'CAA');
    }
    const facts: Record<string, unknown> = { 'dns.platform': platform };
    if (!platform && !errors.includes(`MX ${domain}`)) facts['dns.mx'] = realMx(data.mx).length > 0;
    const artifacts: Artifact[] = [{ type: 'dns', key: host, data }];
    const notChecked: NotChecked[] = errors.length
      ? [{ module: id, reason: 'error', detail: `failed: ${errors.join(', ')}`.slice(0, 200) }]
      : [];
    return { artifacts, facts, notChecked };
  },
};
