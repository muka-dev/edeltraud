import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding } from '../../core/types.ts';
import type { WellknownData } from '../collect/wellknown.ts';
import type { PageData } from '../util.ts';

const wk = (ctx: { artifacts: { list(t: string): { data: unknown }[] } }) => ctx.artifacts.list('wellknown')[0]?.data as WellknownData | undefined;

// ---------------------------------------------------------------- security.txt

/** First value of a security.txt field (case-insensitive), or undefined. */
export function secTxtField(body: string, name: string): string | undefined {
  const re = new RegExp(`^\\s*${name}\\s*:\\s*(.+?)\\s*$`, 'im');
  return body.match(re)?.[1];
}

export const securityTxt: CheckModule = {
  manifest: {
    id: 'wellknown.securitytxt',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:wellknown'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = securityTxt.manifest;
    const d = wk(ctx);
    if (!d) return {};
    const loc = { url: ctx.target.url };
    const out: Finding[] = [];
    if (!d.securityTxt) {
      out.push(finding(m, { kind: 'securitytxt-missing', severity: 'info', confidence: 'confirmed', location: loc, messageKey: 'wellknown.securitytxt-missing' }));
      return { findings: out };
    }
    const where = { url: d.securityTxt.url };
    const expires = secTxtField(d.securityTxt.body ?? '', 'Expires');
    const exp = expires ? Date.parse(expires) : NaN;
    if (!expires || Number.isNaN(exp)) {
      out.push(finding(m, {
        kind: 'securitytxt-incomplete', severity: 'info', confidence: 'confirmed', location: where,
        evidence: expires ? `Expires: ${expires.slice(0, 40)}` : undefined,
        messageKey: 'wellknown.securitytxt-incomplete',
        vars: { reason: expires ? 'invalid-expires' : 'no-expires' },
      }));
    } else if (exp < Date.parse(d.checkedAt)) {
      out.push(finding(m, {
        kind: 'securitytxt-expired', severity: 'low', confidence: 'confirmed', location: where,
        evidence: `Expires: ${expires.slice(0, 40)}`,
        messageKey: 'wellknown.securitytxt-expired',
        vars: { date: new Date(exp).toISOString().slice(0, 10) },
      }));
    }
    return { findings: out };
  },
};

// ---------------------------------------------------------------- robots.txt

const SENSITIVE = /^\/(?:admin|dashboard|internal|api\/private|backup|staging|\.env|wp-admin|phpmyadmin|debug|test)(?=$|[/_.\-?*$])/i;

/** Disallow paths per user-agent group. Comments stripped; empty Disallow ignored. */
export function parseRobots(body: string): { agents: string[]; disallow: string[]; allow: string[] }[] {
  const groups: { agents: string[]; disallow: string[]; allow: string[] }[] = [];
  let cur: { agents: string[]; disallow: string[]; allow: string[] } | null = null;
  let lastWasAgent = false;
  for (const raw of body.split(/\r?\n/)) {
    const line = raw.replace(/#.*$/, '').trim();
    const m = line.match(/^([A-Za-z-]+)\s*:\s*(.*)$/);
    if (!m) continue;
    const key = m[1]!.toLowerCase();
    const val = m[2]!.trim();
    if (key === 'user-agent') {
      if (!cur || !lastWasAgent) {
        cur = { agents: [], disallow: [], allow: [] };
        groups.push(cur);
      }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
      continue;
    }
    lastWasAgent = false;
    if (!cur) continue;
    if (key === 'disallow' && val) cur.disallow.push(val);
    else if (key === 'allow' && val) cur.allow.push(val);
  }
  return groups;
}

export const robotsHints: CheckModule = {
  manifest: {
    id: 'wellknown.robots-hints',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    uses: ['artifact:wellknown'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = robotsHints.manifest;
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const d = wk(ctx);
    const out: Finding[] = [];
    const groups = d?.robots.body ? parseRobots(d.robots.body) : [];

    const sensitive = [...new Set(groups.flatMap((g) => g.disallow).filter((p) => SENSITIVE.test(p)))].sort();
    if (sensitive.length) {
      out.push(finding(m, {
        kind: 'robots-sensitive', severity: 'info', confidence: 'confirmed', location: { url: new URL('/robots.txt', page.finalUrl).toString() },
        evidence: sensitive.slice(0, 5).join(', '),
        messageKey: 'wellknown.robots-sensitive',
        vars: { count: String(sensitive.length), sample: sensitive.slice(0, 5).join(', ') },
      }));
    }

    // Site hidden from search engines: Disallow: / for all crawlers, or noindex on the start page.
    const sources: string[] = [];
    const star = groups.filter((g) => g.agents.includes('*'));
    if (star.some((g) => g.disallow.includes('/') && !g.allow.includes('/'))) sources.push('robots.txt');
    if (/\bnoindex\b/i.test(page.headers['x-robots-tag'] ?? '')) sources.push('X-Robots-Tag');
    for (const t of page.html.matchAll(/<meta\b[^>]*>/gi)) {
      if (/\bname\s*=\s*["']?(?:robots|googlebot)\b/i.test(t[0]) && /\bcontent\s*=\s*["'][^"']*\bnoindex\b/i.test(t[0])) {
        sources.push('meta robots');
        break;
      }
    }
    if (sources.length) {
      out.push(finding(m, {
        kind: 'robots-blocks-all', severity: 'info', confidence: 'confirmed', location: { url: page.finalUrl },
        evidence: sources.join(', '),
        messageKey: 'wellknown.robots-blocks-all',
        vars: { sources: sources.join(', ') },
      }));
    }
    return { findings: out };
  },
};

// ---------------------------------------------------------------- generator tag

/**
 * Tiny version table. Stand: 21.11.2026, zu prüfen (not an advisory database; see deps-db.ts for that).
 * - Astro: minimum 7.4.7. Source: advisory as given in the task brief (Nov 2026), CVE-2026-126364,
 *   path check bypass in combination with @astrojs/node. Not verified against the upstream advisory here;
 *   the dependency (@astrojs/node) cannot be seen from the generator tag, hence confidence 'possible'.
 * - WordPress: deliberately NO rule. Which branches still get security fixes is not certain
 *   enough to flag a version here. Add only after checking https://wordpress.org/about/security/.
 */
export const GENERATOR_MIN: Record<string, { min: string; advisory: string }> = {
  astro: { min: '7.4.7', advisory: 'CVE-2026-126364' },
};
export const GENERATOR_TABLE_DATE = '21.11.2026';

const GENERATORS: { name: string; re: RegExp }[] = [
  { name: 'Astro', re: /^Astro\b\s*v?(\d+(?:\.\d+){0,2})?/i },
  { name: 'Nuxt', re: /^Nuxt(?:\.js)?\b\s*v?(\d+(?:\.\d+){0,2})?/i },
  { name: 'Hugo', re: /^Hugo\b\s*v?(\d+(?:\.\d+){0,2})?/i },
  { name: 'Gatsby', re: /^Gatsby\b\s*v?(\d+(?:\.\d+){0,2})?/i },
  { name: 'WordPress', re: /^WordPress\b\s*v?(\d+(?:\.\d+){0,2})?/i },
];

/** Reads `<meta name="generator" content="Astro v4.5.0">` (any attribute order, any number of tags). */
export function parseGenerators(html: string): { name: string; version: string | null }[] {
  const found: { name: string; version: string | null }[] = [];
  for (const t of html.matchAll(/<meta\b[^>]*>/gi)) {
    if (!/\bname\s*=\s*["']?generator["'\s/>]/i.test(t[0])) continue;
    const content = t[0].match(/\bcontent\s*=\s*"([^"]*)"/i)?.[1] ?? t[0].match(/\bcontent\s*=\s*'([^']*)'/i)?.[1];
    if (!content) continue;
    for (const g of GENERATORS) {
      const mm = content.trim().match(g.re);
      if (mm) {
        found.push({ name: g.name, version: mm[1] ?? null });
        break;
      }
    }
  }
  return found;
}

/** Numeric comparison of dotted versions: negative if a < b. Missing parts count as 0. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length, 3); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

export const stackGenerator: CheckModule = {
  manifest: {
    id: 'stack.generator',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'quality',
    requires: ['artifact:page'],
    provides: ['fact:stack.generator'],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = stackGenerator.manifest;
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const gen = parseGenerators(page.html)[0];
    if (!gen) return {};
    const findings: Finding[] = [];
    const rule = GENERATOR_MIN[gen.name.toLowerCase()];
    if (rule && gen.version && compareVersions(gen.version, rule.min) < 0) {
      findings.push(finding(m, {
        kind: 'generator-outdated', severity: 'low', confidence: 'possible', location: { url: page.finalUrl },
        evidence: `generator: ${gen.name} ${gen.version}`,
        messageKey: 'deps.generator-outdated',
        vars: { name: gen.name, version: gen.version, min: rule.min, advisory: rule.advisory, date: GENERATOR_TABLE_DATE },
      }));
    }
    return { facts: { 'stack.generator': { name: gen.name, version: gen.version } }, findings };
  },
};

export const WELLKNOWN_ANALYZERS: CheckModule[] = [securityTxt, robotsHints, stackGenerator];
