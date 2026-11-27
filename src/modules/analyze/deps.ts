import { finding } from '../../core/finding.ts';
import type { CheckModule, Confidence, Finding, Severity } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';
import { EOL_DB, VULN_DB, type DbSeverity } from './deps-db.ts';

export interface DetectedLibrary {
  /** Normalised name: jquery, jquery-ui, bootstrap, lodash, moment, angularjs, vue2, dompurify, axios, nextjs. */
  name: string;
  version: string;
  confidence: Confidence;
}

/** Compares dotted numeric versions. Pre-release suffixes are ignored. Returns -1, 0 or 1. */
export function compareVersions(a: string, b: string): number {
  const pa = a.split('.').map((x) => parseInt(x, 10) || 0);
  const pb = b.split('.').map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length, 3); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

const BANNERS: [string, RegExp, Confidence][] = [
  ['jquery', /jQuery (?:JavaScript Library )?v(\d+\.\d+\.\d+)/, 'likely'],
  ['jquery-ui', /jQuery UI - v(\d+\.\d+\.\d+)/, 'likely'],
  ['bootstrap', /Bootstrap v(\d+\.\d+\.\d+)/, 'likely'],
  ['dompurify', /DOMPurify (\d+\.\d+\.\d+)/, 'likely'],
  ['vue2', /Vue\.js v(2\.\d+\.\d+)/, 'likely'],
];

/** Finds the nearest `IDENT="x.y.z"` assignment before `index`. */
function resolveIdent(code: string, ident: string, index: number): string | undefined {
  const esc = ident.replace(/\$/g, '\\$');
  const re = new RegExp(`(?:^|[^\\w$.])${esc}\\s*=\\s*["'](\\d+\\.\\d+\\.\\d+)["']`, 'g');
  const head = code.slice(0, index);
  let last: string | undefined;
  for (const m of head.matchAll(re)) last = m[1];
  return last;
}

/** Detects libraries from bundle code or inline HTML. Patterns rely on license banners and string constants that survive minification. */
export function detectLibraries(code: string): DetectedLibrary[] {
  const seen = new Set<string>();
  const out: DetectedLibrary[] = [];
  const add = (name: string, version: string | undefined, confidence: Confidence) => {
    if (!version) return;
    const key = `${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ name, version, confidence });
  };

  for (const [name, re, conf] of BANNERS) {
    for (const m of code.matchAll(new RegExp(re.source, 'g'))) add(name, m[1], conf);
  }

  // Lodash: version literal shortly before the core-js marker.
  for (const m of code.matchAll(/["'](4\.\d+\.\d+)["'][\s\S]{0,300}?Unsupported core-js use/g)) add('lodash', m[1], 'likely');

  // Moment: marker string plus version assignment.
  if (code.includes('moment construction falls back')) {
    for (const m of code.matchAll(/\.version\s*=\s*["'](2\.\d+\.\d+)["']/g)) add('moment', m[1], 'likely');
  }

  // AngularJS.
  for (const m of code.matchAll(/AngularJS v(1\.\d+\.\d+)/g)) add('angularjs', m[1], 'likely');
  for (const m of code.matchAll(/full:\s*["'](1\.\d+\.\d+)["']\s*,\s*major:/g)) add('angularjs', m[1], 'likely');

  // Axios: "[Axios v"+IDENT+"] or literal.
  for (const m of code.matchAll(/\[Axios v(?:(\d+\.\d+\.\d+)|["'`]\s*\+\s*([A-Za-z_$][\w$]*))/g)) {
    add('axios', m[1] ?? resolveIdent(code, m[2]!, m.index), 'likely');
  }
  for (const m of code.matchAll(/\[Axios v\$\{([A-Za-z_$][\w$]*)\}/g)) add('axios', resolveIdent(code, m[1]!, m.index), 'likely');

  // Next.js.
  for (const m of code.matchAll(/window\.next\s*=\s*\{\s*version\s*:\s*(?:["'](\d+\.\d+\.\d+)[^"']*["']|([A-Za-z_$][\w$]*))/g)) {
    add('nextjs', m[1] ?? resolveIdent(code, m[2]!, m.index), 'possible');
  }
  return out;
}

const SEV_ORDER: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

interface VulnMatch {
  severity: DbSeverity;
  ids: string[];
  fixed: string;
}

/** Highest-severity matching rule wins; advisories of all matching rules are merged; `fixed` is the version that clears all of them. */
export function matchVulnerabilities(name: string, version: string): VulnMatch | null {
  const entry = VULN_DB.find((e) => e.name === name);
  if (!entry) return null;
  let severity: DbSeverity | null = null;
  const ids: string[] = [];
  let fixed: string | null = null;
  for (const rule of entry.rules) {
    const range = rule.ranges.find((x) => (x.from === null || compareVersions(version, x.from) >= 0) && compareVersions(version, x.to) < 0);
    if (!range) continue;
    if (severity === null || SEV_ORDER[rule.severity]! > SEV_ORDER[severity]!) severity = rule.severity;
    for (const id of rule.ids) if (!ids.includes(id)) ids.push(id);
    if (fixed === null || compareVersions(range.to, fixed) > 0) fixed = range.to;
  }
  return severity ? { severity, ids, fixed: fixed ?? '–' } : null;
}

const LABEL: Record<string, string> = {
  jquery: 'jQuery',
  'jquery-ui': 'jQuery UI',
  bootstrap: 'Bootstrap',
  lodash: 'Lodash',
  moment: 'Moment.js',
  angularjs: 'AngularJS',
  vue2: 'Vue 2',
  dompurify: 'DOMPurify',
  axios: 'Axios',
  nextjs: 'Next.js',
};

/** Known-vulnerable and end-of-life client libraries, recognised by version markers in the shipped JavaScript. */
export const depsVulnerable: CheckModule = {
  manifest: {
    id: 'deps.vulnerable',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:js-bundle', 'artifact:page'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = depsVulnerable.manifest;
    try {
      const sources: { url: string; code: string }[] = ctx.artifacts.list('js-bundle').map((a) => {
        const b = a.data as BundleData;
        return { url: b.url, code: b.code };
      });
      for (const a of ctx.artifacts.list('page')) {
        const p = a.data as PageData;
        sources.push({ url: p.finalUrl, code: p.html });
      }
      const out: Finding[] = [];
      const seen = new Set<string>();
      for (const src of sources) {
        for (const lib of detectLibraries(src.code)) {
          const key = `${lib.name}@${lib.version}`;
          if (seen.has(key)) continue;
          seen.add(key);
          const library = LABEL[lib.name] ?? lib.name;
          const common = { kind: `lib-${lib.name}`, confidence: lib.confidence, category: 'security' as const, location: { url: src.url }, evidence: `${library}@${lib.version}`, discriminator: key };
          const v = matchVulnerabilities(lib.name, lib.version);
          if (v) {
            // Next.js is only a 'possible' detection: do not report more than high.
            const severity: Severity = lib.confidence === 'possible' && v.severity === 'critical' ? 'high' : v.severity;
            out.push(finding(m, { ...common, severity, messageKey: 'deps.vulnerable', vars: { library, version: lib.version, advisories: v.ids.join(', '), fixed: v.fixed } }));
            continue;
          }
          const eol = EOL_DB.find((e) => e.name === lib.name && compareVersions(lib.version, e.from) >= 0 && compareVersions(lib.version, e.to) < 0);
          if (eol) {
            out.push(finding(m, { ...common, severity: eol.severity, messageKey: 'deps.eol', vars: { library, version: lib.version, eol: eol.eol } }));
          }
        }
      }
      return { findings: out };
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: 'error', detail: e instanceof Error ? e.message : String(e) }] };
    }
  },
};
