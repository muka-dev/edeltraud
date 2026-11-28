import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, ModuleContext, NotChecked, RenderAudit, RenderData, Severity } from '../../core/types.ts';

/** Rules a11y.basics already reports from the same DOM; axe would only repeat them. */
const COVERED = new Set(['html-has-lang', 'html-lang-valid', 'image-alt', 'label', 'button-name', 'link-name', 'meta-viewport', 'document-title']);
const IMPACT: Record<string, Severity> = { critical: 'high', serious: 'medium', moderate: 'low', minor: 'low' };

/** null: no rendered page at all (collect.render already says why). */
function audit<K extends keyof RenderAudit>(ctx: ModuleContext, id: string, key: K): { render: RenderData; value: NonNullable<RenderAudit[K]> } | NotChecked | null {
  const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
  if (!render) return null;
  const value = render.audit?.[key];
  if (!value) return { module: id, reason: 'condition', detail: 'rendered page without audit (collect.render audit:true)' };
  return { render, value: value as NonNullable<RenderAudit[K]> };
}
const isGap = (x: object): x is NotChecked => 'reason' in x;

/** axe-core results of the rendered start page (WCAG A/AA rules that can be checked automatically). */
export const a11yAxe: CheckModule = {
  manifest: {
    id: 'a11y.axe',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'accessibility',
    requires: [],
    uses: ['artifact:render'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = a11yAxe.manifest;
    const a = audit(ctx, m.id, 'axe');
    if (!a) return {};
    if (isGap(a)) return { notChecked: [a] };
    if ('error' in a.value) return { notChecked: [{ module: m.id, reason: 'error', detail: a.value.error }] };
    const minor = a.value.version.split('.').slice(0, 2).join('.');
    const findings: Finding[] = [];
    for (const v of a.value.violations) {
      if (COVERED.has(v.id)) continue;
      const contrast = v.id === 'color-contrast';
      findings.push(
        finding(m, {
          kind: v.id,
          severity: IMPACT[v.impact ?? ''] ?? 'low',
          confidence: 'likely',
          location: { url: a.render.finalUrl },
          evidence: `${v.id}: ${v.nodes} × (${v.targets.join(', ')})`,
          messageKey: contrast ? 'a11y.contrast' : 'a11y.axe',
          vars: {
            rule: v.id,
            count: String(v.nodes),
            sample: v.targets.join(', '),
            link: `https://dequeuniversity.com/rules/axe/${minor}/${v.id}`,
          },
          discriminator: v.id,
        }),
      );
    }
    return { findings, facts: { 'a11y.axe': { version: a.value.version, rules: a.value.violations.length } } };
  },
};

const KB = 1024;
const fmt = (n: number) => (n >= KB * KB ? `${(n / KB / KB).toFixed(1)} MB` : `${Math.round(n / KB)} KB`);
const WEIGHT = { totalLow: 2.5 * KB * KB, totalMedium: 5 * KB * KB, script: 1 * KB * KB, image: 500 * KB };

/** Transferred bytes of one load of the start page: total, JavaScript, single large images. */
export const perfWeight: CheckModule = {
  manifest: {
    id: 'perf.weight',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'quality',
    requires: [],
    uses: ['artifact:render'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = perfWeight.manifest;
    const a = audit(ctx, m.id, 'perf');
    if (!a) return {};
    if (isGap(a)) return { notChecked: [a] };
    const { bytes, largestImages } = a.value;
    const total = Object.values(bytes).reduce((s, n) => s + n, 0);
    const loc = { url: a.render.finalUrl };
    const out: Finding[] = [];
    if (total > WEIGHT.totalLow) {
      out.push(finding(m, {
        kind: 'total', severity: total > WEIGHT.totalMedium ? 'medium' : 'low', confidence: 'confirmed', location: loc,
        evidence: `${total} bytes`, messageKey: 'perf.weight-total', vars: { size: fmt(total) },
      }));
    }
    const js = bytes.script ?? 0;
    if (js > WEIGHT.script) {
      out.push(finding(m, {
        kind: 'script', severity: 'low', confidence: 'confirmed', location: loc,
        evidence: `${js} bytes`, messageKey: 'perf.weight-js', vars: { size: fmt(js) },
      }));
    }
    const big = largestImages.filter((i) => i.bytes > WEIGHT.image);
    if (big.length) {
      out.push(finding(m, {
        kind: 'image', severity: 'low', confidence: 'confirmed', location: { url: big[0]!.url },
        evidence: big.map((i) => `${i.url} ${i.bytes}`).join('; '), messageKey: 'perf.weight-image',
        vars: { count: String(big.length), sample: big.slice(0, 3).map((i) => `${i.url.split('/').pop() || i.url} (${fmt(i.bytes)})`).join(', ') },
      }));
    }
    return { findings: out, facts: { 'perf.weight': { total, ...bytes } } };
  },
};

/** Thresholds of the Core Web Vitals ("needs improvement" / "poor"); TBT stands in for INP in the lab. */
const VITALS = [
  { key: 'lcpMs', kind: 'lcp', low: 2500, medium: 4000, show: (n: number) => `${(n / 1000).toFixed(1)} s` },
  { key: 'cls', kind: 'cls', low: 0.1, medium: 0.25, show: (n: number) => n.toFixed(2) },
  { key: 'tbtMs', kind: 'tbt', low: 200, medium: 600, show: (n: number) => `${Math.round(n)} ms` },
] as const;

/** Lab values of one desktop load (LCP, CLS, TBT). One run, so only "possible". */
export const perfVitals: CheckModule = {
  manifest: {
    id: 'perf.vitals',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'quality',
    requires: [],
    uses: ['artifact:render'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = perfVitals.manifest;
    const a = audit(ctx, m.id, 'perf');
    if (!a) return {};
    if (isGap(a)) return { notChecked: [a] };
    const out: Finding[] = [];
    for (const v of VITALS) {
      const n = a.value[v.key];
      if (n == null || n <= v.low) continue;
      out.push(finding(m, {
        kind: v.kind, severity: n > v.medium ? 'medium' : 'low', confidence: 'possible', location: { url: a.render.finalUrl },
        evidence: `${v.kind} ${n}`, messageKey: `perf.${v.kind}`, vars: { value: v.show(n), limit: v.show(v.low) },
      }));
    }
    return { findings: out, facts: { 'perf.vitals': { lcpMs: a.value.lcpMs, cls: a.value.cls, tbtMs: a.value.tbtMs } } };
  },
};
