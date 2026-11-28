import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, ModuleContext, RenderData } from '../../core/types.ts';
import type { PageData } from '../util.ts';
import { isSpaShell } from './privacy.ts';
import { staticLinks } from '../collect/legal.ts';

// ---------- small HTML helpers (regex-based, like the other passive analyzers) ----------

/** Attributes of one start tag, names lower-cased. Valueless attributes get ''. */
export function attrsOf(tag: string): Record<string, string> {
  const out: Record<string, string> = {};
  const body = tag.replace(/^<\w+/, '').replace(/\/?>$/, '');
  for (const m of body.matchAll(/([^\s"'=<>\/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g)) {
    const name = m[1]!.toLowerCase();
    if (!(name in out)) out[name] = m[2] ?? m[3] ?? m[4] ?? '';
  }
  return out;
}

/** Removes comments, scripts, styles and templates: their content is not part of the page. */
export function cleanHtml(html: string): string {
  // Comments by index, each replaced by a space so no new '<!--' can form; an unterminated one runs to the end.
  let out = '';
  for (let i = 0; ; ) {
    const start = html.indexOf('<!--', i);
    if (start < 0) { out += html.slice(i); break; }
    out += html.slice(i, start) + ' ';
    const end = html.indexOf('-->', start + 4);
    if (end < 0) break;
    i = end + 3;
  }
  return out.replace(/<(script|style|template|noscript)\b[\s\S]*?<\/\1>/gi, ' ');
}

/** Visible text of a fragment. */
export function textOf(fragment: string): string {
  return fragment.replace(/<[^>]*>/g, ' ').replace(/&nbsp;|&#160;/gi, ' ').replace(/\s+/g, ' ').trim();
}

const hidden = (a: Record<string, string>) => a['aria-hidden'] === 'true' || 'hidden' in a;
const named = (a: Record<string, string>) => !!(a['aria-label']?.trim() || a['aria-labelledby']?.trim() || a['title']?.trim());

/** Short selector-like description of an element, without values entered or shown to users. */
function describe(tag: string, a: Record<string, string>): string {
  const t = tag.toLowerCase();
  let s = t;
  if (a.id) s += `#${a.id}`;
  else if (a.name) s += `[name=${a.name}]`;
  else if (t === 'img' && a.src) s += `[src=${a.src.replace(/[?#].*$/, '').split('/').pop() || a.src}]`;
  else if (t === 'a' && a.href) s += `[href=${a.href.replace(/[?#].*$/, '')}]`;
  else if (a.class) s += `.${a.class.trim().split(/\s+/)[0]}`;
  else if (a.type) s += `[type=${a.type}]`;
  return s.length > 60 ? s.slice(0, 59) + '…' : s;
}

// ---------- rules ----------

export type A11yRule = 'no-lang' | 'img-alt' | 'input-label' | 'control-name' | 'zoom-blocked' | 'no-title';

/** Problems of one page: rule → samples (one entry per affected element). */
export function a11yIssues(html: string): Map<A11yRule, string[]> {
  const out = new Map<A11yRule, string[]>();
  const add = (r: A11yRule, s: string) => (out.get(r) ?? out.set(r, []).get(r)!).push(s);
  const doc = cleanHtml(html);

  const htmlTag = doc.match(/<html\b[^>]*>/i)?.[0];
  if (!(htmlTag && attrsOf(htmlTag).lang?.trim())) add('no-lang', 'html');

  const noSvg = doc.replace(/<svg\b[\s\S]*?<\/svg>/gi, ' ');
  const title = noSvg.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i);
  if (!title || !textOf(title[1]!)) add('no-title', 'title');

  for (const m of doc.matchAll(/<meta\b[^>]*>/gi)) {
    const a = attrsOf(m[0]);
    if (a.name?.toLowerCase() !== 'viewport') continue;
    const c = (a.content ?? '').toLowerCase().replace(/\s+/g, '');
    const us = c.match(/user-scalable=([^,;]+)/)?.[1];
    const max = c.match(/maximum-scale=([\d.]+)/)?.[1];
    if (us === 'no' || us === '0' || (max !== undefined && Number(max) < 2)) add('zoom-blocked', (a.content ?? '').trim().slice(0, 80));
  }

  for (const m of doc.matchAll(/<img\b[^>]*>/gi)) {
    const a = attrsOf(m[0]);
    if (hidden(a) || a.role === 'presentation' || a.role === 'none') continue;
    if ('alt' in a || named(a)) continue;
    add('img-alt', describe('img', a));
  }

  // Form fields: <label for>, a wrapping <label>, aria-label/-labelledby or title.
  const labelFor = new Set([...doc.matchAll(/<label\b[^>]*>/gi)].map((m) => attrsOf(m[0]).for).filter((x): x is string => !!x));
  const wraps = [...doc.matchAll(/<label\b[\s\S]*?<\/label>/gi)].map((m) => [m.index!, m.index! + m[0].length] as const);
  for (const m of doc.matchAll(/<(input|select|textarea)\b[^>]*>/gi)) {
    const tag = m[1]!.toLowerCase();
    const a = attrsOf(m[0]);
    const type = (a.type ?? 'text').toLowerCase();
    if (tag === 'input' && ['hidden', 'submit', 'button', 'reset', 'image'].includes(type)) continue;
    if (hidden(a) || named(a) || (a.id && labelFor.has(a.id))) continue;
    if (wraps.some(([s, e]) => m.index! > s && m.index! < e)) continue;
    add('input-label', describe(tag === 'input' ? `input[type=${type}]` : tag, { ...a, type: '' }));
  }

  // Buttons and links: visible text, aria-label/-labelledby, title, or an image with alt text inside.
  for (const m of doc.matchAll(/<(button|a)\b([^>]*)>([\s\S]*?)<\/\1>/gi)) {
    const tag = m[1]!.toLowerCase();
    const a = attrsOf(`<${tag}${m[2]}>`);
    if (tag === 'a' && !('href' in a)) continue;
    if (hidden(a) || named(a)) continue;
    const inner = m[3]!;
    if (textOf(inner.replace(/<svg\b[\s\S]*?<\/svg>/gi, ' '))) continue;
    const innerNamed = [...inner.matchAll(/<(img|svg|span|i)\b[^>]*>/gi)].some((x) => {
      const ia = attrsOf(x[0]);
      return (x[1]!.toLowerCase() === 'img' && !!ia.alt?.trim()) || !!ia['aria-label']?.trim();
    });
    if (innerNamed || /<svg\b[\s\S]*?<title\b[^>]*>\s*\S/i.test(inner)) continue;
    add('control-name', describe(tag, a));
  }
  return out;
}

const SEVERITY: Record<A11yRule, 'low' | 'medium'> = {
  'no-lang': 'medium',
  'zoom-blocked': 'medium',
  'img-alt': 'low',
  'input-label': 'low',
  'control-name': 'low',
  'no-title': 'low',
};

/** Start page (rendered if available) and static subpages; null if only an SPA shell is there. */
function pages(ctx: ModuleContext): { url: string; html: string }[] | null {
  const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
  const page = ctx.artifacts.list('page')[0]?.data as PageData | undefined;
  const out: { url: string; html: string }[] = [];
  if (render?.html) out.push({ url: render.finalUrl, html: render.html });
  else if (page && !isSpaShell(page.html)) out.push({ url: page.finalUrl, html: page.html });
  else if (page) return null;
  for (const a of ctx.artifacts.list('subpage')) {
    const d = a.data as PageData;
    if (!isSpaShell(d.html)) out.push({ url: d.finalUrl, html: d.html });
  }
  return out;
}

/** Accessibility basics from the HTML: hints, no statement about conformity. */
export const a11yBasics: CheckModule = {
  manifest: {
    id: 'a11y.basics',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'accessibility',
    requires: [],
    uses: ['artifact:page', 'artifact:render', 'artifact:subpage'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = a11yBasics.manifest;
    const list = pages(ctx);
    if (list === null) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'SPA shell: needs the rendered page' }] };
    if (!list.length) return {};
    const agg = new Map<A11yRule, { count: number; pages: number; samples: string[] }>();
    for (const p of list) {
      for (const [rule, samples] of a11yIssues(p.html)) {
        const e = agg.get(rule) ?? { count: 0, pages: 0, samples: [] };
        e.count += samples.length;
        e.pages++;
        for (const s of samples) if (e.samples.length < 3 && !e.samples.includes(s)) e.samples.push(s);
        agg.set(rule, e);
      }
    }
    const findings: Finding[] = [];
    for (const rule of Object.keys(SEVERITY) as A11yRule[]) {
      const e = agg.get(rule);
      if (!e) continue;
      findings.push(
        finding(m, {
          kind: rule,
          severity: SEVERITY[rule],
          confidence: 'likely',
          location: { url: ctx.target.url },
          messageKey: `a11y.${rule}`,
          vars: { count: String(e.count), pages: String(e.pages), sample: e.samples.join(', ') },
        }),
      );
    }
    return { findings };
  },
};

const STATEMENT_TEXT = /barrierefrei|accessibilit|acessibilidade|accesibilidad/i;
const STATEMENT_HREF = /barrierefrei|accessibility|acessibilidade|accesibilidad|\/a11y\b/i;

/** Is an accessibility statement linked? */
export const a11yStatement: CheckModule = {
  manifest: {
    id: 'a11y.statement',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'accessibility',
    requires: [],
    uses: ['artifact:page', 'artifact:render', 'artifact:subpage'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = a11yStatement.manifest;
    const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
    const page = ctx.artifacts.list('page')[0]?.data as PageData | undefined;
    let links: { href: string; text: string }[];
    if (render) links = render.links.length ? render.links : staticLinks(render.html);
    else if (page && !isSpaShell(page.html)) links = staticLinks(page.html);
    else if (page) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'SPA shell: needs the rendered page' }] };
    else return {};
    for (const a of ctx.artifacts.list('subpage')) links.push(...staticLinks((a.data as PageData).html));
    const hit = links.some((l) => (l.text.length <= 80 && STATEMENT_TEXT.test(l.text)) || STATEMENT_HREF.test(l.href.replace(/[?#].*$/, '')));
    if (hit) return {};
    return {
      findings: [
        finding(m, { kind: 'missing', severity: 'low', confidence: 'possible', location: { url: ctx.target.url }, messageKey: 'a11y.no-statement' }),
      ],
    };
  },
};
