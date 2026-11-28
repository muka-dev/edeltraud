import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, RenderData } from '../../core/types.ts';
import type { PageData } from '../util.ts';
import type { ErrorPageData } from '../collect/errorpages.ts';
import { isSpaShell } from './privacy.ts';
import { attrsOf, cleanHtml, textOf } from './a11y.ts';

const TITLE_MAX = 65;

/** SEO basics of the start page as delivered (static HTML, as a crawler first sees it). */
export const seoBasics: CheckModule = {
  manifest: {
    id: 'seo.basics',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'quality',
    requires: ['artifact:page'],
    uses: ['artifact:render'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = seoBasics.manifest;
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    if (page.status >= 400) return {};
    const doc = cleanHtml(page.html);
    const head = doc.replace(/<svg\b[\s\S]*?<\/svg>/gi, ' ');
    const metas = [...head.matchAll(/<meta\b[^>]*>/gi)].map((x) => attrsOf(x[0]));
    const meta = (key: 'name' | 'property', v: string) => metas.find((a) => a[key]?.toLowerCase() === v)?.content?.trim();
    const loc = { url: page.finalUrl };
    const out: Finding[] = [];
    const add = (kind: string, messageKey: string, severity: 'low' | 'medium', vars?: Record<string, string>) =>
      out.push(finding(m, { kind, severity, confidence: 'confirmed', location: loc, messageKey, ...(vars ? { vars } : {}) }));

    const title = textOf(head.match(/<title\b[^>]*>([\s\S]*?)<\/title>/i)?.[1] ?? '').replace(/&amp;/g, '&');
    if (!title) add('title-missing', 'seo.title-missing', 'low');
    else if (title.length > TITLE_MAX) add('title-long', 'seo.title-long', 'low', { length: String(title.length), max: String(TITLE_MAX) });

    if (!meta('name', 'description')) add('description-missing', 'seo.description-missing', 'low');

    const canonical = [...head.matchAll(/<link\b[^>]*>/gi)].map((x) => attrsOf(x[0])).some((a) => /\bcanonical\b/i.test(a.rel ?? '') && a.href?.trim());
    if (!canonical) add('canonical-missing', 'seo.canonical-missing', 'low');

    const NOINDEX = /\b(noindex|none)\b/i;
    const xRobots = page.headers['x-robots-tag'] ?? '';
    const metaRobots = [meta('name', 'robots'), meta('name', 'googlebot')].join(',');
    if (NOINDEX.test(xRobots) || NOINDEX.test(metaRobots)) add('noindex', 'seo.noindex', 'medium', { source: NOINDEX.test(xRobots) ? 'X-Robots-Tag' : 'meta robots' });

    // h1 needs content: from the rendered page if the delivered HTML is only an app shell.
    const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
    const body = isSpaShell(page.html) ? (render?.html ? cleanHtml(render.html) : null) : doc;
    if (body !== null) {
      const h1 = (body.match(/<h1\b/gi) ?? []).length;
      if (h1 === 0) add('h1-missing', 'seo.h1-missing', 'low');
      else if (h1 > 1) add('h1-multiple', 'seo.h1-multiple', 'low', { count: String(h1) });
    }

    const og = ['og:title', 'og:image'].filter((p) => !meta('property', p) && !meta('name', p));
    if (og.length) add('og-missing', 'seo.og-missing', 'low', { list: og.join(', ') });
    return { findings: out };
  },
};

const looksHtml = (e: ErrorPageData) => /text\/html|application\/xhtml/i.test(e.headers['content-type'] ?? '') || /^\s*(<!doctype html|<html\b)/i.test(e.body);

/** A made-up path answers 200 with an HTML page (soft 404). Uses the probes of collect.errorpages. */
export const ops404: CheckModule = {
  manifest: {
    id: 'ops.404',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'operations',
    requires: [],
    uses: ['artifact:error-page'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = ops404.manifest;
    const soft = ctx.artifacts
      .list('error-page')
      .map((a) => a.data as ErrorPageData)
      .filter((e) => e.status >= 200 && e.status < 300 && looksHtml(e));
    if (!soft.length) return {};
    const paths = soft.map((e) => new URL(e.url).pathname);
    return {
      findings: [
        finding(m, {
          kind: 'soft-404',
          severity: 'low',
          confidence: 'confirmed',
          location: { url: soft[0]!.url },
          messageKey: 'ops.soft-404',
          vars: { paths: paths.join(', '), status: String(soft[0]!.status) },
        }),
      ],
    };
  },
};
