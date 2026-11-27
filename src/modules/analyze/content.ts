import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, RenderData } from '../../core/types.ts';
import { sameSite, type PageData } from '../util.ts';

interface Ref {
  tag: string;
  rel?: string;
  attrs: string;
}

function attr(attrs: string, name: string): string | undefined {
  const m = attrs.match(new RegExp(`(?:^|\\s)${name}\\s*=\\s*(?:"([^"]*)"|'([^']*)'|([^\\s>]+))`, 'i'));
  return m ? (m[1] ?? m[2] ?? m[3]) : undefined;
}

/** HTML without comments and script/style bodies, so that code strings are not mistaken for markup. */
function markup(html: string): string {
  return html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style)\b([^>]*)>[\s\S]*?<\/\1>/gi, '<$1$2></$1>');
}

function tags(html: string, names: string[]): Ref[] {
  const out: Ref[] = [];
  const re = new RegExp(`<(${names.join('|')})\\b([^>]*)>`, 'gi');
  for (const m of markup(html).matchAll(re)) out.push({ tag: m[1]!.toLowerCase(), attrs: m[2] ?? '' });
  return out;
}

function sample(url: string): string {
  return url.replace(/[?#].*$/, '').slice(0, 120);
}

/** https page that loads active or passive subresources over http. */
export const mixedContent: CheckModule = {
  manifest: {
    id: 'mixed.content',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:render', 'artifact:page'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = mixedContent.manifest;
    const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
    const page = ctx.artifacts.list('page')[0]?.data as PageData | undefined;
    const base = render?.finalUrl ?? page?.finalUrl;
    if (!base || !base.startsWith('https://')) return {};

    const active = new Set<string>();
    const passive = new Set<string>();
    const add = (set: Set<string>, ref: string | undefined) => {
      if (ref && /^http:\/\//i.test(ref.trim())) set.add(ref.trim());
    };

    if (render) {
      for (const q of render.requests) {
        if (!q.url.startsWith('http://')) continue;
        if (['image', 'media'].includes(q.resourceType)) passive.add(q.url);
        else if (['script', 'stylesheet', 'document', 'xhr', 'fetch', 'font', 'websocket', 'eventsource'].includes(q.resourceType)) active.add(q.url);
      }
    }
    // Static markup: skipped when the page asks the browser to upgrade insecure requests.
    const csp = page?.headers['content-security-policy'] ?? '';
    if (!/upgrade-insecure-requests/i.test(csp)) {
      for (const html of [page?.html, render?.html]) {
        if (!html) continue;
        for (const t of tags(html, ['script', 'link', 'img', 'iframe', 'audio', 'video', 'source', 'form'])) {
          if (t.tag === 'script' || t.tag === 'iframe') add(active, attr(t.attrs, 'src'));
          else if (t.tag === 'link') {
            if (/\bstylesheet\b/i.test(attr(t.attrs, 'rel') ?? '')) add(active, attr(t.attrs, 'href'));
          } else if (t.tag === 'form') add(active, attr(t.attrs, 'action'));
          else add(passive, attr(t.attrs, 'src'));
        }
      }
    }

    const out: Finding[] = [];
    const loc = { url: base };
    if (active.size) {
      const first = [...active][0]!;
      out.push(finding(m, { kind: 'active', severity: 'medium', confidence: 'confirmed', location: loc, messageKey: 'mixed.active', vars: { count: String(active.size), sample: sample(first) }, discriminator: sample(first) }));
    }
    for (const u of active) passive.delete(u);
    if (passive.size) {
      const first = [...passive][0]!;
      out.push(finding(m, { kind: 'passive', severity: 'low', confidence: 'confirmed', location: loc, messageKey: 'mixed.passive', vars: { count: String(passive.size), sample: sample(first) }, discriminator: sample(first) }));
    }
    return { findings: out };
  },
};

/** Services that change without notice or are meant to be loaded from their own host: SRI cannot work. */
const SELF_UPDATING: RegExp[] = [
  /(^|\.)googletagmanager\.com$/,
  /(^|\.)google-analytics\.com$/,
  /^fonts\.googleapis\.com$/,
  /^(www\.)?google\.com$/, // reCAPTCHA
  /^(www\.)?gstatic\.com$/, // reCAPTCHA
  /(^|\.)recaptcha\.net$/,
  /(^|\.)stripe\.(com|network)$/,
  /(^|\.)paypal\.com$/,
  /(^|\.)paypalobjects\.com$/,
  /(^|\.)cloudflareinsights\.com$/,
  /(^|\.)facebook\.net$/,
  /(^|\.)facebook\.com$/,
  /(^|\.)intercom\.io$/,
  /(^|\.)intercomcdn\.com$/,
  /(^|\.)clerk\.(com|accounts\.dev)$/,
  /(^|\.)sentry-cdn\.com$/,
  /(^|\.)crisp\.chat$/,
  /(^|\.)gpteng\.co$/, // Lovable
  /(^|\.)lovable\.(dev|app)$/,
];

/** Third-party scripts and stylesheets without an integrity attribute. */
export const sriMissing: CheckModule = {
  manifest: {
    id: 'sri.missing',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    uses: ['artifact:render'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = sriMissing.manifest;
    const page = ctx.artifacts.list('page')[0]?.data as PageData | undefined;
    if (!page) return {};
    const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
    const found = new Set<string>();
    for (const [html, base] of [[page.html, page.finalUrl], [render?.html, render?.finalUrl ?? page.finalUrl]] as const) {
      if (!html) continue;
      for (const t of tags(html, ['script', 'link'])) {
        const ref = t.tag === 'script' ? attr(t.attrs, 'src') : /\bstylesheet\b/i.test(attr(t.attrs, 'rel') ?? '') ? attr(t.attrs, 'href') : undefined;
        if (!ref || attr(t.attrs, 'integrity')) continue;
        let u: URL;
        try {
          u = new URL(ref, base);
        } catch {
          continue;
        }
        if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
        const host = u.hostname.toLowerCase();
        if (sameSite(host, ctx.target.host)) continue;
        if (SELF_UPDATING.some((re) => re.test(host))) continue;
        found.add(u.toString());
      }
    }
    if (!found.size) return {};
    const first = [...found][0]!;
    return {
      findings: [finding(m, {
        kind: 'missing', severity: 'low', confidence: 'confirmed', location: { url: page.finalUrl },
        messageKey: 'sri.missing', vars: { count: String(found.size), sample: sample(first) },
      })],
    };
  },
};
