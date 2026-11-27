import type { CheckModule, NotChecked, RenderData } from '../../core/types.ts';
import { sameSite, type PageData } from '../util.ts';

export interface LegalLink {
  href: string;
  status: number;
}
export interface LegalPagesData {
  imprint: LegalLink | null;
  privacy: LegalLink | null;
  source: 'render' | 'html';
}

const IMPRINT = /impressum|imprint|legal[\s_-]?notice|aviso[\s_-]legal|informa[cç][aã]o[\s_-]legal|ficha[\s_-]t[eé]cnica/i;
const PRIVACY = /datenschutz|privacy|privacidade|pol[ií]tica[\s_-]de[\s_-]privacidade|lgpd|rgpd|data[\s_-]protection/i;

/** True if the HTML has (almost) no visible text and no links: an SPA shell that needs rendering. */
export function isSpaShell(html: string): boolean {
  const body = html
    .replace(/<!--[\s\S]*?-->/g, '')
    .replace(/<(script|style|noscript|template)\b[\s\S]*?<\/\1>/gi, '');
  if (/<a\b[^>]*\bhref\s*=/i.test(body)) return false;
  const text = body
    .replace(/<head\b[\s\S]*?<\/head>/i, '')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&[a-z#0-9]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return text.length < 40;
}

/** Anchors from static HTML: href and visible text. */
export function staticLinks(html: string): { href: string; text: string }[] {
  const out: { href: string; text: string }[] = [];
  const clean = html.replace(/<!--[\s\S]*?-->/g, '').replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, '');
  for (const m of clean.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)) {
    const href = (m[1] ?? '').match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i);
    const h = href?.[1] ?? href?.[2] ?? href?.[3];
    if (h === undefined) continue;
    out.push({ href: h.replace(/&amp;/g, '&'), text: (m[2] ?? '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim() });
  }
  return out;
}

function pick(links: { href: string; text: string }[], base: string, host: string, re: RegExp): string | null {
  for (const l of links) {
    let u: URL;
    try {
      u = new URL(l.href, base);
    } catch {
      continue;
    }
    if (u.protocol !== 'https:' && u.protocol !== 'http:') continue;
    if (!sameSite(u.hostname, host)) continue;
    let path = u.pathname + u.search;
    try {
      path = decodeURIComponent(path);
    } catch {
      /* keep raw */
    }
    // The start page itself is not a legal page, and long link texts are sentences, not labels.
    const hit = (u.pathname !== '/' && re.test(path)) || (l.text.length <= 60 && re.test(l.text));
    if (hit) {
      u.hash = '';
      return u.toString();
    }
  }
  return null;
}

/** Finds the first imprint and privacy link and checks that each one answers. */
export const collectLegal: CheckModule = {
  manifest: {
    id: 'collect.legal',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'privacy',
    requires: [],
    uses: ['artifact:render', 'artifact:page'],
    provides: ['artifact:legal-pages'],
    params: {},
    budget: { requests: 2, ms: 10_000 },
  },
  async run(ctx) {
    const id = collectLegal.manifest.id;
    const render = ctx.artifacts.list('render')[0]?.data as RenderData | undefined;
    const page = ctx.artifacts.list('page')[0]?.data as PageData | undefined;
    let source: 'render' | 'html';
    let links: { href: string; text: string }[];
    let base: string;
    if (render) {
      source = 'render';
      links = render.links.length ? render.links : staticLinks(render.html);
      base = render.finalUrl;
    } else if (page) {
      if (isSpaShell(page.html)) {
        return { notChecked: [{ module: id, reason: 'unsupported', detail: 'needs rendering' }] };
      }
      source = 'html';
      links = staticLinks(page.html);
      base = page.finalUrl;
    } else {
      return {};
    }
    const host = new URL(base).hostname;
    const found = { imprint: pick(links, base, host, IMPRINT), privacy: pick(links, base, host, PRIVACY) };
    const notChecked: NotChecked[] = [];
    const check = async (href: string | null): Promise<LegalLink | null> => {
      if (!href) return null;
      try {
        const res = await ctx.http!.fetch({ url: href, followRedirects: true, maxBytes: 16 * 1024 });
        return { href, status: res.status };
      } catch (e) {
        // A request that cannot be made (network error) is unknown, not "unreachable".
        notChecked.push({ module: id, reason: 'error', detail: String(e instanceof Error ? e.message : e).slice(0, 120) });
        return { href, status: 0 };
      }
    };
    const imprint = await check(found.imprint);
    const privacy = await check(found.privacy);
    const data: LegalPagesData = { imprint, privacy, source };
    return { artifacts: [{ type: 'legal-pages', key: base, data }], notChecked };
  },
};
