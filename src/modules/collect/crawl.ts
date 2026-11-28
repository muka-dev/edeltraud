import { createHash } from 'node:crypto';
import type { Artifact, CheckModule, HttpResponse, NotChecked } from '../../core/types.ts';
import { parseRobots } from '../analyze/wellknown.ts';
import type { PageData } from '../util.ts';
import { isRobotsTxt, isSitemap, type WellknownData } from './wellknown.ts';

/** Paths that might change state when visited: never requested. Matched at the start of a path segment. */
const DESTRUCTIVE = /(?:^|[/_.-])(?:log-?out|sign-?out|log-?off|delete|remove|destroy|unsubscribe|checkout|pay|cart|basket|admin|cancel|confirm|verify|reset|activate)/i;
const NON_HTML =
  /\.(?:pdf|zip|gz|tgz|tar|rar|7z|jpe?g|png|gif|webp|avif|svg|ico|bmp|mp[34]|m4a|webm|mov|avi|wav|ogg|woff2?|ttf|otf|eot|css|m?js|json|xml|txt|csv|xlsx?|docx?|pptx?|odt|rss|atom|apk|dmg|exe|map|wasm)$/i;
/** Query parameters that may carry a token, session or one-time code. */
const TOKEN_PARAM = /token|key|auth|code|session|sid|sig|secret|pass|jwt|otp|invite|hash|nonce|ticket|state/i;
const looksLikeHtml = (body: string) => /^\s*(?:<!doctype html|<html|<head|<body)/i.test(body);
const sha = (s: string) => createHash('sha256').update(s).digest('hex');

/** robots.txt Disallow rules of the '*' group as regular expressions ('*' wildcard, '$' end anchor). */
export function robotsDisallow(body: string | undefined): RegExp[] {
  if (!body) return [];
  return parseRobots(body)
    .filter((g) => g.agents.includes('*'))
    .flatMap((g) => g.disallow)
    .map((d) => {
      const end = d.endsWith('$');
      const core = (end ? d.slice(0, -1) : d).replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
      return new RegExp('^' + core + (end ? '$' : ''));
    });
}

/** Same-origin page URL without fragment, or null if it must not be requested. */
export function crawlable(ref: string, base: string, origin: string, disallow: RegExp[]): string | null {
  let u: URL;
  try {
    u = new URL(ref.trim(), base);
  } catch {
    return null;
  }
  if (u.origin !== origin) return null;
  u.hash = '';
  if (NON_HTML.test(u.pathname) || DESTRUCTIVE.test(u.pathname)) return null;
  if ([...u.searchParams.keys()].some((k) => TOKEN_PARAM.test(k))) return null;
  const path = u.pathname + u.search;
  if (disallow.some((re) => re.test(path))) return null;
  return u.toString();
}

/** href values of plain <a> links in the HTML. */
function anchorHrefs(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/<a\b([^>]*)>/gi)) {
    const attrs = m[1] ?? '';
    const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1] ?? attrs.match(/\bhref\s*=\s*([^\s"'>]+)/i)?.[1];
    if (href && !/^(?:javascript|mailto|tel|data):/i.test(href)) out.push(href);
  }
  return out;
}

/**
 * Loads up to maxPages further pages of the same origin as 'subpage' artifacts (PageData shape), so that
 * analyzers can look beyond the start page. Sources in order: sitemap.xml, links on the start page.
 * Plain GETs only; robots.txt Disallow for '*' is respected; logout/delete/checkout-like paths,
 * non-HTML files and URLs with token-like query parameters are skipped. Pages identical to the
 * start page (SPA fallback) are dropped. Being cut short never makes the run incomplete: the
 * start page checks are complete without it.
 */
export const collectCrawl: CheckModule<{ maxPages: number }> = {
  manifest: {
    id: 'collect.crawl',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'operations',
    requires: ['artifact:page'],
    uses: ['artifact:wellknown'],
    provides: ['artifact:subpage'],
    params: { maxPages: { type: 'number', default: 5, min: 1, max: 20 } },
    // maxPages (max 20) + robots.txt and sitemap.xml when collect.wellknown is not in the plan.
    budget: { requests: 22, ms: 30_000 },
  },
  async run(ctx, params) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const origin = new URL(page.finalUrl).origin;
    const http = ctx.http!;
    const notChecked: NotChecked[] = [];
    const cut = (detail: string) => notChecked.push({ module: 'collect.crawl', reason: 'condition', detail });
    const get = async (url: string, maxBytes: number): Promise<HttpResponse | null> => {
      try {
        return await http.fetch({ url, maxBytes });
      } catch (e) {
        if (e instanceof Error && e.name === 'BudgetExceededError') throw e;
        ctx.log.debug(`collect.crawl: ${url} failed`, e);
        return null;
      }
    };

    const artifacts: Artifact[] = [];
    try {
      // robots.txt and sitemap: from collect.wellknown if it ran, otherwise fetched here.
      const wk = ctx.artifacts.list('wellknown')[0]?.data as WellknownData | undefined;
      let robots: string | undefined;
      let sitemap: string[];
      if (wk) {
        robots = wk.robots.body;
        sitemap = wk.sitemap.index ? [] : wk.sitemap.sample;
      } else {
        const r = await get(origin + '/robots.txt', 64 * 1024);
        robots = r && isRobotsTxt(r) ? r.body : undefined;
        const s = await get(origin + '/sitemap.xml', 64 * 1024);
        sitemap = s && isSitemap(s) && !/<sitemapindex\b/.test(s.body) ? [...s.body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]!) : [];
      }
      const disallow = robotsDisallow(robots);

      const skip = new Set([page.url, page.finalUrl, ctx.target.url].map((u) => crawlable(u, u, origin, []) ?? u));
      const queue: string[] = [];
      for (const ref of [...sitemap, ...anchorHrefs(page.html)]) {
        const u = crawlable(ref, page.finalUrl, origin, disallow);
        if (u && !skip.has(u)) {
          skip.add(u);
          queue.push(u);
        }
      }

      const hashes = new Set([sha(page.html)]);
      let tried = 0;
      while (queue.length && tried < params.maxPages) {
        if (ctx.signal.aborted) {
          cut('time limit reached');
          break;
        }
        const url = queue.shift()!;
        tried++;
        const res = await get(url, 2 * 1024 * 1024);
        if (!res || res.status !== 200) continue;
        if (new URL(res.finalUrl).origin !== origin) continue;
        const type = res.headers['content-type'];
        if (type ? !/text\/html|application\/xhtml/i.test(type) : !looksLikeHtml(res.body)) continue;
        // SPA fallback (or a redirect back to a known page): the same HTML adds nothing.
        const h = sha(res.body);
        if (hashes.has(h)) continue;
        hashes.add(h);
        const data: PageData = {
          url: res.url,
          finalUrl: res.finalUrl,
          status: res.status,
          headers: res.headers,
          setCookies: res.setCookies,
          html: res.body,
          redirects: res.redirects,
        };
        artifacts.push({ type: 'subpage', key: res.finalUrl, data });
      }
    } catch (e) {
      // Plan request budget exhausted: keep what was loaded so far.
      cut(e instanceof Error ? e.message : String(e));
    }
    return { artifacts, notChecked };
  },
};
