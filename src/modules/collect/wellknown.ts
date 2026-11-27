import type { Artifact, CheckModule, HttpResponse, NotChecked } from '../../core/types.ts';
import { sameSite, type PageData } from '../util.ts';

export interface WellknownData {
  /** ISO time of the start page fetch (Date header if present). Analyzers compare dates against it. */
  checkedAt: string;
  securityTxt: { url: string; status: number; body?: string } | null;
  robots: { status: number; body?: string };
  sitemap: { status: number; urls: number; index: boolean; sample: string[] };
  manifest: {
    url: string;
    status: number;
    valid: boolean;
    linked: boolean;
    name?: string;
    shortName?: string;
    startUrl?: string;
    display?: string;
  };
}

const KIB = 1024;
const isHtml = (res: HttpResponse) => /html/i.test(res.headers['content-type'] ?? '');
/** SPA fallbacks answer 200 with index.html for every path: HTML content or a missing directive means "not a real file". */
const looksLikeHtml = (body: string) => /^\s*(?:<!doctype html|<html|<head|<body)/i.test(body);

export const isSecurityTxt = (res: HttpResponse): boolean =>
  res.status === 200 && !isHtml(res) && !looksLikeHtml(res.body) && /^\s*Contact\s*:/im.test(res.body);

export const isRobotsTxt = (res: HttpResponse): boolean =>
  res.status === 200 && !isHtml(res) && !looksLikeHtml(res.body) && /^\s*(?:user-agent|disallow|allow|sitemap)\s*:/im.test(res.body);

export const isSitemap = (res: HttpResponse): boolean =>
  res.status === 200 && !(isHtml(res) && !/xml/i.test(res.headers['content-type'] ?? '')) && /<(?:urlset|sitemapindex)\b/.test(res.body);

/** Finds <link rel="manifest" href="..."> and resolves it against the page URL. Same site only. */
export function findManifestLink(html: string, pageUrl: string): string | null {
  for (const m of html.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = m[1] ?? '';
    const rel = attrs.match(/\brel\s*=\s*["']?([^"'>]+)/i)?.[1] ?? '';
    if (!rel.toLowerCase().split(/\s+/).includes('manifest')) continue;
    const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1] ?? attrs.match(/\bhref\s*=\s*([^\s"'>]+)/i)?.[1];
    if (!href) continue;
    try {
      const u = new URL(href, pageUrl);
      if ((u.protocol === 'https:' || u.protocol === 'http:') && sameSite(u.hostname, new URL(pageUrl).hostname)) return u.toString();
    } catch {
      /* ignore broken href */
    }
  }
  return null;
}

function parseSitemap(body: string): { urls: number; index: boolean; sample: string[] } {
  const locs = [...body.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]!);
  const sample: string[] = [];
  for (const l of locs) {
    if (sample.length >= 20) break;
    try {
      sample.push(new URL(l).pathname.slice(0, 120));
    } catch {
      /* skip */
    }
  }
  return { urls: locs.length, index: /<sitemapindex\b/.test(body), sample };
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v.slice(0, 120) : undefined;
}

/** Fetches the small public files every site may publish: security.txt, robots.txt, sitemap.xml, manifest. Plain GETs. */
export const collectWellknown: CheckModule = {
  manifest: {
    id: 'collect.wellknown',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    provides: ['artifact:wellknown'],
    params: {},
    // 1 security.txt + 1 fallback + robots + sitemap + manifest in the worst case.
    budget: { requests: 5, ms: 15_000 },
  },
  async run(ctx) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const origin = new URL(page.finalUrl).origin;
    const http = ctx.http!;
    const failed: string[] = [];
    const get = async (url: string, maxBytes: number): Promise<HttpResponse | null> => {
      try {
        return await http.fetch({ url, maxBytes, followRedirects: true });
      } catch (e) {
        failed.push(`${new URL(url).pathname}: ${e instanceof Error ? e.message : String(e)}`.slice(0, 80));
        return null;
      }
    };

    // security.txt: .well-known first, root fallback only if the first answer is no real security.txt.
    let securityTxt: WellknownData['securityTxt'] = null;
    for (const path of ['/.well-known/security.txt', '/security.txt']) {
      const res = await get(origin + path, 16 * KIB);
      if (res && isSecurityTxt(res)) {
        securityTxt = { url: origin + path, status: res.status, body: res.body.slice(0, 8 * KIB) };
        break;
      }
    }

    const robotsRes = await get(origin + '/robots.txt', 64 * KIB);
    const robots: WellknownData['robots'] = robotsRes && isRobotsTxt(robotsRes)
      ? { status: robotsRes.status, body: robotsRes.body.slice(0, 16 * KIB) }
      : { status: robotsRes?.status ?? 0 };

    // Only the first 64 KiB of the sitemap are read.
    const sitemapRes = await get(origin + '/sitemap.xml', 64 * KIB);
    const sitemap: WellknownData['sitemap'] = sitemapRes && isSitemap(sitemapRes)
      ? { status: sitemapRes.status, ...parseSitemap(sitemapRes.body) }
      : { status: sitemapRes?.status ?? 0, urls: 0, index: false, sample: [] };

    const linked = findManifestLink(page.html, page.finalUrl);
    const manifestUrl = linked ?? origin + '/manifest.json';
    const manifestRes = await get(manifestUrl, 64 * KIB);
    const manifest: WellknownData['manifest'] = { url: manifestUrl, status: manifestRes?.status ?? 0, valid: false, linked: linked !== null };
    if (manifestRes && manifestRes.status === 200 && !isHtml(manifestRes) && !looksLikeHtml(manifestRes.body)) {
      try {
        const j = JSON.parse(manifestRes.body) as unknown;
        if (j && typeof j === 'object' && !Array.isArray(j)) {
          const o = j as Record<string, unknown>;
          manifest.valid = true;
          for (const [k, key] of [['name', 'name'], ['shortName', 'short_name'], ['startUrl', 'start_url'], ['display', 'display']] as const) {
            const v = str(o[key]);
            if (v !== undefined) manifest[k] = v;
          }
        }
      } catch {
        /* not JSON: stays invalid */
      }
    }

    const checkedAt = new Date(Date.parse(page.headers['date'] ?? '') || Date.now()).toISOString();
    const data: WellknownData = { checkedAt, securityTxt, robots, sitemap, manifest };
    const artifacts: Artifact[] = [{ type: 'wellknown', key: origin, data }];
    const notChecked: NotChecked[] = failed.length ? [{ module: 'collect.wellknown', reason: 'error', detail: failed.join('; ').slice(0, 200) }] : [];
    return { artifacts, notChecked };
  },
};
