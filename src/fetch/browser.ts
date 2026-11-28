import { lookup as dnsLookup } from 'node:dns';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import type { AxeViolation, Browser, RenderAudit, RenderData, RenderRequest } from '../core/types.ts';
import { assertAllowedUrl, isBlockedIp } from './ssrf.ts';
import { USER_AGENT } from './http.ts';

const lookupAll = promisify(dnsLookup);

export interface LiveBrowserOptions {
  /** Path to a Chromium binary; default: the one bundled with Playwright (or EDELTRAUD_CHROMIUM). */
  executablePath?: string;
  /** Test hook: decides whether a URL may be loaded. Default: SSRF rules plus DNS check. */
  allowUrl?: (url: string) => Promise<boolean>;
}

/** Loads Playwright lazily, so the API image and CI do not need it. */
export function loadPlaywright(): { chromium: { launch(o: object): Promise<any> } } {
  const require = createRequire(import.meta.url);
  for (const name of [process.env.EDELTRAUD_PLAYWRIGHT, 'playwright-core', 'playwright'].filter(Boolean) as string[]) {
    try {
      return require(name);
    } catch {
      /* try next */
    }
  }
  throw Object.assign(new Error('Playwright is not installed'), { code: 'EDELTRAUD_NO_BROWSER' });
}

let axeSource: string | undefined;
/** axe-core ships with the repository (vendor/axe-core), never loaded from a CDN. */
function loadAxe(): string {
  return (axeSource ??= readFileSync(new URL('../../vendor/axe-core/axe.min.js', import.meta.url), 'utf8'));
}

/** Runs in the page before any of its scripts: LCP, CLS and long tasks (for TBT) of this load. */
function perfObserver() {
  const w = window as any;
  const m = (w.__edeltraudPerf = { lcp: null as number | null, cls: 0, tbt: 0 });
  const obs = (type: string, cb: (e: any) => void) => {
    try {
      new PerformanceObserver((l) => l.getEntries().forEach(cb)).observe({ type, buffered: true });
    } catch {
      /* type not supported */
    }
  };
  obs('largest-contentful-paint', (e) => (m.lcp = e.startTime));
  obs('layout-shift', (e) => {
    if (!e.hadRecentInput) m.cls += e.value;
  });
  obs('longtask', (e) => (m.tbt += Math.max(0, e.duration - 50)));
}

const SIZE_TYPES = new Set(['document', 'script', 'stylesheet', 'image', 'font']);

/** SSRF rule for every request the page makes: public http(s) only, checked after DNS resolution. */
export async function defaultAllowUrl(url: string): Promise<boolean> {
  if (url.startsWith('data:') || url.startsWith('blob:')) return true;
  try {
    const u = assertAllowedUrl(url);
    const host = u.hostname.replace(/^\[|\]$/g, '');
    const addrs = (await lookupAll(host, { all: true })) as { address: string }[];
    return addrs.length > 0 && !addrs.some((a) => isBlockedIp(a.address));
  } catch {
    return false;
  }
}

/**
 * Headless Chromium, one fresh browser per render. No clicks, no consent, no form input:
 * the result shows what a first visit loads on its own.
 * Remaining risk: Chromium resolves names itself after our check (DNS rebinding). The worker
 * container therefore runs in a network without access to internal services.
 */
export class LiveBrowser implements Browser {
  private opts: LiveBrowserOptions;
  constructor(opts: LiveBrowserOptions = {}) {
    this.opts = opts;
  }

  async render(url: string, o: { waitMs: number; maxRequests: number; timeoutMs: number; audit?: boolean }): Promise<RenderData> {
    const allow = this.opts.allowUrl ?? defaultAllowUrl;
    if (!(await allow(url))) throw new Error(`blocked target ${url}`);
    const { chromium } = loadPlaywright();
    const executablePath = this.opts.executablePath ?? process.env.EDELTRAUD_CHROMIUM;
    const browser = await chromium.launch({
      ...(executablePath ? { executablePath } : {}),
      args: ['--no-sandbox', '--disable-dev-shm-usage'],
    });
    try {
      const context = await browser.newContext({
        userAgent: `Mozilla/5.0 (X11; Linux x86_64) Chrome ${USER_AGENT}`,
        locale: 'de-DE',
        viewport: { width: 1280, height: 900 },
        serviceWorkers: 'block',
        acceptDownloads: false,
        ignoreHTTPSErrors: false,
      });
      const page = await context.newPage();
      const requests: RenderRequest[] = [];
      const byReq = new Map<unknown, RenderRequest>();
      const blocked: string[] = [];
      const consoleMsgs: RenderData['console'] = [];
      const pageErrors: string[] = [];
      let count = 0;
      let limitReached = false;

      await page.route('**/*', async (route: any) => {
        const u: string = route.request().url();
        if (count >= o.maxRequests) {
          limitReached = true;
          return route.abort('blockedbyclient');
        }
        if (!(await allow(u))) {
          blocked.push(u);
          return route.abort('blockedbyclient');
        }
        count++;
        return route.continue();
      });
      page.on('request', (r: any) => {
        const entry: RenderRequest = { url: r.url(), method: r.method(), resourceType: r.resourceType(), status: null, failure: null };
        byReq.set(r, entry);
        requests.push(entry);
      });
      page.on('response', (res: any) => {
        const e = byReq.get(res.request());
        if (e) e.status = res.status();
      });
      page.on('requestfailed', (r: any) => {
        const e = byReq.get(r);
        if (e) e.failure = r.failure()?.errorText ?? 'failed';
      });
      page.on('console', (m: any) => {
        if (consoleMsgs.length < 200) consoleMsgs.push({ type: m.type(), text: String(m.text()).slice(0, 500), url: m.location()?.url || null });
      });
      page.on('pageerror', (e: Error) => {
        if (pageErrors.length < 100) pageErrors.push(String(e.message).slice(0, 500));
      });

      const sizes: Promise<void>[] = [];
      const bytes: Record<string, number> = {};
      const images: { url: string; bytes: number }[] = [];
      if (o.audit) {
        await page.addInitScript(perfObserver);
        page.on('requestfinished', (r: any) =>
          sizes.push(
            r.sizes().then(
              (z: { responseBodySize: number; responseHeadersSize: number }) => {
                const type = SIZE_TYPES.has(r.resourceType()) ? r.resourceType() : 'other';
                const n = Math.max(0, z.responseBodySize) + Math.max(0, z.responseHeadersSize);
                bytes[type] = (bytes[type] ?? 0) + n;
                if (type === 'image') images.push({ url: String(r.url()).replace(/[?#].*$/, '').slice(0, 200), bytes: n });
              },
              () => {},
            ),
          ),
        );
      }

      const res = await page.goto(url, { waitUntil: 'load', timeout: o.timeoutMs });
      await page.waitForTimeout(o.waitMs);
      const html: string = await page.content();
      const links = (await page.$$eval('a[href]', (as: any[]) =>
        as.slice(0, 500).map((a) => ({ href: a.href as string, text: String(a.textContent ?? '').trim().slice(0, 100) })),
      )) as RenderData['links'];
      const storage = (await page.evaluate(() => {
        const keys = (s: Storage) => Array.from({ length: s.length }, (_, i) => s.key(i) ?? '');
        try {
          return { local: keys(localStorage), session: keys(sessionStorage) };
        } catch {
          return { local: [], session: [] };
        }
      })) as RenderData['storage'];
      const cookies = ((await context.cookies()) as any[]).map((c) => ({
        name: c.name, domain: c.domain, path: c.path, expires: c.expires, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite,
      }));
      let audit: RenderAudit | undefined;
      if (o.audit) {
        await Promise.all(sizes);
        const pm = (await page.evaluate(() => (window as any).__edeltraudPerf ?? null).catch(() => null)) as
          | { lcp: number | null; cls: number; tbt: number }
          | null;
        audit = {
          perf: {
            lcpMs: pm?.lcp != null ? Math.round(pm.lcp) : null,
            cls: pm ? Math.round(pm.cls * 1000) / 1000 : null,
            tbtMs: pm ? Math.round(pm.tbt) : null,
            bytes,
            largestImages: images.sort((a, b) => b.bytes - a.bytes).slice(0, 5),
          },
          axe: await runAxe(page),
        };
      }
      return {
        url,
        finalUrl: page.url(),
        status: res ? res.status() : null,
        html: html.length > 3_000_000 ? html.slice(0, 3_000_000) : html,
        title: await page.title(),
        requests,
        cookies,
        storage,
        console: consoleMsgs,
        pageErrors,
        links,
        blocked,
        limitReached,
        ...(audit ? { audit } : {}),
      };
    } finally {
      await browser.close().catch(() => {});
    }
  }
}

/**
 * axe-core in the rendered page (WCAG 2.0/2.1/2.2 A and AA rules). Evaluated through the
 * DevTools protocol, so the page's CSP does not block it. Only rule ids, impact, counts and
 * selectors leave the page, no element HTML or text.
 */
async function runAxe(page: any): Promise<NonNullable<RenderAudit['axe']>> {
  try {
    await page.evaluate(loadAxe());
    return (await page.evaluate(async () => {
      const axe = (window as any).axe;
      const r = await axe.run(document, {
        runOnly: { type: 'tag', values: ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'] },
        resultTypes: ['violations'],
      });
      return {
        version: String(axe.version),
        violations: r.violations.map((v: any) => ({
          id: v.id,
          impact: v.impact ?? null,
          nodes: v.nodes.length,
          targets: v.nodes.slice(0, 3).map((n: any) => String(n.target?.[0] ?? '').slice(0, 80)),
        })),
      };
    })) as { version: string; violations: AxeViolation[] };
  } catch (e) {
    return { error: (e instanceof Error ? e.message : String(e)).slice(0, 200) };
  }
}
