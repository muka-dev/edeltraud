import { lookup as dnsLookup } from 'node:dns';
import { createRequire } from 'node:module';
import { promisify } from 'node:util';
import type { Browser, RenderData, RenderRequest } from '../core/types.ts';
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

  async render(url: string, o: { waitMs: number; maxRequests: number; timeoutMs: number }): Promise<RenderData> {
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
      };
    } finally {
      await browser.close().catch(() => {});
    }
  }
}
