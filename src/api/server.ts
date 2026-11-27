import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { pathToFileURL } from 'node:url';
import { scan } from '../core/scan.ts';
import { loadPlan } from '../core/plan.ts';
import type { Http } from '../core/types.ts';
import { normaliseTarget, BlockedTargetError } from '../fetch/ssrf.ts';
import { isLang } from '../i18n/index.ts';
import { present } from '../report/present.ts';
import { readFile } from 'node:fs/promises';
import { extname, normalize, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { clientKey, RateLimiter, TieredLimiter, TtlCache } from './ratelimit.ts';
import { ProofOfWork } from './pow.ts';
import { registrableDomain } from '../modules/collect/dns.ts';
import type { ScanResult } from '../core/types.ts';

type Tier = { limit: number; windowMs: number };

/** What the API needs from the (private) watch to handle unsubscribe links. */
export interface WatchHooks {
  verify(id: string, sig: string): boolean;
  stop(id: string): Promise<void>;
}

/** Paid part (private, injected): checkout, Paddle webhook, ownership confirmation for the deep check. */
export interface CommerceHooks {
  checkout(input: { url: string; product: string; lang: string; email?: string }): Promise<{ checkoutUrl: string }>;
  /** Returns the HTTP status for Paddle: 200 handled or duplicate, 400 bad signature/payload, 500 retry later. */
  webhook(rawBody: Buffer, signature: string | undefined): Promise<number>;
  /** GET shows a confirmation page, POST runs the ownership check. Returns status + HTML. */
  ownership(method: 'GET' | 'POST', jobId: string, sig: string): Promise<{ status: number; html: string }>;
}

export interface ApiOptions {
  /** Origins allowed to call the API from a browser. */
  origins?: string[];
  http?: Http;
  /** Per client (IPv4 address or IPv6 /64). Default: 3/min, 10/h, 30/day. */
  perIp?: Tier | Tier[];
  /** Per registrable domain of the target. Default: 20/h. Cached results do not count. */
  perTarget?: Tier | Tier[];
  /** All scans together, protects the server budget. Default: 300/h. */
  global?: Tier;
  /** Scans running at the same time. Default: 4. */
  maxConcurrent?: number;
  cacheMs?: number;
  /** Proof of work before each scan. Default on, difficulty 16; false only for tests and trusted clients. */
  pow?: false | { secret?: string; difficulty?: number };
  /** Domains whose operators asked not to be scanned (registrable domains). */
  blockedDomains?: string[];
  /** Watch subscriptions (private part, injected): enables /v1/watch/unsubscribe. */
  watch?: WatchHooks;
  commerce?: CommerceHooks;
  /** Public Paddle settings for the payment page (client-side token is meant to be public). */
  payConfig?: { clientToken: string; environment: 'sandbox' | 'production' };
  /** Directory with the static Ampel page; default web/ next to src/. null: no page. */
  webDir?: string | null;
  /** Trust X-Forwarded-For (only behind your own reverse proxy). */
  trustProxy?: boolean;
}

/**
 * Small HTTP API plus the static Ampel page (scan.m-ko.de). Only the free plan runs
 * here; paid plans run in the worker after payment.
 *
 *   GET  /v1/challenge                                          → proof-of-work puzzle
 *   POST /v1/scan   { "url": "...", "lang": "de", "pow": {…} }  → presented Ampel result
 *   GET  /health
 *   GET  /, /assets/*, /fonts/*                                 → page from web/
 *
 * Abuse protection: proof of work per scan, limits per client (IPv6 by /64), per target
 * domain and globally, a cap on concurrent scans, a short result cache, and an opt-out
 * list for operators who do not want their domain scanned.
 */
export function createApi(opts: ApiOptions = {}) {
  const origins = opts.origins ?? ['https://m-ko.de', 'https://scan.m-ko.de'];
  const tiers = (t: Tier | Tier[] | undefined, d: Tier[]) => (t === undefined ? d : Array.isArray(t) ? t : [t]);
  const perIp = new TieredLimiter(tiers(opts.perIp, [
    { limit: 3, windowMs: 60_000 },
    { limit: 10, windowMs: 60 * 60_000 },
    { limit: 30, windowMs: 24 * 60 * 60_000 },
  ]));
  const perTarget = new TieredLimiter(tiers(opts.perTarget, [{ limit: 20, windowMs: 60 * 60_000 }]));
  const global = new RateLimiter(opts.global?.limit ?? 300, opts.global?.windowMs ?? 60 * 60_000);
  const maxConcurrent = opts.maxConcurrent ?? 4;
  let running = 0;
  const cache = new TtlCache<ScanResult>(opts.cacheMs ?? 10 * 60_000);
  const pow = opts.pow === false ? null : new ProofOfWork(opts.pow ?? {});
  const blocked = new Set((opts.blockedDomains ?? []).map((d) => d.toLowerCase()));
  const webDir = opts.webDir === undefined ? fileURLToPath(new URL('../../web/', import.meta.url)) : opts.webDir;
  const plan = loadPlan('ampel');

  return createServer(async (req, res) => {
    const origin = req.headers.origin;
    if (origin && origins.includes(origin)) {
      res.setHeader('access-control-allow-origin', origin);
      res.setHeader('vary', 'origin');
      res.setHeader('access-control-allow-methods', 'POST, OPTIONS');
      res.setHeader('access-control-allow-headers', 'content-type');
    }
    res.setHeader('x-content-type-options', 'nosniff');
    res.setHeader('cache-control', 'no-store');
    try {
      if (req.method === 'OPTIONS') return send(res, 204);
      if (req.method === 'GET' && req.url === '/health') return send(res, 200, { ok: true });
      if (req.method === 'GET' && req.url === '/v1/challenge') {
        return pow ? send(res, 200, pow.issue()) : send(res, 404, { error: 'pow_disabled' });
      }
      if ((req.url ?? '').startsWith('/v1/watch/unsubscribe')) return unsubscribe(req, res, opts.watch);
      if (req.method === 'GET' && req.url === '/v1/pay/config') {
        return opts.payConfig ? send(res, 200, opts.payConfig) : send(res, 404, { error: 'payment_disabled' });
      }
      if (opts.commerce && req.method === 'POST' && req.url === '/v1/paddle/webhook') {
        const raw = await readRaw(req, 1024 * 1024);
        const status = await opts.commerce.webhook(raw, req.headers['paddle-signature'] as string | undefined);
        return send(res, status, { ok: status < 300 });
      }
      if (opts.commerce && (req.url ?? '').startsWith('/v1/ownership/check')) {
        if (req.method !== 'GET' && req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
        const u = new URL(req.url ?? '/', 'http://x');
        if (req.method === 'POST') for await (const _ of req) { /* drain */ }
        const out = await opts.commerce.ownership(req.method, u.searchParams.get('job') ?? '', u.searchParams.get('sig') ?? '');
        res.writeHead(out.status, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", 'referrer-policy': 'no-referrer', 'cache-control': 'no-store' });
        return void res.end(out.html);
      }
      if (opts.commerce && req.method === 'POST' && req.url === '/v1/checkout') {
        const body = await readJson(req, 4096);
        if (typeof body.url !== 'string' || body.url.length > 2048) return send(res, 400, { error: 'invalid_url' });
        if (typeof body.product !== 'string' || !/^(report|deep|watchdog|watchdog-y)$/.test(body.product)) return send(res, 400, { error: 'invalid_product' });
        let target: URL;
        try {
          target = normaliseTarget(body.url);
        } catch {
          return send(res, 400, { error: 'blocked_target' });
        }
        const domain = registrableDomain(target.hostname);
        if (blocked.has(domain) || blocked.has(target.hostname)) return send(res, 403, { error: 'target_opted_out' });
        if (pow) {
          const err = pow.verify(body.pow);
          if (err) return send(res, 400, { error: err });
        }
        const wait = perIp.check(clientKey(clientIp(req, opts.trustProxy ?? false)));
        if (wait) return send(res, 429, { error: 'rate_limited', scope: 'ip', retryAfter: wait }, { 'retry-after': String(wait) });
        const email = typeof body.email === 'string' && body.email.length < 255 ? body.email : undefined;
        const { checkoutUrl } = await opts.commerce.checkout({
          url: target.toString(),
          product: body.product,
          lang: isLang(body.lang) ? body.lang : 'de',
          ...(email ? { email } : {}),
        });
        return send(res, 200, { checkoutUrl });
      }
      if ((req.method === 'GET' || req.method === 'HEAD') && webDir) return serveStatic(res, webDir, req.url ?? '/', req.method === 'HEAD');
      if (req.method !== 'POST' || req.url !== '/v1/scan') return send(res, 404, { error: 'not_found' });

      const body = await readJson(req, 4096);
      const lang = isLang(body.lang) ? body.lang : 'de';
      if (typeof body.url !== 'string' || body.url.length > 2048) return send(res, 400, { error: 'invalid_url' });
      let target: URL;
      try {
        target = normaliseTarget(body.url);
      } catch (e) {
        return send(res, 400, { error: 'blocked_target', detail: e instanceof Error ? e.message : '' });
      }

      const domain = registrableDomain(target.hostname);
      if (blocked.has(domain) || blocked.has(target.hostname)) return send(res, 403, { error: 'target_opted_out' });

      if (pow) {
        const err = pow.verify(body.pow);
        if (err) return send(res, 400, { error: err });
      }

      const key = target.toString();
      let result = cache.get(key);
      const cached = Boolean(result);
      if (!result) {
        // Busy first, so that a refused request costs the client none of its quota.
        if (running >= maxConcurrent) return send(res, 503, { error: 'busy', retryAfter: 10 }, { 'retry-after': '10' });
        const limited = (scope: string, wait: number) =>
          send(res, 429, { error: 'rate_limited', scope, retryAfter: wait }, { 'retry-after': String(wait) });
        const waitIp = perIp.check(clientKey(clientIp(req, opts.trustProxy ?? false)));
        if (waitIp) return limited('ip', waitIp);
        const waitTarget = perTarget.check(domain);
        if (waitTarget) return limited('target', waitTarget);
        const waitGlobal = global.take('all');
        if (waitGlobal) return limited('global', waitGlobal);
        running++;
        try {
          result = (await scan({ url: key, plan, ...(opts.http ? { http: opts.http } : {}) })).result;
        } finally {
          running--;
        }
        cache.set(key, result);
      }
      return send(res, 200, { ...present(result, plan, lang), cached });
    } catch (e) {
      if (e instanceof BlockedTargetError) return send(res, 400, { error: 'blocked_target' });
      if (e instanceof BadRequest) return send(res, 400, { error: e.message });
      console.error(e);
      return send(res, 500, { error: 'internal' });
    }
  });
}

class BadRequest extends Error {}

const PAGE = (body: string) =>
  `<!doctype html><html lang="de"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>EDEL.TRAUD.AI</title></head><body style="font-family:system-ui,sans-serif;max-width:36rem;margin:3rem auto;padding:0 1rem;color:#12332E">${body}</body></html>`;

/**
 * GET shows a confirmation page (mail scanners open links on their own), POST stops the watch.
 * POST without a form also works: one-click unsubscribe per RFC 8058.
 */
async function unsubscribe(req: IncomingMessage, res: ServerResponse, watch: ApiOptions['watch']): Promise<void> {
  if (!watch) return send(res, 404, { error: 'not_found' });
  const u = new URL(req.url ?? '/', 'http://x');
  const id = u.searchParams.get('id') ?? '';
  const sig = u.searchParams.get('sig') ?? '';
  if (!/^[0-9a-f]{24}$/.test(id) || !watch.verify(id, sig)) return send(res, 400, { error: 'invalid_link' });
  const html = (status: number, body: string) => {
    res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'content-security-policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'", 'referrer-policy': 'no-referrer' });
    res.end(PAGE(body));
  };
  if (req.method === 'GET') {
    return html(200, `<h1>WatchDog abbestellen?</h1><p>Für diese Adresse kommen dann keine Mails vom WatchDog mehr.</p>
<form method="post" action="/v1/watch/unsubscribe?id=${id}&amp;sig=${encodeURIComponent(sig)}"><button type="submit">Abbestellen / Unsubscribe</button></form>`);
  }
  if (req.method !== 'POST') return send(res, 405, { error: 'method_not_allowed' });
  for await (const _ of req) { /* drain body */ }
  await watch.stop(id);
  return html(200, '<h1>Abbestellt</h1><p>Der WatchDog für diese Adresse ist beendet. / WatchDog has been stopped.</p>');
}

const TYPES: Record<string, string> = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};

/** Strict policy for the page: only own files, no inline code, no third parties. */
const PAGE_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self'",
  "img-src 'self' data:",
  "font-src 'self'",
  "connect-src 'self'",
  "worker-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'self'",
  "object-src 'none'",
].join('; ');

/** Only the payment page may load Paddle.js and show its checkout frame. */
const PAY_CSP = PAGE_CSP.replace("script-src 'self'", "script-src 'self' https://cdn.paddle.com")
  .replace("style-src 'self'", "style-src 'self' 'unsafe-inline' https://cdn.paddle.com")
  .replace("img-src 'self' data:", "img-src 'self' data: https://*.paddle.com")
  .replace("connect-src 'self'", "connect-src 'self' https://*.paddle.com")
  .replace("frame-ancestors 'none'", "frame-src https://*.paddle.com; frame-ancestors 'none'");

async function serveStatic(res: ServerResponse, dir: string, url: string, headOnly = false): Promise<void> {
  const path = decodeURIComponent(url.split(/[?#]/)[0]!);
  const rel = path === '/' ? 'index.html' : path === '/pay' ? 'pay.html' : path.replace(/^\/+/, '');
  const file = normalize(dir + sep + rel);
  const type = TYPES[extname(file)];
  if (!file.startsWith(normalize(dir + sep)) || rel.includes('\0') || !type || /(^|\/)\./.test(rel)) {
    return send(res, 404, { error: 'not_found' });
  }
  let data: Buffer;
  try {
    data = await readFile(file);
  } catch {
    return send(res, 404, { error: 'not_found' });
  }
  res.writeHead(200, {
    'content-type': type,
    'content-security-policy': rel === 'pay.html' ? PAY_CSP : PAGE_CSP,
    'referrer-policy': 'no-referrer',
    'permissions-policy': 'camera=(), microphone=(), geolocation=(), interest-cohort=()',
    'strict-transport-security': 'max-age=63072000; includeSubDomains',
    'cross-origin-opener-policy': 'same-origin',
    'x-frame-options': 'DENY',
    'cache-control': type.startsWith('text/html') ? 'no-cache' : 'public, max-age=3600',
    'content-length': String(data.length),
  });
  res.end(headOnly ? undefined : data);
}

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { ...(body === undefined ? {} : { 'content-type': 'application/json; charset=utf-8' }), ...headers });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

/**
 * Behind our own reverse proxy the client address is the LAST X-Forwarded-For entry: the one
 * the proxy appended. Earlier entries come from the client and can be forged to dodge limits.
 */
function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  const fwd = trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',').map((s) => s.trim()).filter(Boolean).pop() ?? '' : '';
  return fwd || req.socket.remoteAddress || 'unknown';
}

async function readRaw(req: IncomingMessage, max: number): Promise<Buffer> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > max) throw new BadRequest('too_large');
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks);
}

async function readJson(req: IncomingMessage, max: number): Promise<Record<string, unknown>> {
  if (!String(req.headers['content-type'] ?? '').includes('application/json')) throw new BadRequest('expected_json');
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > max) throw new BadRequest('too_large');
    chunks.push(c as Buffer);
  }
  try {
    const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw new BadRequest('invalid_json');
  }
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? '').href) {
  const port = Number(process.env.PORT ?? 8787);
  const origins = process.env.ALLOWED_ORIGINS?.split(',').map((s) => s.trim()).filter(Boolean);
  const blockedDomains = process.env.BLOCKED_DOMAINS?.split(',').map((s) => s.trim()).filter(Boolean);
  // The watch is private; without it (open core) the unsubscribe route simply does not exist.
  let watch: WatchHooks | undefined;
  // Unsubscribing deletes the subscription and its last result right away.
  // Optional parts never stop the free Ampel: a gap in their configuration only switches them off.
  if (process.env.WATCH_SECRET && process.env.WATCH_DIR) {
    try {
      const mod: string = '../watch/store.ts';
      const { WatchStore, checkUnsubscribeSig } = await import(mod);
      const store = new WatchStore(process.env.WATCH_DIR);
      const secret = process.env.WATCH_SECRET;
      watch = { verify: (id, sig) => checkUnsubscribeSig(secret, id, sig), stop: async (id) => void (await store.remove(id)) };
    } catch (e) {
      console.warn(`WatchDog unsubscribe disabled: ${e instanceof Error ? e.message : e}`);
    }
  }
  // Payment is private too; it is switched on by PADDLE_API_KEY.
  let commerce: CommerceHooks | undefined;
  if (process.env.PADDLE_API_KEY) {
    try {
      const mod: string = '../pay/api.ts';
      const { commerceFromEnv } = await import(mod);
      commerce = await commerceFromEnv(process.env);
      console.log(`payment enabled (${process.env.PADDLE_ENV === 'production' ? 'production' : 'sandbox'})`);
    } catch (e) {
      console.warn(`payment disabled: ${e instanceof Error ? e.message : e} (see deploy/README.md, section 6)`);
    }
  }
  createApi({
    ...(origins ? { origins } : {}),
    ...(watch ? { watch } : {}),
    ...(commerce ? { commerce } : {}),
    ...(process.env.PADDLE_CLIENT_TOKEN
      ? { payConfig: { clientToken: process.env.PADDLE_CLIENT_TOKEN, environment: process.env.PADDLE_ENV === 'production' ? 'production' as const : 'sandbox' as const } }
      : {}),
    ...(blockedDomains ? { blockedDomains } : {}),
    // A fixed secret keeps challenges valid across restarts; without it each process makes its own.
    pow: { ...(process.env.POW_SECRET ? { secret: process.env.POW_SECRET } : {}), difficulty: Number(process.env.POW_DIFFICULTY ?? 16) },
    trustProxy: process.env.TRUST_PROXY === '1',
  }).listen(port, () =>
    console.log(`edeltraud api on :${port}`),
  );
}
