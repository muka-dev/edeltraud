import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { pathToFileURL } from 'node:url';
import { scan } from '../core/scan.ts';
import { loadPlan } from '../core/plan.ts';
import type { Http } from '../core/types.ts';
import { normaliseTarget, BlockedTargetError } from '../fetch/ssrf.ts';
import { isLang } from '../i18n/index.ts';
import { present } from '../report/present.ts';
import { RateLimiter, TtlCache } from './ratelimit.ts';
import type { ScanResult } from '../core/types.ts';

export interface ApiOptions {
  /** Origins allowed to call the API from a browser. */
  origins?: string[];
  http?: Http;
  perIp?: { limit: number; windowMs: number };
  perTarget?: { limit: number; windowMs: number };
  cacheMs?: number;
  /** Trust X-Forwarded-For (only behind your own reverse proxy). */
  trustProxy?: boolean;
}

/**
 * Small HTTP API for the website. Only the free plan runs here; paid plans will run
 * in a worker queue after payment (wave 6).
 *
 *   POST /v1/scan   { "url": "...", "lang": "de" }  → presented Ampel result
 *   GET  /health
 */
export function createApi(opts: ApiOptions = {}) {
  const origins = opts.origins ?? ['https://m-ko.de', 'https://scan.m-ko.de'];
  const perIp = new RateLimiter(opts.perIp?.limit ?? 10, opts.perIp?.windowMs ?? 60 * 60_000);
  const perTarget = new RateLimiter(opts.perTarget?.limit ?? 30, opts.perTarget?.windowMs ?? 60 * 60_000);
  const cache = new TtlCache<ScanResult>(opts.cacheMs ?? 10 * 60_000);
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

      const ip = clientIp(req, opts.trustProxy ?? false);
      const key = target.toString();
      let result = cache.get(key);
      if (!result) {
        const waitIp = perIp.take(ip);
        if (waitIp) return send(res, 429, { error: 'rate_limited', retryAfter: waitIp }, { 'retry-after': String(waitIp) });
        const waitTarget = perTarget.take(target.hostname);
        if (waitTarget) return send(res, 429, { error: 'rate_limited', retryAfter: waitTarget }, { 'retry-after': String(waitTarget) });
        result = (await scan({ url: key, plan, ...(opts.http ? { http: opts.http } : {}) })).result;
        cache.set(key, result);
      }
      return send(res, 200, present(result, plan, lang));
    } catch (e) {
      if (e instanceof BlockedTargetError) return send(res, 400, { error: 'blocked_target' });
      if (e instanceof BadRequest) return send(res, 400, { error: e.message });
      console.error(e);
      return send(res, 500, { error: 'internal' });
    }
  });
}

class BadRequest extends Error {}

function send(res: ServerResponse, status: number, body?: unknown, headers: Record<string, string> = {}): void {
  res.writeHead(status, { ...(body === undefined ? {} : { 'content-type': 'application/json; charset=utf-8' }), ...headers });
  res.end(body === undefined ? undefined : JSON.stringify(body));
}

function clientIp(req: IncomingMessage, trustProxy: boolean): string {
  const fwd = trustProxy ? String(req.headers['x-forwarded-for'] ?? '').split(',')[0]!.trim() : '';
  return fwd || req.socket.remoteAddress || 'unknown';
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
  createApi({ ...(origins ? { origins } : {}), trustProxy: process.env.TRUST_PROXY === '1' }).listen(port, () =>
    console.log(`edeltraud api on :${port}`),
  );
}
