import { lookup as dnsLookup } from 'node:dns';
import { promisify } from 'node:util';
import http from 'node:http';
import https from 'node:https';
import zlib from 'node:zlib';
import type { LookupFunction } from 'node:net';
import type { Http, HttpRequest, HttpResponse } from '../core/types.ts';
import { assertAllowedUrl, BlockedTargetError, isBlockedIp } from './ssrf.ts';

export const USER_AGENT = 'EDEL.TRAUD.AI/0.1 (+https://m-ko.de/scan; passive check)';
const lookupAll = promisify(dnsLookup);

/** DNS lookup that refuses private addresses, so the connected IP is always checked. */
export const safeLookup: LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err, '', 4);
    const list = addresses as unknown as { address: string; family: number }[];
    const bad = list.find((a) => isBlockedIp(a.address));
    if (bad) return callback(new BlockedTargetError(`${hostname} resolves to a blocked address`), '', 4);
    if ((options as { all?: boolean }).all) return (callback as any)(null, list);
    callback(null, list[0]!.address, list[0]!.family);
  });
};

export interface LiveHttpOptions {
  timeoutMs?: number;
  maxBytes?: number;
}

/** Real network access. Every module gets it only through a BudgetedHttp. */
export class LiveHttp implements Http {
  private opts: LiveHttpOptions;
  constructor(opts: LiveHttpOptions = {}) {
    this.opts = opts;
  }

  async fetch(req: HttpRequest): Promise<HttpResponse> {
    const redirects: string[] = [];
    let url = req.url;
    for (let hop = 0; hop <= 5; hop++) {
      const u = assertAllowedUrl(url);
      // Pre-check resolution as well: with an HTTP proxy the lookup hook is not used.
      const host = u.hostname.replace(/^\[|\]$/g, '');
      const addrs = await lookupAll(host, { all: true }).catch(() => []);
      if ((addrs as { address: string }[]).some((a) => isBlockedIp(a.address))) {
        throw new BlockedTargetError(`${host} resolves to a blocked address`);
      }
      const res = await this.once(u, req);
      const loc = res.headers['location'];
      if (req.followRedirects !== false && res.status >= 300 && res.status < 400 && loc) {
        redirects.push(url);
        url = new URL(loc, url).toString();
        continue;
      }
      return { ...res, url: req.url, finalUrl: url, redirects };
    }
    throw new Error('too many redirects');
  }

  private once(u: URL, req: HttpRequest): Promise<Omit<HttpResponse, 'url' | 'finalUrl' | 'redirects'>> {
    const maxBytes = req.maxBytes ?? this.opts.maxBytes ?? 5 * 1024 * 1024;
    const timeout = this.opts.timeoutMs ?? 10_000;
    const lib = u.protocol === 'https:' ? https : http;
    return new Promise((resolve, reject) => {
      const r = lib.request(
        u,
        {
          method: req.method ?? 'GET',
          headers: {
            'user-agent': USER_AGENT,
            'accept-encoding': 'gzip, br, deflate',
            ...(req.body !== undefined ? { 'content-length': String(Buffer.byteLength(req.body)) } : {}),
            ...req.headers,
          },
          lookup: safeLookup,
          timeout,
        },
        (res) => {
          const enc = String(res.headers['content-encoding'] ?? '');
          const stream =
            enc === 'gzip' ? res.pipe(zlib.createGunzip()) :
            enc === 'br' ? res.pipe(zlib.createBrotliDecompress()) :
            enc === 'deflate' ? res.pipe(zlib.createInflate()) : res;
          const chunks: Buffer[] = [];
          let size = 0;
          let truncated = false;
          stream.on('data', (c: Buffer) => {
            if (truncated) return;
            size += c.length;
            if (size > maxBytes) {
              truncated = true;
              chunks.push(c.subarray(0, c.length - (size - maxBytes)));
              res.destroy();
              finish();
            } else chunks.push(c);
          });
          let done = false;
          const finish = () => {
            if (done) return;
            done = true;
            const headers: Record<string, string> = {};
            for (const [k, v] of Object.entries(res.headers)) {
              if (k !== 'set-cookie' && v !== undefined) headers[k] = Array.isArray(v) ? v.join(', ') : v;
            }
            resolve({
              status: res.statusCode ?? 0,
              headers,
              setCookies: res.headers['set-cookie'] ?? [],
              body: Buffer.concat(chunks).toString('utf8'),
              truncated,
            });
          };
          stream.on('end', finish);
          stream.on('error', (e) => (truncated ? finish() : reject(e)));
        },
      );
      r.on('timeout', () => r.destroy(new Error('timeout')));
      r.on('error', reject);
      r.end(req.body);
    });
  }
}

export class BudgetExceededError extends Error {
  override name = 'BudgetExceededError';
}

/** Counts requests against the plan budget and records exchanges for replay. */
export class BudgetedHttp implements Http {
  count = 0;
  readonly recorded: { req: HttpRequest; res: HttpResponse }[] = [];

  private inner: Http;
  private limit: number;
  private record: boolean;
  constructor(inner: Http, limit: number, record = false) {
    this.inner = inner;
    this.limit = limit;
    this.record = record;
  }

  get remaining(): number {
    return Math.max(0, this.limit - this.count);
  }

  async fetch(req: HttpRequest): Promise<HttpResponse> {
    if (this.count >= this.limit) throw new BudgetExceededError('request budget exhausted');
    this.count++;
    const res = await this.inner.fetch(req);
    if (this.record) this.recorded.push({ req, res });
    return res;
  }
}
