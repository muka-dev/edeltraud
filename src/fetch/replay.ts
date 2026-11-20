import type { Http, HttpRequest, HttpResponse } from '../core/types.ts';

export interface FixtureResponse {
  status?: number;
  headers?: Record<string, string>;
  setCookies?: string[];
  body?: string;
  /** Redirect target; status defaults to 301. */
  redirect?: string;
}

/**
 * Serves requests from a map of URL → response. Unknown URLs get a 404.
 * Used by tests and to replay recorded scans deterministically.
 */
export class ReplayHttp implements Http {
  readonly log: string[] = [];
  private site: Record<string, FixtureResponse>;
  constructor(site: Record<string, FixtureResponse>) {
    this.site = site;
  }

  async fetch(req: HttpRequest): Promise<HttpResponse> {
    const redirects: string[] = [];
    let url = req.url;
    for (let hop = 0; hop <= 5; hop++) {
      this.log.push(`${req.method ?? 'GET'} ${url}`);
      const f = this.site[url];
      if (f?.redirect && req.followRedirects !== false) {
        redirects.push(url);
        url = new URL(f.redirect, url).toString();
        continue;
      }
      const headers = Object.fromEntries(Object.entries(f?.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]));
      if (f?.redirect) headers['location'] = f.redirect;
      const body = req.method === 'HEAD' ? '' : (f?.body ?? (f ? '' : 'Not found'));
      const max = req.maxBytes ?? Infinity;
      return {
        url: req.url,
        finalUrl: url,
        status: f ? (f.status ?? (f.redirect ? 301 : 200)) : 404,
        headers,
        setCookies: f?.setCookies ?? [],
        body: body.length > max ? body.slice(0, max) : body,
        truncated: body.length > max,
        redirects,
      };
    }
    throw new Error('too many redirects');
  }
}
