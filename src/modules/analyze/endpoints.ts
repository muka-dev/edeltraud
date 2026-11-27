import { finding } from '../../core/finding.ts';
import type { CheckModule, ModuleContext, RenderData } from '../../core/types.ts';
import { sameSite, type BundleData, type PageData } from '../util.ts';
import { findSupabaseClient } from '../probe/supabase-key.ts';

/** One discovered same-site API endpoint. Paths are normalised: no query, ids replaced with ':id'. */
export interface EndpointEntry {
  path: string;
  method?: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'HEAD' | 'OPTIONS';
  source: 'bundle' | 'render';
  /** Name of a Supabase Edge Function ('/functions/v1/<name>'). */
  edgeFunction?: string;
  /** Origin if it is not the scanned site's own (Edge Functions on *.supabase.co). */
  origin?: string;
}

export interface EndpointsData {
  list: EndpointEntry[];
}

export const MAX_ENDPOINTS = 200;

const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);
const STATIC_FILE = /\.(?:m?js|css|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|pdf|html?|txt|xml)$/i;
const PATH_CHARS = /^\/[\w\-./:~@%+=,!$&'()*;[\]]*$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Hosts whose Edge Functions are part of the app's backend. */
export function isSupabaseHost(host: string): boolean {
  return /(^|\.)supabase\.(co|in)$/i.test(host);
}

/** Origins the scanner may talk to for API discovery and probing: the site itself or its Supabase project. */
export function allowedOrigin(origin: string, targetHost: string): boolean {
  try {
    const u = new URL(origin);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    return sameSite(u.hostname, targetHost) || isSupabaseHost(u.hostname);
  } catch {
    return false;
  }
}

function normaliseSegment(seg: string): string {
  if (!seg) return seg;
  if (seg.startsWith(':') || /^\[.*\]$/.test(seg) || /^\{.*\}$/.test(seg)) return ':id';
  if (/^\d+$/.test(seg) || UUID.test(seg) || /^[0-9a-f]{24,}$/i.test(seg)) return ':id';
  if (/^[A-Za-z0-9_-]{20,}$/.test(seg) && /\d/.test(seg) && /[A-Za-z]/.test(seg)) return ':id';
  return seg;
}

/**
 * Turns a string literal / template content into a normalised path, or null.
 * Template placeholders become ':id' (or are dropped at the start: `${base}/api/x`).
 */
export function normalisePath(raw: string): string | null {
  let s = raw.trim().replace(/^(?:\$\{[^}]*\})+/, '');
  s = s.replace(/\$\{[^}]*\}/g, ':id');
  s = s.replace(/[?#].*$/, '');
  if (!s.startsWith('/') || s.startsWith('//')) return null;
  const prefixOnly = s.length > 1 && s.endsWith('/') && s.split('/').filter(Boolean).length >= 2;
  const segs = s.split('/').filter((x, i, a) => x !== '' || i === 0 || i === a.length - 1).map(normaliseSegment);
  let path = segs.join('/').replace(/\/+$/, '');
  if (prefixOnly) path += '/:id';
  if (!path || path === '/' || path === '/api' || path.length > 200) return null;
  if (!PATH_CHARS.test(path) || STATIC_FILE.test(path)) return null;
  return path;
}

function edgeName(path: string): string | undefined {
  return path.match(/^\/functions\/v1\/([A-Za-z0-9_-]+)(?:\/|$)/)?.[1];
}

class Collector {
  readonly list: EndpointEntry[] = [];
  private seen = new Set<string>();
  private targetHost: string;
  private supabaseOrigin: string | undefined;
  constructor(targetHost: string, supabaseOrigin: string | undefined) {
    this.targetHost = targetHost;
    this.supabaseOrigin = supabaseOrigin;
  }

  add(e: EndpointEntry): void {
    if (this.list.length >= MAX_ENDPOINTS) return;
    const key = `${e.origin ?? ''}|${e.method ?? ''}|${e.path}`;
    if (this.seen.has(key)) return;
    this.seen.add(key);
    this.list.push(e);
  }

  /** A path from code. `origin` set for absolute URLs. */
  addPath(raw: string, source: EndpointEntry['source'], method?: string, origin?: string): void {
    const path = normalisePath(raw);
    if (!path) return;
    const name = edgeName(path);
    const e: EndpointEntry = { path, source };
    const mu = method?.toUpperCase();
    if (mu && METHODS.has(mu)) e.method = mu as EndpointEntry['method'];
    if (name) {
      e.edgeFunction = name;
      const o = origin ?? this.supabaseOrigin;
      if (o) e.origin = o;
    } else if (origin) {
      try {
        if (new URL(origin).host !== this.targetHost) e.origin = origin;
      } catch {
        return;
      }
    }
    this.add(e);
  }

  addEdge(name: string, method: string | undefined, origin?: string): void {
    const e: EndpointEntry = { path: `/functions/v1/${name}`, source: 'bundle', edgeFunction: name };
    const mu = method?.toUpperCase();
    if (mu && METHODS.has(mu)) e.method = mu as EndpointEntry['method'];
    const o = origin ?? this.supabaseOrigin;
    if (o) e.origin = o;
    this.add(e);
  }

  /** Absolute URL or relative path from a fetch/axios call. */
  addTarget(raw: string, source: EndpointEntry['source'], method?: string): void {
    if (/^https?:\/\//i.test(raw)) {
      let u: URL;
      try {
        u = new URL(raw.replace(/\$\{[^}]*\}/g, 'x'));
      } catch {
        return;
      }
      if (!allowedOrigin(u.origin, this.targetHost)) return;
      // Keep the placeholder structure of the path, not the substituted one.
      const pathRaw = raw.replace(/^https?:\/\/[^/]+/i, '');
      this.addPath(pathRaw, source, method, u.origin);
    } else {
      this.addPath(raw, source, method);
    }
  }
}

const CALL = /(?<![\w$.])(?:(fetch|\$fetch|ky)|(?:axios|http|api|client|request)(?:\.(get|post|put|patch|delete|head))?)\(\s*(["'`])((?:(?!\3).){1,300})\3/g;
const API_LITERAL = /(["'`])((?:\$\{[^}]*\})*\/api\/(?:(?!\1)[^\s]){1,200})\1/g;
const EDGE_URL = /(https?:\/\/[A-Za-z0-9.-]+)?\/functions\/v1\/([A-Za-z0-9_-]+)/g;
const EDGE_INVOKE = /functions\s*\.\s*invoke\(\s*(["'`])([A-Za-z0-9_-]{1,64})\1(?:\s*,\s*\{([^{}]{0,200}))?/g;

function scanBundle(code: string, c: Collector): void {
  for (const m of code.matchAll(CALL)) {
    let method = m[2]?.toUpperCase();
    const target = m[4]!;
    if (!method && m[1]) {
      // fetch("/x", { method: "POST" }): look a short way ahead for the method option.
      const after = code.slice(m.index! + m[0].length, m.index! + m[0].length + 160);
      method = after.match(/^\s*,\s*\{[^}]*?\bmethod\s*:\s*["'`](\w+)["'`]/)?.[1]?.toUpperCase() ?? 'GET';
    }
    c.addTarget(target, 'bundle', method);
  }
  for (const m of code.matchAll(API_LITERAL)) c.addPath(m[2]!, 'bundle');
  for (const m of code.matchAll(EDGE_URL)) {
    let origin: string | undefined;
    if (m[1]) {
      try {
        origin = new URL(m[1]).origin;
      } catch {
        /* ignore */
      }
    }
    c.addEdge(m[2]!, undefined, origin);
  }
  for (const m of code.matchAll(EDGE_INVOKE)) {
    c.addEdge(m[2]!, m[3]?.match(/\bmethod\s*:\s*["'`](\w+)["'`]/)?.[1] ?? 'POST');
  }
}

function discover(ctx: ModuleContext): EndpointEntry[] {
  const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
  const html = (ctx.artifacts.list('page')[0]?.data as PageData | undefined)?.html ?? '';
  const sb = findSupabaseClient(bundles, html);
  const c = new Collector(ctx.target.host, sb?.url);
  for (const b of bundles) scanBundle(b.code, c);

  for (const a of ctx.artifacts.list('render')) {
    const r = a.data as RenderData;
    for (const req of r.requests ?? []) {
      if (req.resourceType !== 'xhr' && req.resourceType !== 'fetch') continue;
      let u: URL;
      try {
        u = new URL(req.url);
      } catch {
        continue;
      }
      if (!allowedOrigin(u.origin, ctx.target.host)) continue;
      const path = normalisePath(u.pathname);
      if (!path) continue;
      const e: EndpointEntry = { path, source: 'render' };
      const method = req.method?.toUpperCase();
      if (method && METHODS.has(method)) e.method = method as EndpointEntry['method'];
      const name = edgeName(path);
      if (name) e.edgeFunction = name;
      if (u.host !== ctx.target.host) e.origin = u.origin;
      c.add(e);
    }
  }
  // A method-less hit (plain "/api/x" literal) is redundant once the same path is known with a method.
  const withMethod = new Set(c.list.filter((e) => e.method).map((e) => `${e.origin ?? ''}|${e.path}`));
  return c.list.filter((e) => e.method || !withMethod.has(`${e.origin ?? ''}|${e.path}`));
}

/** Collects same-site API endpoints from bundles and the rendered page. Names only, nothing is requested. */
export const endpointsDiscovered: CheckModule = {
  manifest: {
    id: 'endpoints.discovered',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:js-bundle', 'artifact:render', 'artifact:page'],
    provides: ['artifact:endpoints', 'fact:endpoints.count'],
    params: {},
    budget: {},
  },
  run(ctx) {
    const list = discover(ctx);
    return {
      artifacts: [{ type: 'endpoints', key: ctx.target.url, data: { list } satisfies EndpointsData }],
      facts: { 'endpoints.count': list.length },
    };
  },
};

// ---------------------------------------------------------------------------------------------
// auth.client-only

const ADMIN_ROUTE = /(["'`])(\/(?:[\w-]+\/)*admin[\w-]*(?:\/[\w\-/:.]*)?)\1/g;
const ROLE_CHECK = new RegExp(
  [
    String.raw`\brole\s*[!=]==?\s*["'\`](?:admin|superadmin|super_admin)["'\`]`,
    String.raw`["'\`](?:admin|superadmin|super_admin)["'\`]\s*[!=]==?\s*[\w$.?]*\brole\b`,
    String.raw`\bis_?[Aa]dmin\b`,
    String.raw`user_metadata\??\.(?:role|is_?admin)`,
    String.raw`app_metadata\??\.(?:role|roles|is_?admin|admin)`,
  ].join('|'),
);
const SERVER_ADMIN = /\/api\/admin\b|\/functions\/v1\/[\w-]*admin/i;

/** Hint: access control for admin areas seems to exist only as a browser-side check. */
export const authClientOnly: CheckModule = {
  manifest: {
    id: 'auth.client-only',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:js-bundle', 'artifact:endpoints'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = authClientOnly.manifest;
    const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
    const eps = (ctx.artifacts.list('endpoints')[0]?.data as EndpointsData | undefined)?.list ?? [];
    const serverSide =
      eps.some((e) => /^\/api\/admin(?:\/|$)/.test(e.path) || (e.edgeFunction !== undefined && /admin/i.test(e.edgeFunction))) ||
      bundles.some((b) => SERVER_ADMIN.test(b.code));
    if (serverSide) return {};

    const routes = new Set<string>();
    let firstUrl: string | undefined;
    for (const b of bundles) {
      const found = new Set<string>();
      for (const r of b.code.matchAll(ADMIN_ROUTE)) {
        const p = r[2]!;
        if (!p.startsWith('/api/') && !p.startsWith('/functions/')) found.add(p);
      }
      if (!found.size || !ROLE_CHECK.test(b.code)) continue;
      firstUrl ??= b.url;
      for (const p of found) routes.add(p);
    }
    if (!routes.size || !firstUrl) return {};
    const sample = [...routes].sort().slice(0, 5).join(', ');
    return {
      findings: [
        finding(m, {
          kind: 'client-only',
          severity: 'medium',
          confidence: 'possible',
          location: { url: firstUrl },
          evidence: `Routen ${sample}`,
          messageKey: 'auth.client-only',
          vars: { routes: sample },
        }),
      ],
    };
  },
};

export const ENDPOINT_MODULES: CheckModule<any>[] = [endpointsDiscovered, authClientOnly];
