import { finding } from '../../core/finding.ts';
import type { CheckModule, HttpResponse, ModuleContext, NotChecked } from '../../core/types.ts';
import { allowedOrigin, type EndpointEntry, type EndpointsData } from '../analyze/endpoints.ts';

const MAX_BYTES = 64 * 1024;
// Anything that could change state or cost money, even behind a GET.
const DESTRUCTIVE = /logout|signout|delete|remove|reset|pay|checkout|webhook|send|invite|cron/i;
const PERSONAL_FIELD = /e-?mail|phone|mobile|address|passw|token|secret|iban/i;
const WRAPPER_KEYS = ['items', 'data', 'results', 'rows', 'records', 'users', 'list', 'profiles', 'accounts', 'orders', 'customers'];
const SCALAR_DATA_KEYS = ['id', 'email', 'user'];

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const isBudget = (e: unknown) => e instanceof Error && e.name === 'BudgetExceededError';

function endpointsOf(ctx: ModuleContext): EndpointEntry[] {
  return (ctx.artifacts.list('endpoints')[0]?.data as EndpointsData | undefined)?.list ?? [];
}

/** GET-able, fully resolved, non-destructive endpoints on origins the scanner may contact, deduplicated. */
function probeCandidates(ctx: ModuleContext, onlyGet: boolean): { url: string; path: string }[] {
  const seen = new Set<string>();
  const out: { url: string; path: string }[] = [];
  const self = new URL(ctx.target.url).origin;
  for (const e of endpointsOf(ctx)) {
    if (e.path.includes(':')) continue;
    if (DESTRUCTIVE.test(e.path)) continue;
    if (onlyGet && !e.edgeFunction && e.method && e.method !== 'GET') continue;
    const origin = e.origin ?? self;
    if (!allowedOrigin(origin, ctx.target.host)) continue;
    const url = origin + e.path;
    if (seen.has(url)) continue;
    seen.add(url);
    out.push({ url, path: e.path });
  }
  return out;
}

function parseJson(res: HttpResponse): unknown {
  try {
    return JSON.parse(res.body);
  } catch {
    return undefined;
  }
}

const isRecord = (v: unknown): v is Record<string, unknown> => !!v && typeof v === 'object' && !Array.isArray(v);

/** Looks at the shape of a JSON body. Returns counts and field names only, never values. */
export function dataShape(body: unknown): { count: number; fields: string[] } | null {
  if (Array.isArray(body)) {
    const first = body.find(isRecord);
    return first ? { count: body.length, fields: Object.keys(first) } : null;
  }
  if (!isRecord(body)) return null;
  for (const k of WRAPPER_KEYS) {
    const v = body[k];
    if (Array.isArray(v)) {
      const first = v.find(isRecord);
      if (first) return { count: v.length, fields: Object.keys(first) };
    } else if (isRecord(v) && SCALAR_DATA_KEYS.some((k) => v[k] !== undefined && v[k] !== null && typeof v[k] !== 'object')) {
      // A single wrapped record counts only if it looks like one (id, email …), not {"data":{"version":"1"}}.
      return { count: 1, fields: Object.keys(v) };
    }
  }
  const scalar = SCALAR_DATA_KEYS.some((k) => body[k] !== undefined && body[k] !== null && typeof body[k] !== 'object');
  const user = isRecord(body['user']) && Object.keys(body['user']).length > 0;
  return scalar || user ? { count: 1, fields: Object.keys(body) } : null;
}

// ---------------------------------------------------------------------------------------------
// api.unauth

export const apiUnauth: CheckModule<{ maxEndpoints: number }> = {
  manifest: {
    id: 'api.unauth',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:endpoints'],
    uses: [],
    provides: [],
    params: { maxEndpoints: { type: 'number', default: 20, min: 1, max: 25 } },
    budget: { requests: 25 },
  },
  async run(ctx, params) {
    const m = apiUnauth.manifest;
    const all = probeCandidates(ctx, true);
    const todo = all.slice(0, params.maxEndpoints);
    const notChecked: NotChecked[] = [];
    const findings = [];
    let checked = 0;
    let readable = 0;
    let protectedCount = 0;
    let i = 0;
    for (; i < todo.length; i++) {
      const { url, path } = todo[i]!;
      let res: HttpResponse;
      try {
        // No cookies, no Authorization header, no redirects: what an anonymous visitor gets.
        res = await ctx.http!.fetch({ url, headers: { Accept: 'application/json' }, maxBytes: MAX_BYTES, followRedirects: false });
      } catch (e) {
        if (isBudget(e)) {
          notChecked.push({ module: m.id, reason: 'budget', detail: `${todo.length - i} endpoints not checked` });
          break;
        }
        notChecked.push({ module: m.id, reason: 'error', detail: `${path}: ${errText(e).slice(0, 120)}` });
        continue;
      }
      checked++;
      if (res.status === 401 || res.status === 403) {
        protectedCount++;
        continue;
      }
      if (res.status !== 200) continue; // 404/405/redirects/errors: nothing to say
      const ct = (res.headers['content-type'] ?? '').toLowerCase();
      if (ct && !ct.includes('json')) continue; // SPA fallback (text/html) and the like
      if (res.truncated) continue;
      const shape = dataShape(parseJson(res));
      if (!shape) continue;
      readable++;
      const fields = shape.fields.slice(0, 8).join(', ');
      const personal = shape.fields.some((f) => PERSONAL_FIELD.test(f));
      findings.push(
        finding(m, {
          kind: 'unauth-data',
          severity: personal ? 'critical' : 'high',
          confidence: 'confirmed',
          location: { url },
          evidence: `${path}: ${shape.count} Einträge, Felder ${fields}`,
          messageKey: 'api.unauth-data',
          vars: { path, count: String(shape.count), fields },
          discriminator: path,
        }),
      );
    }
    if (all.length > todo.length) {
      notChecked.push({ module: m.id, reason: 'budget', detail: `${all.length - todo.length} endpoints beyond maxEndpoints not checked` });
    }
    return { findings, facts: { 'api.unauth': { checked, readable, protected: protectedCount } }, notChecked };
  },
};

// ---------------------------------------------------------------------------------------------
// cors.policy

const CORS_ORIGIN = 'https://edeltraud-cors-check.invalid';

export const corsPolicy: CheckModule<{ maxEndpoints: number }> = {
  manifest: {
    id: 'cors.policy',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: [],
    uses: ['artifact:endpoints', 'artifact:page'],
    provides: [],
    params: { maxEndpoints: { type: 'number', default: 5, min: 1, max: 5 } },
    budget: { requests: 6 },
  },
  async run(ctx, params) {
    const m = corsPolicy.manifest;
    let targets = probeCandidates(ctx, true).slice(0, params.maxEndpoints);
    if (!targets.length) targets = [{ url: ctx.target.url, path: new URL(ctx.target.url).pathname || '/' }];
    const notChecked: NotChecked[] = [];
    const findings = [];
    for (let i = 0; i < targets.length; i++) {
      const { url, path } = targets[i]!;
      let res: HttpResponse;
      try {
        res = await ctx.http!.fetch({ url, headers: { Origin: CORS_ORIGIN }, maxBytes: 1024, followRedirects: false });
      } catch (e) {
        if (isBudget(e)) {
          notChecked.push({ module: m.id, reason: 'budget', detail: `${targets.length - i} endpoints not checked` });
          break;
        }
        notChecked.push({ module: m.id, reason: 'error', detail: `${path}: ${errText(e).slice(0, 120)}` });
        continue;
      }
      const acao = (res.headers['access-control-allow-origin'] ?? '').trim();
      const credentials = (res.headers['access-control-allow-credentials'] ?? '').trim().toLowerCase() === 'true';
      const evidence = `${path}: Access-Control-Allow-Origin ${acao || '-'}, Allow-Credentials ${credentials}`;
      const base = { location: { url }, evidence, vars: { path }, discriminator: path, confidence: 'confirmed' as const };
      if (acao === CORS_ORIGIN && credentials) {
        findings.push(finding(m, { ...base, kind: 'reflect-credentials', severity: 'high', messageKey: 'cors.reflect-credentials' }));
      } else if (acao === '*' && credentials) {
        findings.push(finding(m, { ...base, kind: 'wildcard-credentials', severity: 'medium', messageKey: 'cors.wildcard-credentials' }));
      } else if (acao === CORS_ORIGIN) {
        findings.push(finding(m, { ...base, kind: 'reflect', severity: 'low', messageKey: 'cors.reflect' }));
      }
    }
    return { findings, notChecked };
  },
};

export const API_MODULES: CheckModule<any>[] = [apiUnauth, corsPolicy];
