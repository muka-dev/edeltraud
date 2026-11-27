import { finding } from '../../core/finding.ts';
import type { Artifact, CheckModule, HttpResponse, ModuleContext, ModuleManifest, NotChecked } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';
import { findSupabaseClient, supabaseHeaders, type SupabaseClientInfo } from './supabase-key.ts';

/** Shape of the artifact 'supabase-openapi': names only, no schema details, no data. */
export interface SupabaseOpenApi {
  url: string;
  tables: string[];
  rpcs: string[];
}

function clientFrom(ctx: ModuleContext): SupabaseClientInfo | null {
  const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
  const html = (ctx.artifacts.list('page')[0]?.data as PageData | undefined)?.html ?? '';
  return findSupabaseClient(bundles, html);
}

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const isBudget = (e: unknown) => e instanceof Error && e.name === 'BudgetExceededError';

function parseJson(res: HttpResponse): unknown {
  try {
    return JSON.parse(res.body);
  } catch {
    return undefined;
  }
}

// ---------------------------------------------------------------------------------------------
// supabase.auth-settings: GET /auth/v1/settings with the public key, exactly like the app's login page.
// Kind 'probe' with mode 'passive': the processor hands http to every non-analyzer, and only
// 'active' modules need proof of ownership.

export const supabaseAuthSettings: CheckModule = {
  manifest: {
    id: 'supabase.auth-settings',
    version: '0.1.0',
    kind: 'probe',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: ['fact:supabase.authProviders'],
    when: ['fact:stack.supabase'],
    params: {},
    budget: { requests: 1 },
  },
  async run(ctx) {
    const m = supabaseAuthSettings.manifest;
    const client = clientFrom(ctx);
    if (!client) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no public Supabase key found in the code' }] };
    const url = `${client.url}/auth/v1/settings`;
    let res: HttpResponse;
    try {
      res = await ctx.http!.fetch({ url, headers: { ...supabaseHeaders(client), Accept: 'application/json' }, maxBytes: 100_000 });
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: isBudget(e) ? 'budget' : 'error', detail: errText(e) }] };
    }
    const body = res.status === 200 ? (parseJson(res) as Record<string, unknown> | undefined) : undefined;
    if (!body || typeof body !== 'object') {
      return { notChecked: [{ module: m.id, reason: 'unsupported', detail: `auth settings answered ${res.status}` }] };
    }

    const external = body.external && typeof body.external === 'object' ? (body.external as Record<string, unknown>) : {};
    const providers = Object.entries(external).filter(([, v]) => v === true).map(([k]) => k).sort();
    const signupOpen = body.disable_signup !== true;
    const findings = [];
    if (signupOpen && body.mailer_autoconfirm === true) {
      findings.push(
        finding(m, {
          kind: 'autoconfirm',
          severity: 'medium',
          confidence: 'confirmed',
          location: { url },
          evidence: 'disable_signup: false, mailer_autoconfirm: true',
          messageKey: 'supabase.autoconfirm',
        }),
      );
    }
    if (signupOpen && body.phone_autoconfirm === true) {
      findings.push(
        finding(m, {
          kind: 'phone-autoconfirm',
          severity: 'low',
          confidence: 'confirmed',
          location: { url },
          evidence: 'disable_signup: false, phone_autoconfirm: true',
          messageKey: 'supabase.phone-autoconfirm',
        }),
      );
    }
    return { findings, facts: { 'supabase.authProviders': providers } };
  },
};

// ---------------------------------------------------------------------------------------------
// supabase.rls-read

const PERSONAL_COLUMN = /e-?mail|phone|mobile|(^|_)tel($|_)|(first|last|full|user|display)_?name|(^|_)name$|address|street|passw|token|secret|iban|birth|(^|_)dob($|_)|(^|_)ip($|_)|ip_address|(^|_)ssn($|_)|card_?number/i;
const SENSITIVE_TABLE = /user|profile|account|customer|client|order|message|payment|subscription|admin|member|contact|lead|invoice|booking|patient/i;
const TABLE_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

/** PostgREST table/view and function names from an OpenAPI document. */
export function parseOpenApi(doc: unknown): { tables: string[]; rpcs: string[] } | null {
  const paths = doc && typeof doc === 'object' ? (doc as { paths?: unknown }).paths : undefined;
  if (!paths || typeof paths !== 'object') return null;
  const tables: string[] = [];
  const rpcs: string[] = [];
  for (const p of Object.keys(paths)) {
    if (p === '/') continue;
    if (p.startsWith('/rpc/')) {
      const fn = p.slice(5);
      if (TABLE_NAME.test(fn)) rpcs.push(fn);
    } else {
      const t = p.slice(1);
      if (TABLE_NAME.test(t)) tables.push(t);
    }
  }
  return { tables, rpcs };
}

/** Table names the app's own code queries: .from("name"), but not storage buckets. */
export function tablesFromBundles(bundles: readonly BundleData[]): string[] {
  const out = new Set<string>();
  for (const b of bundles) {
    for (const m of b.code.matchAll(/(?<!storage)\.from\(\s*["'`]([A-Za-z_][A-Za-z0-9_]*)["'`]\s*\)/g)) out.add(m[1]!);
  }
  return [...out];
}

function totalFromContentRange(headers: Record<string, string>): string | null {
  const m = (headers['content-range'] ?? '').match(/\/(\d+)$/);
  return m ? m[1]! : null;
}

export const supabaseRlsRead: CheckModule<{ maxTables: number }> = {
  manifest: {
    id: 'supabase.rls-read',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: ['artifact:supabase-openapi', 'fact:supabase.tables'],
    when: ['fact:stack.supabase'],
    params: { maxTables: { type: 'number', default: 25, min: 1, max: 100 } },
    budget: { requests: 30 },
  },
  async run(ctx, params) {
    const m = supabaseRlsRead.manifest;
    const client = clientFrom(ctx);
    if (!client) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no public Supabase key found in the code' }] };
    const http = ctx.http!;
    const headers = supabaseHeaders(client);
    const notChecked: NotChecked[] = [];
    const artifacts: Artifact[] = [];
    const findings = [];

    // a) schema: the OpenAPI document of PostgREST
    let tables: string[] = [];
    try {
      const res = await http.fetch({
        url: `${client.url}/rest/v1/`,
        headers: { ...headers, Accept: 'application/openapi+json' },
        maxBytes: 2_000_000,
      });
      const parsed = res.status === 200 ? parseOpenApi(parseJson(res)) : null;
      if (parsed) {
        tables = parsed.tables;
        artifacts.push({ type: 'supabase-openapi', key: client.url, data: { url: client.url, ...parsed } satisfies SupabaseOpenApi });
      } else {
        notChecked.push({ module: m.id, reason: 'unsupported', detail: 'schema not exposed' });
      }
    } catch (e) {
      if (isBudget(e)) return { notChecked: [{ module: m.id, reason: 'budget', detail: errText(e) }] };
      notChecked.push({ module: m.id, reason: 'unsupported', detail: 'schema not exposed' });
    }
    if (!artifacts.length) {
      tables = tablesFromBundles(ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData));
      if (!tables.length) {
        notChecked.push({ module: m.id, reason: 'unsupported', detail: 'no table names found in the code' });
        return { notChecked };
      }
    }

    // Tables that usually hold personal data first, so the cap covers the most valuable ones.
    tables = [...new Set(tables)].sort((a, b) => Number(SENSITIVE_TABLE.test(b)) - Number(SENSITIVE_TABLE.test(a)) || a.localeCompare(b));
    const cap = tables.slice(0, params.maxTables);
    let left = tables.length - cap.length;

    let checked = 0;
    let readable = 0;
    let protectedCount = 0;
    // b) one row at most per table, GET only, never paginated
    for (let i = 0; i < cap.length; i++) {
      const table = cap[i]!;
      const url = `${client.url}/rest/v1/${encodeURIComponent(table)}`;
      let res: HttpResponse;
      try {
        res = await http.fetch({
          url: `${url}?select=*&limit=1`,
          method: 'GET',
          headers: { ...headers, Accept: 'application/json', Range: '0-0', Prefer: 'count=exact' },
          maxBytes: 200_000,
        });
      } catch (e) {
        if (isBudget(e)) {
          left += cap.length - i;
          break;
        }
        notChecked.push({ module: m.id, reason: 'error', detail: `${table}: ${errText(e)}` });
        continue;
      }
      checked++;
      if (res.status === 401 || res.status === 403 || res.status === 404) {
        protectedCount++;
        continue;
      }
      if (res.status !== 200 && res.status !== 206) continue;
      const rows = parseJson(res);
      const first = Array.isArray(rows) ? rows[0] : undefined;
      // Only the key names survive; the row itself is dropped here.
      const columnNames = first && typeof first === 'object' ? Object.keys(first as object) : [];
      if (!columnNames.length) continue; // [] = RLS filter or empty table: indistinguishable
      readable++;
      const total = totalFromContentRange(res.headers) ?? '≥1';
      const columns = columnNames.slice(0, 8).join(', ');
      const personal = columnNames.some((c) => PERSONAL_COLUMN.test(c));
      findings.push(
        finding(m, {
          kind: 'table-readable',
          severity: personal ? 'critical' : 'high',
          confidence: 'confirmed',
          location: { url },
          evidence: `${table}: ${total} Zeilen, Spalten ${columns}`,
          messageKey: 'supabase.table-readable',
          vars: { table, columns, rows: total },
          discriminator: table,
        }),
      );
    }
    if (left > 0) notChecked.push({ module: m.id, reason: 'budget', detail: `${left} tables not checked` });

    return {
      findings,
      facts: { 'supabase.tables': { checked, readable, protected: protectedCount } },
      artifacts,
      notChecked,
    };
  },
};

// ---------------------------------------------------------------------------------------------
// supabase.rpc-exposed: lists /rpc/<fn> from the OpenAPI document. Functions are never called.

const PRIVILEGED_FN = /admin|delete|grant|role|exec|sql|reset|update_user|(^|_)set_/i;

export const supabaseRpcExposed: CheckModule = {
  manifest: {
    id: 'supabase.rpc-exposed',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: [],
    uses: ['artifact:supabase-openapi'],
    provides: [],
    when: ['fact:stack.supabase'],
    params: {},
    budget: { requests: 0 },
  },
  run(ctx) {
    const m = supabaseRpcExposed.manifest;
    const doc = ctx.artifacts.list('supabase-openapi')[0]?.data as SupabaseOpenApi | undefined;
    if (!doc || !doc.rpcs.length) return {};
    const rpcs = [...doc.rpcs].sort();
    const privileged = rpcs.some((n) => PRIVILEGED_FN.test(n));
    const shown = rpcs.slice(0, 10);
    return {
      findings: [
        finding(m, {
          kind: 'rpc-exposed',
          severity: privileged ? 'high' : 'medium',
          confidence: 'confirmed',
          location: { url: `${doc.url}/rest/v1/rpc/` },
          evidence: shown.join(', ') + (rpcs.length > shown.length ? ', …' : ''),
          messageKey: 'supabase.rpc-exposed',
          vars: { count: String(rpcs.length), list: shown.join(', ') },
        }),
      ],
    };
  },
};

// ---------------------------------------------------------------------------------------------
// supabase.storage-public: bucket list with the public key. Listing files needs POST, so it is skipped.

export const supabaseStoragePublic: CheckModule = {
  manifest: {
    id: 'supabase.storage-public',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: [],
    when: ['fact:stack.supabase'],
    params: {},
    budget: { requests: 1 },
  },
  async run(ctx) {
    const m = supabaseStoragePublic.manifest as ModuleManifest;
    const client = clientFrom(ctx);
    if (!client) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no public Supabase key found in the code' }] };
    const url = `${client.url}/storage/v1/bucket`;
    let res: HttpResponse;
    try {
      res = await ctx.http!.fetch({ url, headers: { ...supabaseHeaders(client), Accept: 'application/json' }, maxBytes: 200_000 });
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: isBudget(e) ? 'budget' : 'error', detail: errText(e) }] };
    }
    const list = res.status === 200 ? parseJson(res) : undefined;
    if (!Array.isArray(list)) return {}; // 400/401/403: bucket list not readable with the public key
    const findings = [];
    for (const b of list as Record<string, unknown>[]) {
      if (b && b.public === true) {
        const bucket = String(b.name ?? b.id ?? '');
        if (!bucket) continue;
        findings.push(
          finding(m, {
            kind: 'storage-public',
            severity: 'low',
            confidence: 'confirmed',
            location: { url },
            evidence: `Bucket ${bucket}: public`,
            messageKey: 'supabase.storage-public',
            vars: { bucket },
            discriminator: bucket,
          }),
        );
      }
    }
    return { findings };
  },
};

export const SUPABASE_MODULES: CheckModule<any>[] = [supabaseAuthSettings, supabaseRlsRead, supabaseRpcExposed, supabaseStoragePublic];
