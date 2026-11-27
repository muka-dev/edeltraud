// Supabase probes: RLS read, RPC list, storage, auth settings. Fixture-based, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { findSupabaseClient } from '../src/modules/probe/supabase-key.ts';
import { FAKE, jwt } from './fixtures/sites.ts';

const SB = 'https://abcdefghijklmnopqrst.supabase.co';
const URL_ = 'https://app.example.com/';
const SECRET_EMAIL = 'jane.doe.secret' + '@example.org';
const SECRET_NAME = 'Zaphod-Beeblebrox-' + '4711';

const html = `<!doctype html><html><head><script type="module" src="/assets/index-Ab12Cd34.js"></script></head><body></body></html>`;
const bundle = (extra = '') =>
  `const supabase=c("${SB}","${FAKE.anon}");${extra}`;

function site(extra: Record<string, object> = {}, code = bundle()) {
  return {
    [URL_]: { headers: { 'content-type': 'text/html' }, body: html },
    'https://app.example.com/assets/index-Ab12Cd34.js': { body: code },
    ...extra,
  } as Record<string, any>;
}

const names = ['collect.page', 'collect.bundles', 'stack.detect'];
const plan = (mods: (string | Record<string, object>)[], requests = 60) =>
  parsePlan({ plan: 't', limits: { totalMs: 10000, requests, browser: false }, modules: [...names, ...mods], presentation: { showFindings: 'all', fixPrompts: true } });
const run = (s: Record<string, any>, mods: (string | Record<string, object>)[], own = true, requests = 60) =>
  runOn(s, URL_, plan(mods, requests), { modules: [...MODULES], ownershipVerified: own });

const openapi = (tables: string[], rpcs: string[] = []) =>
  JSON.stringify({ swagger: '2.0', paths: { '/': {}, ...Object.fromEntries(tables.map((t) => [`/${t}`, {}])), ...Object.fromEntries(rpcs.map((r) => [`/rpc/${r}`, {}])) } });

const sbReq = (log: string[]) => log.filter((l) => l.includes('supabase.co'));

test('findSupabaseClient: anon, publishable, custom domain, never service_role', () => {
  const b = (code: string) => [{ url: 'x', source: 'external' as const, status: 200, headers: {}, code, truncated: false }];
  assert.deepEqual(findSupabaseClient(b(bundle()), ''), { url: SB, key: FAKE.anon, keyType: 'anon' });
  const pub = 'sb_publishable_' + 'Ab1'.repeat(8);
  assert.equal(findSupabaseClient(b(`createClient("${SB}","${pub}")`))!.keyType, 'publishable');
  const custom = findSupabaseClient(b(`createClient("https://api.example.com/","${FAKE.anon}")`))!;
  assert.equal(custom.url, 'https://api.example.com');
  assert.equal(findSupabaseClient(b(`createClient("${SB}","${FAKE.serviceRole}")`)), null);
  assert.equal(findSupabaseClient(b(`const a="${SB}",k="${FAKE.serviceRole}"`)), null);
  // anon key wins even if a service_role key sits next to it
  assert.equal(findSupabaseClient(b(`c("${SB}","${FAKE.serviceRole}");d("${SB}","${FAKE.anon}")`))!.key, FAKE.anon);
  assert.equal(findSupabaseClient(b('nothing here')), null);
  void jwt;
});

test('rls-read: readable table with personal columns is critical, evidence has no values', async () => {
  const s = site({
    [`${SB}/rest/v1/`]: { body: openapi(['profiles', 'products', 'orders', 'audit'], ['get_count']) },
    [`${SB}/rest/v1/profiles?select=*&limit=1`]: {
      status: 206,
      headers: { 'content-range': '0-0/123' },
      body: JSON.stringify([{ id: 1, email: SECRET_EMAIL, full_name: SECRET_NAME }]),
    },
    [`${SB}/rest/v1/products?select=*&limit=1`]: { body: JSON.stringify([{ id: 1, sku: 'A-1', price: 5 }]) },
    [`${SB}/rest/v1/orders?select=*&limit=1`]: { body: '[]' },
    [`${SB}/rest/v1/audit?select=*&limit=1`]: { status: 401, body: '{"message":"permission denied"}' },
  });
  const { result, http } = await run(s, ['supabase.rls-read']);
  const f = result.findings.filter((x) => x.id === 'supabase.rls-read/table-readable');
  assert.equal(f.length, 2);
  const prof = f.find((x) => x.vars!.table === 'profiles')!;
  assert.equal(prof.severity, 'critical');
  assert.equal(prof.vars!.rows, '123');
  assert.equal(prof.vars!.columns, 'id, email, full_name');
  assert.equal(prof.evidence, 'profiles: 123 Zeilen, Spalten id, email, full_name');
  assert.equal(prof.location.url, `${SB}/rest/v1/profiles`);
  const prod = f.find((x) => x.vars!.table === 'products')!;
  assert.equal(prod.severity, 'high');
  assert.equal(prod.vars!.rows, '≥1');
  assert.deepEqual(result.facts['supabase.tables'], { checked: 4, readable: 2, protected: 1 });
  const json = JSON.stringify(result);
  assert.ok(!json.includes(SECRET_EMAIL) && !json.includes(SECRET_NAME) && !json.includes(FAKE.anon));
  assert.ok(http.log.every((l) => l.startsWith('GET ')));
  assert.ok(http.log.filter((l) => l.includes('/rest/v1/') && l.includes('?')).every((l) => l.endsWith('select=*&limit=1')));
});

test('rls-read: empty and protected tables give no finding', async () => {
  const s = site({
    [`${SB}/rest/v1/`]: { body: openapi(['a', 'b']) },
    [`${SB}/rest/v1/a?select=*&limit=1`]: { body: '[]' },
    [`${SB}/rest/v1/b?select=*&limit=1`]: { status: 401, body: '{}' },
  });
  const { result } = await run(s, ['supabase.rls-read']);
  assert.equal(result.findings.length, 0);
  assert.deepEqual(result.facts['supabase.tables'], { checked: 2, readable: 0, protected: 1 });
});

test('rls-read: schema not exposed falls back to .from() names in the bundle, storage buckets excluded', async () => {
  const code = bundle(`supabase.from("todos").select("*");supabase.storage.from("avatars").upload();db.from('notes').select()`);
  const s = site(
    {
      [`${SB}/rest/v1/`]: { status: 401, body: '{}' },
      [`${SB}/rest/v1/todos?select=*&limit=1`]: { body: JSON.stringify([{ id: 1, title: 'x' }]) },
      [`${SB}/rest/v1/notes?select=*&limit=1`]: { status: 404, body: '{}' },
    },
    code,
  );
  const { result, http } = await run(s, ['supabase.rls-read', 'supabase.rpc-exposed']);
  assert.ok(result.notChecked.some((n) => n.module === 'supabase.rls-read' && n.reason === 'unsupported' && n.detail === 'schema not exposed'));
  assert.deepEqual(result.facts['supabase.tables'], { checked: 2, readable: 1, protected: 1 });
  assert.ok(!http.log.some((l) => l.includes('avatars')));
  // no OpenAPI document: no RPC finding, no error
  assert.ok(!result.findings.some((f) => f.module === 'supabase.rpc-exposed'));
});

test('rpc-exposed: privileged names are high, harmless ones medium; functions are never called', async () => {
  const s = site({ [`${SB}/rest/v1/`]: { body: openapi(['t'], ['admin_delete_user', 'get_count']) } });
  const { result, http } = await run(s, ['supabase.rls-read', 'supabase.rpc-exposed']);
  const f = result.findings.find((x) => x.id === 'supabase.rpc-exposed/rpc-exposed')!;
  assert.equal(f.severity, 'high');
  assert.equal(f.vars!.count, '2');
  assert.equal(f.vars!.list, 'admin_delete_user, get_count');
  assert.ok(!http.log.some((l) => l.includes('/rpc/')));

  const mild = site({ [`${SB}/rest/v1/`]: { body: openapi([], ['get_count', 'search_items']) } });
  const r2 = await run(mild, ['supabase.rls-read', 'supabase.rpc-exposed']);
  assert.equal(r2.result.findings.find((x) => x.module === 'supabase.rpc-exposed')!.severity, 'medium');
});

test('storage-public: public buckets are low, 400 gives nothing', async () => {
  const s = site({ [`${SB}/storage/v1/bucket`]: { body: JSON.stringify([{ id: 'avatars', name: 'avatars', public: true }, { id: 'docs', name: 'docs', public: false }]) } });
  const { result } = await run(s, ['supabase.storage-public']);
  const f = result.findings.filter((x) => x.module === 'supabase.storage-public');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'low');
  assert.equal(f[0]!.vars!.bucket, 'avatars');

  const denied = await run(site({ [`${SB}/storage/v1/bucket`]: { status: 400, body: '{}' } }), ['supabase.storage-public']);
  assert.equal(denied.result.findings.length, 0);
});

test('auth-settings: autoconfirm with open signup is medium, providers become a fact; passive, no ownership needed', async () => {
  const s = site({
    [`${SB}/auth/v1/settings`]: {
      body: JSON.stringify({ external: { email: true, google: true, github: false, phone: false }, disable_signup: false, mailer_autoconfirm: true, phone_autoconfirm: true }),
    },
  });
  const { result } = await run(s, ['supabase.auth-settings'], false);
  const ids = result.findings.map((f) => f.id).sort();
  assert.deepEqual(ids.filter((i) => i.startsWith('supabase.auth')), ['supabase.auth-settings/autoconfirm', 'supabase.auth-settings/phone-autoconfirm']);
  assert.equal(result.findings.find((f) => f.id.endsWith('/autoconfirm') && !f.id.includes('phone'))!.severity, 'medium');
  assert.equal(result.findings.find((f) => f.id.endsWith('phone-autoconfirm'))!.severity, 'low');
  assert.deepEqual(result.facts['supabase.authProviders'], ['email', 'google']);
  assert.ok(!JSON.stringify(result).includes(FAKE.anon));
});

test('auth-settings: signup disabled or confirmation required gives no finding', async () => {
  for (const body of [
    { external: { email: true }, disable_signup: true, mailer_autoconfirm: true },
    { external: { email: true }, disable_signup: false, mailer_autoconfirm: false },
  ]) {
    const { result } = await run(site({ [`${SB}/auth/v1/settings`]: { body: JSON.stringify(body) } }), ['supabase.auth-settings'], false);
    assert.equal(result.findings.filter((f) => f.module === 'supabase.auth-settings').length, 0);
  }
});

test('without ownership: all active modules are notChecked and nothing goes to supabase.co', async () => {
  const s = site({ [`${SB}/rest/v1/`]: { body: openapi(['profiles'], ['x']) } });
  const { result, http } = await run(s, ['supabase.rls-read', 'supabase.rpc-exposed', 'supabase.storage-public'], false);
  for (const id of ['supabase.rls-read', 'supabase.rpc-exposed', 'supabase.storage-public']) {
    assert.ok(result.notChecked.some((n) => n.module === id && n.reason === 'ownership'), id);
  }
  assert.equal(sbReq(http.log).length, 0);
  assert.equal(result.findings.filter((f) => f.module.startsWith('supabase.')).length, 0);
});

test('budget exhaustion: stops and reports how many tables were left', async () => {
  const tables = Array.from({ length: 40 }, (_, i) => `t${String(i).padStart(2, '0')}`);
  const s = site({ [`${SB}/rest/v1/`]: { body: openapi(tables) } });
  const { result, http } = await run(s, [{ 'supabase.rls-read': { maxTables: 40 } }]);
  const n = result.notChecked.find((x) => x.module === 'supabase.rls-read' && x.reason === 'budget')!;
  assert.ok(n, 'budget notChecked');
  assert.match(n.detail!, /^\d+ tables not checked$/);
  assert.equal(sbReq(http.log).length, 30);
  assert.equal(result.complete, false);

  // maxTables cap alone also reports the rest
  const capped = await run(s, [{ 'supabase.rls-read': { maxTables: 5 } }]);
  assert.equal(capped.result.notChecked.find((x) => x.module === 'supabase.rls-read' && x.reason === 'budget')!.detail, '35 tables not checked');
  assert.equal(sbReq(capped.http.log).length, 6);
});

test('service_role key only: no probe request', async () => {
  const s = site({}, `const a=c("${SB}","${FAKE.serviceRole}");`);
  const { result, http } = await run(s, ['supabase.rls-read', 'supabase.auth-settings']);
  assert.equal(sbReq(http.log).length, 0);
  assert.ok(result.notChecked.some((n) => n.module === 'supabase.rls-read' && n.reason === 'condition'));
});
