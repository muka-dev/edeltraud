// Endpoint discovery, client-only auth hint, anonymous API probe and CORS probe. Fixture-based, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { normalisePath, type EndpointsData } from '../src/modules/analyze/endpoints.ts';
import { dataShape } from '../src/modules/probe/api.ts';

const URL_ = 'https://app.example.com/';
const SECRET_EMAIL = 'jane.doe.secret' + '@example.org';
const SECRET_NAME = 'Zaphod-Beeblebrox-' + '4711';
const CORS_ORIGIN = 'https://edeltraud-cors-check.invalid';
const html = `<!doctype html><html><head><script type="module" src="/assets/index-Ab12Cd34.js"></script></head><body></body></html>`;

function site(code: string, extra: Record<string, object> = {}) {
  return {
    [URL_]: { headers: { 'content-type': 'text/html' }, body: html },
    'https://app.example.com/assets/index-Ab12Cd34.js': { body: code },
    ...extra,
  } as Record<string, any>;
}

const plan = (mods: string[], opts: { browser?: boolean; requests?: number } = {}) =>
  parsePlan({
    plan: 't',
    limits: { totalMs: 10000, requests: opts.requests ?? 60, browser: opts.browser ?? false },
    modules: ['collect.page', 'collect.bundles', ...(opts.browser ? [{ 'collect.render': { waitMs: 0 } }] : []), ...mods],
    presentation: { showFindings: 'all', fixPrompts: true },
  });
const run = (s: Record<string, any>, mods: string[], own = true, opts: { browser?: boolean; requests?: number } = {}, render?: Record<string, any>) =>
  runOn(s, URL_, plan(mods, opts), { modules: [...MODULES], ownershipVerified: own, ...(render ? { render } : {}) });

const json = { headers: { 'content-type': 'application/json' } };
const list = (a: { list: unknown[] }) => a.list as EndpointsData['list'];
const endpointsOf = (r: Awaited<ReturnType<typeof run>>) => list(r.artifacts.list('endpoints')[0]!.data as EndpointsData);

const CODE = `
fetch("/api/users");
fetch("/api/orders/123/items", { method: "POST", body: x });
axios.get("/api/products/550e8400-e29b-41d4-a716-446655440000");
axios.post("/api/contact", d);
const u = \`\${base}/api/projects/\${id}/members?x=1\`;
const s = "/api/status?cache=1";
supabase.functions.invoke("send-welcome", { body: {} });
fetch("https://abcdefghijklmnopqrst.supabase.co/functions/v1/public-feed");
fetch("https://evil.example.net/api/steal");
fetch("/assets/logo.png");
`;

test('normalisePath: ids, queries, templates, static files', () => {
  assert.equal(normalisePath('/api/users/123?x=1'), '/api/users/:id');
  assert.equal(normalisePath('/api/u/550e8400-e29b-41d4-a716-446655440000/x'), '/api/u/:id/x');
  assert.equal(normalisePath('${base}/api/a/${id}/b'), '/api/a/:id/b');
  assert.equal(normalisePath('/api/items/'), '/api/items/:id');
  assert.equal(normalisePath('/api/'), null);
  assert.equal(normalisePath('/logo.png'), null);
  assert.equal(normalisePath('//cdn.example.com/x'), null);
});

test('endpoints.discovered: bundle patterns, normalisation, same-site only, fact', async () => {
  const { result, artifacts } = await run(site(CODE), ['endpoints.discovered']);
  const eps = list(artifacts.list('endpoints')[0]!.data as EndpointsData);
  const paths = eps.map((e) => `${e.method ?? '-'} ${e.path}`);
  assert.ok(paths.includes('GET /api/users'));
  assert.ok(paths.includes('POST /api/orders/:id/items'));
  assert.ok(paths.includes('GET /api/products/:id'));
  assert.ok(paths.includes('POST /api/contact'));
  assert.ok(paths.includes('- /api/projects/:id/members'));
  assert.ok(paths.includes('- /api/status'));
  assert.ok(!paths.some((p) => p.includes('steal') || p.includes('logo')));
  const edge = eps.filter((e) => e.edgeFunction);
  assert.deepEqual(edge.map((e) => e.edgeFunction).sort(), ['public-feed', 'send-welcome']);
  assert.equal(edge.find((e) => e.edgeFunction === 'public-feed')!.origin, 'https://abcdefghijklmnopqrst.supabase.co');
  assert.equal(edge.find((e) => e.edgeFunction === 'send-welcome')!.method, 'POST');
  assert.equal(result.facts['endpoints.count'], eps.length);
  assert.equal(result.findings.length, 0);
  assert.equal(new Set(eps.map((e) => `${e.method}|${e.path}`)).size, eps.length);
});

test('endpoints.discovered: render requests (xhr/fetch, same site only), cap at 200', async () => {
  const many = Array.from({ length: 260 }, (_, i) => `fetch("/api/r${i}");`).join('\n');
  const r1 = await run(site(many), ['endpoints.discovered']);
  assert.equal(endpointsOf(r1).length, 200);

  const render = {
    [URL_]: {
      requests: [
        { url: 'https://app.example.com/rest/items?page=2', method: 'GET', resourceType: 'fetch', status: 200, failure: null },
        { url: 'https://app.example.com/main.js', method: 'GET', resourceType: 'script', status: 200, failure: null },
        { url: 'https://tracker.example.net/collect', method: 'POST', resourceType: 'xhr', status: 200, failure: null },
        { url: 'https://api.example.com/v1/me', method: 'GET', resourceType: 'xhr', status: 200, failure: null },
      ],
    },
  };
  const r2 = await run(site('const a = 1;'), ['endpoints.discovered'], true, { browser: true }, render);
  const eps = endpointsOf(r2);
  assert.deepEqual(eps.map((e) => `${e.source} ${e.method} ${e.path}`), ['render GET /rest/items', 'render GET /v1/me']);
});

const ADMIN_CODE = `const r=[{path:"/admin"},{path:"/dashboard/admin/users"}];if(user.role==="admin"){nav(r)}`;

test('auth.client-only: admin routes plus role comparison, no server admin endpoints', async () => {
  const { result } = await run(site(ADMIN_CODE), ['endpoints.discovered', 'auth.client-only'], false);
  const f = result.findings.filter((x) => x.id === 'auth.client-only/client-only');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'medium');
  assert.equal(f[0]!.confidence, 'possible');
  assert.equal(f[0]!.vars!.routes, '/admin, /dashboard/admin/users');
  assert.equal(f[0]!.messageKey, 'auth.client-only');
});

test('auth.client-only: traps (route only, role only, server admin API, other variants)', async () => {
  const none = ['const r="/admin";render(r)', 'if(user.role==="admin"){x()}', 'const a="/administrator-guide.html";if(isAdmin){}'];
  for (const code of none) {
    const { result } = await run(site(code), ['endpoints.discovered', 'auth.client-only'], false);
    assert.equal(result.findings.length, 0, code);
  }
  const withApi = ADMIN_CODE + `;fetch("/api/admin/users")`;
  assert.equal((await run(site(withApi), ['endpoints.discovered', 'auth.client-only'], false)).result.findings.length, 0);
  const withEdge = ADMIN_CODE + `;supabase.functions.invoke("admin-users")`;
  assert.equal((await run(site(withEdge), ['endpoints.discovered', 'auth.client-only'], false)).result.findings.length, 0);
  const meta = `go("/admin/settings");const ok=session.user.app_metadata?.role;`;
  assert.equal((await run(site(meta), ['endpoints.discovered', 'auth.client-only'], false)).result.findings.length, 1);
  const isAdm = `go("/admin");if(isAdmin){}`;
  assert.equal((await run(site(isAdm), ['auth.client-only'], false)).result.findings.length, 1);
});

test('dataShape: arrays, wrappers, status objects', () => {
  assert.deepEqual(dataShape([{ id: 1, a: 2 }, { id: 2 }]), { count: 2, fields: ['id', 'a'] });
  assert.deepEqual(dataShape({ items: [{ id: 1 }] }), { count: 1, fields: ['id'] });
  assert.equal(dataShape({ status: 'ok' }), null);
  assert.equal(dataShape({ items: [] }), null);
  assert.equal(dataShape([]), null);
  assert.equal(dataShape([1, 2]), null);
  assert.equal(dataShape('x'), null);
  assert.equal(dataShape({ data: null }), null);
});

const PROBE_CODE = `
fetch("/api/users");
fetch("/api/products");
fetch("/api/health");
fetch("/api/spa");
fetch("/api/private");
fetch("/api/missing");
fetch("/api/items/123");
fetch("/api/logout");
fetch("/api/delete-account");
fetch("/api/orders", { method: "POST" });
axios.post("/api/post-only", d);
supabase.functions.invoke("list-things");
`;

function probeSite() {
  return site(PROBE_CODE, {
    'https://app.example.com/api/users': { ...json, body: JSON.stringify([{ id: 1, email: SECRET_EMAIL, name: SECRET_NAME }, { id: 2 }]) },
    'https://app.example.com/api/products': { ...json, body: JSON.stringify({ items: [{ id: 1, sku: 'A-1', price: 5 }] }) },
    'https://app.example.com/api/health': { ...json, body: '{"status":"ok"}' },
    'https://app.example.com/api/spa': { headers: { 'content-type': 'text/html' }, body: html },
    'https://app.example.com/api/private': { status: 401, ...json, body: '{"error":"unauthorized"}' },
    'https://app.example.com/api/items/123': { ...json, body: '[{"id":1}]' },
    'https://app.example.com/api/logout': { ...json, body: '[{"id":1}]' },
    'https://app.example.com/api/delete-account': { ...json, body: '[{"id":1}]' },
    'https://app.example.com/api/orders': { ...json, body: '[{"id":1}]' },
    'https://app.example.com/api/post-only': { ...json, body: '[{"id":1}]' },
    'https://app.example.com/functions/v1/list-things': { ...json, body: '[{"id":1,"label":"x"}]' },
  });
}

test('api.unauth: data endpoints are found, traps are not, no values in the result', async () => {
  const { result, http } = await run(probeSite(), ['endpoints.discovered', 'api.unauth']);
  const f = result.findings.filter((x) => x.id === 'api.unauth/unauth-data');
  const by = Object.fromEntries(f.map((x) => [x.vars!.path, x]));
  assert.deepEqual(Object.keys(by).sort(), ['/api/products', '/api/users', '/functions/v1/list-things']);
  assert.equal(by['/api/users']!.severity, 'critical');
  assert.equal(by['/api/users']!.evidence, '/api/users: 2 Einträge, Felder id, email, name');
  assert.equal(by['/api/products']!.severity, 'high');
  assert.equal(by['/api/products']!.evidence, '/api/products: 1 Einträge, Felder id, sku, price');
  assert.equal(by['/api/products']!.messageKey, 'api.unauth-data');
  const out = JSON.stringify(result);
  assert.ok(!out.includes(SECRET_EMAIL) && !out.includes(SECRET_NAME));
  const probed = http.log.filter((l) => l.includes('/api/') || l.includes('/functions/'));
  assert.ok(probed.every((l) => l.startsWith('GET ')));
  for (const bad of ['/api/items/', '/api/logout', '/api/delete-account', '/api/orders', '/api/post-only']) {
    assert.ok(!probed.some((l) => l.includes(bad)), bad);
  }
  const facts = result.facts['api.unauth'] as { protected: number; readable: number };
  assert.equal(facts.protected, 1);
  assert.equal(facts.readable, 3);
});

test('api.unauth: Edge Function is called with GET (no body), data is reported', async () => {
  const { result, http } = await run(probeSite(), ['endpoints.discovered', 'api.unauth']);
  // invoke() defaults to POST but Edge Functions are probed with GET; the fixture serves it on the site origin.
  assert.ok(http.log.includes('GET https://app.example.com/functions/v1/list-things'));
  assert.ok(result.findings.some((x) => x.id === 'api.unauth/unauth-data' && x.vars!.path === '/functions/v1/list-things'));
});

test('api.unauth: maxEndpoints and request budget end up in notChecked', async () => {
  const s = probeSite();
  const limited = await runOn(s, URL_, parsePlan({
    plan: 't', limits: { totalMs: 10000, requests: 60, browser: false },
    modules: ['collect.page', 'collect.bundles', 'endpoints.discovered', { 'api.unauth': { maxEndpoints: 2 } }],
    presentation: { showFindings: 'all', fixPrompts: true },
  }), { modules: [...MODULES], ownershipVerified: true });
  assert.ok(limited.result.notChecked.some((n) => n.module === 'api.unauth' && n.reason === 'budget'));
  assert.ok(limited.http.log.filter((l) => l.includes('/api/')).length <= 2 + 1);
});

test('without ownership: api.unauth and cors.policy are notChecked and make no requests', async () => {
  const { result, http } = await run(probeSite(), ['endpoints.discovered', 'api.unauth', 'cors.policy'], false);
  for (const id of ['api.unauth', 'cors.policy']) {
    assert.ok(result.notChecked.some((n) => n.module === id && n.reason === 'ownership'), id);
  }
  assert.ok(!http.log.some((l) => l.includes('/api/') || l.includes('/functions/')));
  assert.equal(result.findings.length, 0);
});

test('cors.policy: reflect+credentials high, wildcard+credentials medium, reflect low, safe ones silent', async () => {
  const code = `fetch("/api/a");fetch("/api/b");fetch("/api/c");fetch("/api/d");fetch("/api/e");fetch("/api/f");fetch("/api/g/1");`;
  const s = site(code, {
    'https://app.example.com/api/a': { ...json, headers: { 'content-type': 'application/json', 'access-control-allow-origin': CORS_ORIGIN, 'access-control-allow-credentials': 'true' }, body: '{}' },
    'https://app.example.com/api/b': { headers: { 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }, body: '{}' },
    'https://app.example.com/api/c': { headers: { 'access-control-allow-origin': CORS_ORIGIN }, body: '{}' },
    'https://app.example.com/api/d': { headers: { 'access-control-allow-origin': '*' }, body: '{}' },
    'https://app.example.com/api/e': { headers: { 'access-control-allow-origin': 'https://app.example.com', 'access-control-allow-credentials': 'true' }, body: '{}' },
    'https://app.example.com/api/f': { body: '{}' },
  });
  const { result, http } = await run(s, ['endpoints.discovered', 'cors.policy']);
  const sev = Object.fromEntries(result.findings.map((f) => [f.id.split('/')[1], f.severity]));
  assert.deepEqual(sev, { 'reflect-credentials': 'high', 'wildcard-credentials': 'medium', reflect: 'low' });
  assert.deepEqual(result.findings.map((f) => f.messageKey).sort(), ['cors.reflect', 'cors.reflect-credentials', 'cors.wildcard-credentials']);
  // at most 5 endpoints, none with unresolved params
  assert.equal(http.log.filter((l) => l.includes('/api/')).length, 5);
  assert.ok(!http.log.some((l) => l.includes('/api/g')));
});

test('cors.policy: falls back to the start page when no endpoints are known', async () => {
  const s = site('const x=1;');
  s[URL_] = { headers: { 'content-type': 'text/html', 'access-control-allow-origin': CORS_ORIGIN }, body: html };
  const { result } = await run(s, ['cors.policy']);
  assert.deepEqual(result.findings.map((f) => f.id), ['cors.policy/reflect']);
  assert.equal(result.findings[0]!.location.url, URL_);
});

test('dataShape: wrapped public info is not data, wrapped records are', async () => {
  const { dataShape } = await import('../src/modules/probe/api.ts');
  assert.equal(dataShape({ data: { version: '1', status: 'ok' } }), null);
  assert.deepEqual(dataShape({ data: { id: 7, email: 'x' } })?.fields, ['id', 'email']);
  assert.equal(dataShape({ items: [] }), null);
});
