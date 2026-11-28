// ratelimit.auth and auth.enumeration: failed logins with a fake address. Fixture-based, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { FAKE } from './fixtures/sites.ts';

const SB = 'https://abcdefghijklmnopqrst.supabase.co';
const SB_LOGIN = `${SB}/auth/v1/token?grant_type=password`;
const KEY = FAKE.googleFirebase;
const FB_LOGIN = `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${KEY}`;
const URL_ = 'https://app.example.com/';
const SECRET = 'Zaphod-Beeblebrox-' + '4711';
const html = `<!doctype html><html><head><script type="module" src="/assets/index-Ab12Cd34.js"></script></head><body></body></html>`;
const SB_CODE = `const supabase=createClient("${SB}","${FAKE.anon}");`;
const FB_CODE = `const firebaseConfig={apiKey:"${KEY}",authDomain:"demo-app.firebaseapp.com",projectId:"demo-app"};initializeApp(firebaseConfig);`;

const SB_DENIED = { status: 400, body: `{"code":400,"error_code":"invalid_credentials","msg":"Invalid login credentials","trace":"${SECRET}"}` };
const LIMITED = { status: 429, body: `{"code":429,"error_code":"over_request_rate_limit","msg":"${SECRET}"}` };
const fbError = (message: string) => ({ status: 400, body: JSON.stringify({ error: { code: 400, message, errors: [{ message, domain: SECRET }] } }) });

/** Login URL whose answer changes per call: `answers(n)` gets the 1-based call number. */
function sequence(url: string, answers: (n: number) => object) {
  let n = 0;
  return Object.defineProperty({}, url, { enumerable: true, get: () => answers(++n) });
}

/** The app plus login answers; property descriptors are copied so sequence getters stay live. */
function withLogin(code: string, login: object): Record<string, any> {
  const s = {
    [URL_]: { headers: { 'content-type': 'text/html' }, body: html },
    'https://app.example.com/assets/index-Ab12Cd34.js': { body: code },
  };
  return Object.defineProperties(s, Object.getOwnPropertyDescriptors(login));
}

const plan = parsePlan({
  plan: 't',
  limits: { totalMs: 10000, requests: 60, browser: false },
  modules: ['collect.page', 'collect.bundles', 'auth.enumeration', { 'ratelimit.auth': { maxAttempts: 10, pauseMs: 0 } }],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const run = (s: Record<string, any>, own = true) => runOn(s, URL_, plan, { modules: [...MODULES], ownershipVerified: own });
const logins = (http: { requests: { url: string; method?: string; body?: string }[] }) => http.requests.filter((r) => r.method === 'POST');

function assertSafe(http: { requests: { url: string; method?: string; body?: string }[] }) {
  for (const r of http.requests) {
    assert.ok(!/signup|recover|reset|otp|magiclink|sendOobCode|accounts:signUp|verify/i.test(r.url), `forbidden URL ${r.url}`);
  }
  const posts = logins(http);
  const emails = new Set(posts.map((r) => JSON.parse(r.body!).email as string));
  for (const e of emails) assert.match(e, /^edeltraud-probe-[0-9a-f]{12}@example\.invalid$/);
}

test('ratelimit.auth (Supabase): limited after 4 failed logins → no finding, stops at 429', async () => {
  const { result, http } = await run(withLogin(SB_CODE, sequence(SB_LOGIN, (n) => (n <= 4 ? SB_DENIED : LIMITED))));
  assertSafe(http);
  const posts = logins(http);
  assert.equal(posts.length, 5);
  assert.ok(posts.every((r) => r.url === SB_LOGIN));
  assert.equal(new Set(posts.map((r) => JSON.parse((r as any).body).email)).size, 1, 'same fake email every time');
  assert.equal(result.findings.filter((f) => f.module === 'ratelimit.auth').length, 0);
  assert.deepEqual(result.facts['ratelimit.auth'], { provider: 'supabase', attempts: 5, limitedAfter: 4 });
  // Supabase: no enumeration request at all.
  assert.ok(result.notChecked.some((n) => n.module === 'auth.enumeration' && n.reason === 'condition'));
});

test('ratelimit.auth (Supabase): never limited → medium finding, public key only, no response values', async () => {
  const { result, http } = await run(withLogin(SB_CODE, { [SB_LOGIN]: SB_DENIED }));
  assertSafe(http);
  const posts = logins(http) as any[];
  assert.equal(posts.length, 10);
  for (const r of posts) {
    assert.equal(r.headers['apikey'], FAKE.anon);
    assert.equal(r.headers['content-type'], 'application/json');
    assert.equal(r.followRedirects, false);
    assert.deepEqual(Object.keys(JSON.parse(r.body)).sort(), ['email', 'password']);
  }
  const fs = result.findings.filter((f) => f.module === 'ratelimit.auth');
  assert.equal(fs.length, 1);
  assert.equal(fs[0]!.severity, 'medium');
  assert.equal(fs[0]!.confidence, 'likely');
  assert.equal(fs[0]!.messageKey, 'ratelimit.auth.supabase');
  assert.equal(fs[0]!.evidence, 'supabase: 10 failed logins, no HTTP 429');
  assert.deepEqual(result.facts['ratelimit.auth'], { provider: 'supabase', attempts: 10, limitedAfter: null });
  assert.ok(!JSON.stringify(result).includes(SECRET), 'no response body content in the result');
});

test('ratelimit.auth: other status → notChecked, no finding', async () => {
  const { result, http } = await run(withLogin(SB_CODE, { [SB_LOGIN]: { status: 503, body: 'down' } }));
  assert.equal(logins(http).length, 1);
  assert.equal(result.findings.filter((f) => f.module === 'ratelimit.auth').length, 0);
  assert.ok(result.notChecked.some((n) => n.module === 'ratelimit.auth' && n.reason === 'error'));
});

test('auth.enumeration (Firebase): EMAIL_NOT_FOUND → confirmed finding; TOO_MANY_ATTEMPTS counts as limit', async () => {
  const { result, http } = await run(
    withLogin(FB_CODE, sequence(FB_LOGIN, (n) => (n <= 3 ? fbError('EMAIL_NOT_FOUND') : fbError('TOO_MANY_ATTEMPTS_TRY_LATER : Access disabled'))),
  ));
  assertSafe(http);
  const posts = logins(http) as any[];
  assert.ok(posts.every((r) => r.url === FB_LOGIN && JSON.parse(r.body).returnSecureToken === true));
  const en = result.findings.filter((f) => f.module === 'auth.enumeration');
  assert.equal(en.length, 1);
  assert.equal(en[0]!.severity, 'medium');
  assert.equal(en[0]!.confidence, 'confirmed');
  assert.ok(!en[0]!.location.url!.includes(KEY), 'API key not in the location');
  // 1 enumeration request + ratelimit: 2 denied, then limited on the 3rd.
  assert.equal(posts.length, 4);
  assert.deepEqual(result.facts['ratelimit.auth'], { provider: 'firebase', attempts: 3, limitedAfter: 2 });
  assert.equal(result.findings.filter((f) => f.module === 'ratelimit.auth').length, 0);
  assert.ok(!JSON.stringify(result).includes(SECRET));
});

test('auth.enumeration (Firebase): INVALID_LOGIN_CREDENTIALS → no enumeration finding', async () => {
  const { result } = await run(withLogin(FB_CODE, { [FB_LOGIN]: fbError('INVALID_LOGIN_CREDENTIALS') }));
  assert.equal(result.findings.filter((f) => f.module === 'auth.enumeration').length, 0);
  assert.deepEqual(result.facts['auth.enumeration'], { provider: 'firebase', enumerable: false });
  const rl = result.findings.filter((f) => f.module === 'ratelimit.auth');
  assert.equal(rl.length, 1);
  assert.equal(rl[0]!.messageKey, 'ratelimit.auth.firebase');
});

test('ratelimit.auth / auth.enumeration: without ownership nothing is sent', async () => {
  for (const s of [withLogin(SB_CODE, { [SB_LOGIN]: SB_DENIED }), withLogin(FB_CODE, { [FB_LOGIN]: fbError('EMAIL_NOT_FOUND') })]) {
    const { result, http } = await run(s, false);
    assert.equal(logins(http).length, 0);
    for (const id of ['ratelimit.auth', 'auth.enumeration']) {
      assert.ok(result.notChecked.some((n) => n.module === id && n.reason === 'ownership'));
      assert.equal(result.findings.filter((f) => f.module === id).length, 0);
    }
  }
});
