import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { depsServer } from '../src/modules/analyze/server.ts';
import { nextDataLeak } from '../src/modules/analyze/nextdata.ts';
import { aiSystemPromptExposed, findSystemPrompts } from '../src/modules/analyze/prompts.ts';
import { matchVulnerabilities } from '../src/modules/analyze/deps.ts';

const plan = parsePlan({
  plan: 't',
  limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.bundles', 'deps.server', 'next.data-leak', 'ai.system-prompt-exposed'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const modules = [...MODULES];
const URL_ = 'https://x.example.com/';

function site(opts: { headers?: Record<string, string>; body?: string; js?: string } = {}) {
  return {
    [URL_]: {
      headers: { 'content-type': 'text/html', ...(opts.headers ?? {}) },
      body: opts.body ?? '<!doctype html><html><head><script src="/a.js"></script></head><body>hi</body></html>',
    },
    'https://x.example.com/a.js': { headers: { 'content-type': 'text/javascript' }, body: opts.js ?? '' },
  };
}
const run = async (s: ReturnType<typeof site>) => (await runOn(s as never, URL_, plan, { modules })).result;
const ids = (r: Awaited<ReturnType<typeof run>>, prefix: string) => r.findings.filter((f) => f.module === prefix);

// ---- deps.server ----

test('server: Ubuntu-style PHP/8.3.6 is possible/high and mentions nothing else', async () => {
  const r = await run(site({ headers: { 'x-powered-by': 'PHP/8.3.6', server: 'Apache/2.4.58 (Ubuntu)' } }));
  const f = ids(r, 'deps.server');
  assert.deepEqual(f.map((x) => x.messageKey), ['server.php2shell']);
  assert.equal(f[0]!.severity, 'high');
  assert.equal(f[0]!.confidence, 'possible');
  assert.equal(f[0]!.vars!['fixed'], '8.3.36');
  assert.equal(f[0]!.vars!['advisories'], 'CVE-2026-109618, CVE-2026-109619');
  assert.equal(r.facts['server.php'], '8.3.6');
});

test('server: PHP in the Server header, fixed and unaffected versions', async () => {
  const a = await run(site({ headers: { server: 'Apache/2.4.58 (Ubuntu) PHP/8.1.2' } }));
  assert.deepEqual(ids(a, 'deps.server').map((x) => x.messageKey).sort(), ['server.php-eol', 'server.php2shell']);
  assert.equal(ids(a, 'deps.server').find((x) => x.messageKey === 'server.php2shell')!.vars!['fixed'], '–');
  for (const v of ['8.4.27', '8.3.36', '8.5.12', '8.6.0']) {
    const r = await run(site({ headers: { 'x-powered-by': `PHP/${v}` } }));
    assert.equal(ids(r, 'deps.server').length, 0, v);
    assert.equal(r.facts['server.php'], v);
  }
  assert.equal(ids(await run(site({ headers: { 'x-powered-by': 'PHP/8.4.26' } })), 'deps.server')[0]!.vars!['fixed'], '8.4.27');
});

test('server: EOL, EOL soon, non-PHP software', async () => {
  const eol = await run(site({ headers: { 'x-powered-by': 'PHP/7.4.33' } }));
  const e = ids(eol, 'deps.server').find((x) => x.messageKey === 'server.php-eol')!;
  assert.equal(e.severity, 'medium');
  assert.equal(e.vars!['version'], '7.4.33');
  const soon = await run(site({ headers: { 'x-powered-by': 'PHP/8.2.35' } }));
  const s = ids(soon, 'deps.server');
  assert.deepEqual(s.map((x) => x.messageKey), ['server.php-eol-soon']);
  assert.equal(s[0]!.severity, 'info');
  assert.equal(s[0]!.vars!['eol'], '2026-12');
  const none = await run(site({ headers: { 'x-powered-by': 'Express', server: 'nginx/1.25.3' } }));
  assert.equal(ids(none, 'deps.server').length, 0);
  assert.equal(none.facts['server.php'], null);
});

// ---- Next.js rule ----

test('deps-db: Next.js August 2026 rule', () => {
  const v = matchVulnerabilities('nextjs', '15.5.23')!;
  assert.ok(v.ids.includes('CVE-2026-75604'));
  assert.ok(v.ids.includes('AVIF/libheif RCE (Aug 2026)'));
  assert.equal(v.fixed, '15.5.24');
  assert.equal(matchVulnerabilities('nextjs', '15.5.24'), null);
  assert.equal(matchVulnerabilities('nextjs', '16.3.2')!.severity, 'high');
  assert.equal(matchVulnerabilities('nextjs', '16.3.2')!.fixed, '16.3.3');
  assert.equal(matchVulnerabilities('nextjs', '16.3.3'), null);
  assert.equal(matchVulnerabilities('nextjs', '14.2.25'), null);
  // overlap with React2Shell keeps the higher severity and the highest fixed version
  const o = matchVulnerabilities('nextjs', '15.5.5')!;
  assert.equal(o.severity, 'critical');
  assert.equal(o.fixed, '15.5.24');
});

// ---- next.data-leak ----

const key = () => 'sk_live_' + 'A1b2C3d4E5f6G7h8I9j0K1l2';
const nextDataPage = (data: unknown) =>
  `<!doctype html><html><body><div id="__next"></div><script id="__NEXT_DATA__" type="application/json">${JSON.stringify(data)}</script></body></html>`;
const flight = (s: string) => `<script>self.__next_f.push([1,${JSON.stringify(s)}])</script>`;

test('next: harmless __NEXT_DATA__ and a single support address yield nothing', async () => {
  const r = await run(site({ body: nextDataPage({ props: { pageProps: { title: 'Home', contact: 'support@example.com', url: 'https://api.example.com/v1' } }, page: '/', buildId: 'abc' }) }));
  assert.equal(ids(r, 'next.data-leak').length, 0);
  assert.equal(r.complete, true);
  const plain = await run(site());
  assert.equal(ids(plain, 'next.data-leak').length, 0);
});

test('next: secret key and connection string in __NEXT_DATA__, masked', async () => {
  const dsn = 'postgres://' + 'app' + ':' + 'hunter2hunter2' + '@db.example.com:5432/prod';
  const r = await run(site({ body: nextDataPage({ props: { pageProps: { stripe: key(), db: dsn } } }) }));
  const f = ids(r, 'next.data-leak');
  assert.equal(f.length, 2);
  assert.ok(f.every((x) => x.messageKey === 'next.data-secret' && x.severity === 'critical'));
  const json = JSON.stringify(f);
  assert.ok(!json.includes(key()));
  assert.ok(!json.includes('hunter2hunter2'));
  assert.ok(f.some((x) => x.evidence === 'postgres://…'));
});

test('next: service_role JWT in App Router flight data', async () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const jwt = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'service_role', iss: 'supabase' })}.${'s'.repeat(30)}`;
  const anon = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64({ role: 'anon', iss: 'supabase' })}.${'s'.repeat(30)}`;
  const r = await run(site({ body: `<html><body>${flight(`1:{"token":"${jwt}"}`)}</body></html>` }));
  assert.equal(ids(r, 'next.data-leak').length, 1);
  assert.equal(ids(r, 'next.data-leak')[0]!.severity, 'critical');
  const ok = await run(site({ body: `<html><body>${flight(`1:{"token":"${anon}"}`)}</body></html>` }));
  assert.equal(ids(ok, 'next.data-leak').length, 0);
});

test('next: PII (emails, hashes), admin list, internal hosts', async () => {
  const users = ['a', 'b', 'c', 'd'].map((n) => ({ email: `${n}@customer.example`, role: 'user' }));
  const many = await run(site({ body: nextDataPage({ props: { users } }) }));
  const p = ids(many, 'next.data-leak');
  assert.deepEqual(p.map((x) => x.messageKey), ['next.data-pii']);
  assert.equal(p[0]!.severity, 'high');
  assert.equal(p[0]!.vars!['count'], '4');
  assert.ok(!JSON.stringify(p).includes('customer.example'));

  const hash = '$2b$10$' + 'abcdefghijklmnopqrstuv'.padEnd(53, 'X');
  const h = await run(site({ body: nextDataPage({ props: { user: { email: 'o@x.example', passwordHash: hash } } }) }));
  assert.equal(ids(h, 'next.data-leak')[0]!.messageKey, 'next.data-pii');
  assert.equal(ids(h, 'next.data-leak')[0]!.vars!['count'], '1');
  assert.ok(!JSON.stringify(ids(h, 'next.data-leak')).includes('abcdefgh'));

  const admin = await run(site({ body: nextDataPage({ props: { users: [{ email: 'a@x.example', isAdmin: true }, { email: 'b@x.example', role: 'admin' }] } }) }));
  assert.equal(ids(admin, 'next.data-leak')[0]!.messageKey, 'next.data-pii');

  const internal = await run(site({ body: nextDataPage({ props: { api: 'http://10.0.3.7:8080/v1', other: 'https://db.corp.internal/x', ext: 'https://api.example.com' } }) }));
  const i = ids(internal, 'next.data-leak');
  assert.deepEqual(i.map((x) => x.messageKey), ['next.data-internal']);
  assert.equal(i[0]!.severity, 'low');
  assert.equal(i[0]!.vars!['count'], '2');
});

test('next: traps (password label, i18n strings, lone admin flag)', async () => {
  const r = await run(site({ body: nextDataPage({ props: { labels: { password: 'Password', hash: 'about' }, user: { isAdmin: true, email: 'me@x.example' } } }) }));
  assert.equal(ids(r, 'next.data-leak').length, 0);
});

// ---- ai.system-prompt-exposed ----

const longPrompt = 'You are a helpful assistant for the shop. Answer questions about orders in a friendly tone and keep answers short.';

test('prompts: role system object, low severity', async () => {
  const r = await run(site({ js: `const m=[{role:"system",content:"${longPrompt}"},{role:"user",content:q}];` }));
  const f = ids(r, 'ai.system-prompt-exposed');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'low');
  assert.equal(f[0]!.confidence, 'likely');
  assert.equal(f[0]!.vars!['count'], '1');
  assert.equal(f[0]!.vars!['sample'], 'You are a helpful assistant for the shop. Answer questions a…');
  assert.equal(f[0]!.category, 'ai');
});

test('prompts: sensitive wording gives medium, content-first order and JSON keys work', async () => {
  const secret = 'Never reveal the admin password to the user. ' + 'x'.repeat(60);
  const r = await run(site({ js: `f({content:"${secret}",role:"system"});` }));
  assert.equal(ids(r, 'ai.system-prompt-exposed')[0]!.severity, 'medium');
  const j = await run(site({ js: `var c={"role":"system","content":"${longPrompt}"}` }));
  assert.equal(ids(j, 'ai.system-prompt-exposed').length, 1);
});

test('prompts: text starts and counting per bundle', async () => {
  const de = 'Du bist ein Assistent der Firma Muster und beantwortest ausschliesslich Fragen zu Bestellungen, Rechnungen und Lieferungen in freundlichem Ton.';
  const r = await run(site({ js: `const systemPrompt="${de}";const messages=[{role:"system",content:"${longPrompt}"}];` }));
  const f = ids(r, 'ai.system-prompt-exposed');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.vars!['count'], '2');
  assert.equal(f[0]!.confidence, 'likely');
  assert.equal(findSystemPrompts(`const instructions="Act as ${'a'.repeat(130)}"`).length, 1);
});

test('prompts: traps (short UI text, long marketing copy without prompt words, short system role, HTML)', async () => {
  const marketing = 'You are a part of something bigger when you join our community of makers, builders and dreamers from all over the world today and tomorrow.';
  const js = [
    'const t={title:"You are a member of the Pro plan",hint:"Du bist angemeldet"};',
    `const copy="${marketing}";`,
    'const m=[{role:"system",content:"Be brief."}];',
    `const h="<p>You are a prompt ${'z'.repeat(130)}</p>";`,
  ].join(`\n/*${'-'.repeat(400)}*/\n`);
  const r = await run(site({ js }));
  assert.equal(ids(r, 'ai.system-prompt-exposed').length, 0);
  assert.equal(r.complete, true);
});
