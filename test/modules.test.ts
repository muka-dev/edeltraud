import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { cleanSite, vulnerableSite, FAKE } from './fixtures/sites.ts';
import { scanText } from '../src/modules/analyze/secrets.ts';
import { extractChunkRefs, extractScripts } from '../src/modules/util.ts';

const kinds = (fs: { id: string }[]) => fs.map((f) => f.id).sort();

test('secrets: server keys found, public keys ignored', () => {
  const hit = (t: string) => scanText({ url: 'x', text: t }).map((h) => h.kind);
  assert.deepEqual(hit(`k="${FAKE.openai}"`), ['openai-key']);
  assert.deepEqual(hit(`k="${FAKE.anthropic}"`), ['anthropic-key']);
  assert.deepEqual(hit(`k="${FAKE.stripeLive}"`), ['stripe-secret']);
  assert.deepEqual(hit(`k="${FAKE.github}"`), ['github-token']);
  assert.deepEqual(hit(`k="${FAKE.serviceRole}"`), ['supabase-service-role']);
  assert.deepEqual(hit(`-----BEGIN RSA PRIVATE KEY-----`), ['private-key']);
  assert.deepEqual(hit(`k="${FAKE.anon}"`), []);
  assert.deepEqual(hit(`k="${FAKE.stripePub}"`), []);
  assert.deepEqual(hit(`{apiKey:"${FAKE.googleFirebase}",authDomain:"x.firebaseapp.com"}`), []);
  assert.deepEqual(hit(`new GoogleGenerativeAI("${FAKE.googleGemini}")`), ['gemini-key']);
  assert.deepEqual(hit(`key="${FAKE.googleGemini}"`), ['google-key']);
  // sk- prefixes in ordinary words must not match
  assert.deepEqual(hit('const task-list = "sk-learn is great"'), []);
});

test('script extraction: externals, modulepreload, inline; chunk refs', () => {
  const { external, inline } = extractScripts(
    `<script src="/a.js"></script><script type="module">x()</script><link rel="modulepreload" href="/b.js"><link rel="preload" as="style" href="/c.css"><script type="text/template">no</script>`,
    'https://x.com/p/',
  );
  assert.deepEqual(external, ['https://x.com/a.js', 'https://x.com/b.js']);
  assert.deepEqual(inline, ['x()']);
  assert.deepEqual(extractChunkRefs('import("./Page-abc.js");"assets/x-1.js";"react.js"', 'https://x.com/assets/i.js'), [
    'https://x.com/assets/Page-abc.js',
    'https://x.com/assets/assets/x-1.js',
  ]);
});

test('vulnerable site, report plan: all expected findings', async () => {
  const { result } = await runOn(vulnerableSite(), 'https://vibe.example.com/', 'report');
  assert.deepEqual(kinds(result.findings), [
    'ai.client-llm-call/browser-flag',
    'ai.client-llm-call/direct-call',
    'cookies.flags/cookie-flags',
    'headers.security/csp-missing',
    'headers.security/frame-missing',
    'headers.security/hsts-missing',
    'headers.security/nosniff-missing',
    'headers.security/permissions-missing',
    'headers.security/referrer-missing',
    'headers.security/version-disclosure',
    'secrets.frontend/anthropic-key',
    'secrets.frontend/openai-key',
    'secrets.frontend/supabase-service-role',
    'sourcemaps.exposed/exposed',
    'supabase.config/detected',
    'tls.basics/no-redirect',
    'wellknown.securitytxt/securitytxt-missing',
  ]);
  assert.equal(result.verdict.light, 'red');
  // Evidence is masked, never the full key
  const json = JSON.stringify(result);
  assert.ok(!json.includes(FAKE.openai) && !json.includes(FAKE.anthropic) && !json.includes(FAKE.serviceRole));
  // SPA fallback (index.html under .map) is not counted as a source map
  assert.equal(result.findings.find((f) => f.id === 'sourcemaps.exposed/exposed')?.vars?.count, '1');
  assert.ok((result.facts['stack'] as string[]).includes('Supabase'));
  assert.ok((result.facts['stack'] as string[]).includes('Lovable'));
});

test('ampel plan does not follow lazy chunks (anthropic key only in report)', async () => {
  const { result } = await runOn(vulnerableSite(), 'https://vibe.example.com/', 'ampel');
  assert.ok(!result.findings.some((f) => f.id === 'secrets.frontend/anthropic-key'));
  assert.ok(result.findings.some((f) => f.id === 'secrets.frontend/openai-key'));
  assert.ok(result.requests <= 12);
});

test('clean site: green, no false positives from public keys', async () => {
  const { result } = await runOn(cleanSite(), 'https://clean.example.com/', 'report');
  assert.equal(result.verdict.light, 'green');
  assert.deepEqual(kinds(result.findings), ['firebase.config/detected', 'supabase.config/detected']);
});

test('unreachable site: never green, never a crash', async () => {
  const { result } = await runOn({}, 'https://gone.example.com/', 'ampel');
  // ReplayHttp answers unknown URLs with 404
  assert.equal(result.verdict.light, 'unknown');
  const failing = { fetch: async () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); } };
  const { runPlan } = await import('../src/core/processor.ts');
  const { loadPlan } = await import('../src/core/plan.ts');
  const { createRegistry } = await import('../src/modules/index.ts');
  const out = await runPlan({ plan: loadPlan('ampel'), target: { url: 'https://down.example.com/', host: 'down.example.com', ownershipVerified: false }, registry: createRegistry(), http: failing });
  assert.equal(out.result.complete, false);
  assert.equal(out.result.verdict.light, 'unknown', 'a failed scan must never look green');
  assert.ok(out.result.notChecked.some((n) => n.module === 'collect.page' && n.reason === 'error'));
});

test('http-only app is flagged', async () => {
  const { result } = await runOn(
    { 'https://plain.example.com/': { redirect: 'http://plain.example.com/' }, 'http://plain.example.com/': { body: '<html></html>' } },
    'https://plain.example.com/',
    'ampel',
  );
  assert.ok(result.findings.some((f) => f.id === 'tls.basics/http-only'));
});

test('stack: Clerk key recognised by its encoded host, Stripe key is not Clerk', async () => {
  const clerk = 'pk_' + 'test_' + Buffer.from('fine-gull-12.clerk.accounts.dev$').toString('base64');
  const site = (code: string) => ({
    'https://c.example.com/': { body: '<script src="/assets/index-Aa1Bb2Cc.js"></script>' },
    'https://c.example.com/assets/index-Aa1Bb2Cc.js': { body: code },
  });
  const a = await runOn(site(`Clerk("${clerk}")`), 'https://c.example.com/', 'ampel');
  assert.equal(a.result.facts['stack.clerk'], true);
  const b = await runOn(site(`Stripe("${FAKE.stripePub}")`), 'https://c.example.com/', 'ampel');
  assert.equal(b.result.facts['stack.clerk'], false);
});
