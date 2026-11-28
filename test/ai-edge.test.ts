// ai.edge-function-open: one POST with invalid JSON per LLM-looking Edge Function. Fixture-based, no network.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { FAKE } from './fixtures/sites.ts';

const SB = 'https://abcdefghijklmnopqrst.supabase.co';
const URL_ = 'https://app.example.com/';
const SECRET = 'Zaphod-Beeblebrox-' + '4711';
const html = `<!doctype html><html><head><script type="module" src="/assets/index-Ab12Cd34.js"></script></head><body></body></html>`;

const CODE = `const supabase=c("${SB}","${FAKE.anon}");
supabase.functions.invoke("chat", { body: { q } });
supabase.functions.invoke("summarize-doc", { body: { text } });
supabase.functions.invoke("helper", { body: { model: "gpt-4o-mini", messages } });
supabase.functions.invoke("public-feed", { body: {} });
supabase.functions.invoke("delete-chat", { body: {} });`;

const fn = (name: string) => `${SB}/functions/v1/${name}`;
const site = (extra: Record<string, object>) =>
  ({
    [URL_]: { headers: { 'content-type': 'text/html' }, body: html },
    'https://app.example.com/assets/index-Ab12Cd34.js': { body: CODE },
    ...extra,
  }) as Record<string, any>;

const plan = parsePlan({
  plan: 't',
  limits: { totalMs: 10000, requests: 60, browser: false },
  modules: ['collect.page', 'collect.bundles', 'endpoints.discovered', 'ai.edge-function-open'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const run = (s: Record<string, any>, own = true) => runOn(s, URL_, plan, { modules: [...MODULES], ownershipVerified: own });

const RESPONSES = {
  [fn('chat')]: { status: 401, body: '{"msg":"unauthorized"}' },
  [fn('summarize-doc')]: { status: 400, headers: { 'content-type': 'application/json' }, body: `{"error":"Unexpected end of JSON input","echo":"${SECRET}"}` },
  [fn('helper')]: { status: 200, body: `{"answer":"${SECRET}"}` },
};

test('ai.edge-function-open: protected, open via parse error, 200 accepted; non-LLM and destructive ignored', async () => {
  const { result, http } = await run(site(RESPONSES));
  const posted = http.requests.filter((r) => r.method === 'POST').map((r) => r.url).sort();
  assert.deepEqual(posted, [fn('chat'), fn('helper'), fn('summarize-doc')]);

  const fs = result.findings.filter((f) => f.module === 'ai.edge-function-open');
  const by = Object.fromEntries(fs.map((f) => [f.vars!['name'], f]));
  assert.equal(fs.length, 2);
  assert.equal(by['summarize-doc']!.severity, 'high');
  assert.equal(by['summarize-doc']!.confidence, 'likely');
  assert.equal(by['summarize-doc']!.evidence, 'summarize-doc: HTTP 400');
  assert.equal(by['helper']!.confidence, 'possible');
  assert.equal(by['helper']!.evidence, 'helper: HTTP 200');
  assert.ok(!by['chat']);
  assert.deepEqual(result.facts['ai.edge-function-open'], { checked: 3, open: 2, protected: 1 });
  assert.ok(!JSON.stringify(result).includes(SECRET), 'no response body content in the result');
});

test('ai.edge-function-open: exactly one POST per function, body "{", public key only, no cookies, no redirects', async () => {
  const { http } = await run(site(RESPONSES));
  const reqs = http.requests.filter((r) => r.url.includes('/functions/v1/'));
  assert.equal(reqs.length, 3);
  for (const r of reqs) {
    assert.equal(r.method, 'POST');
    assert.equal(r.body, '{');
    assert.equal(r.followRedirects, false);
    assert.equal(r.headers!['content-type'], 'application/json');
    assert.equal(r.headers!['apikey'], FAKE.anon);
    assert.equal(r.headers!['Authorization'], `Bearer ${FAKE.anon}`);
    assert.ok(!Object.keys(r.headers!).some((k) => k.toLowerCase() === 'cookie'));
  }
});

test('ai.edge-function-open: 500 counts only with a parse error, 404 is nothing', async () => {
  const { result } = await run(
    site({
      [fn('chat')]: { status: 500, body: 'SyntaxError: Unexpected end of JSON input' },
      [fn('summarize-doc')]: { status: 500, body: 'upstream timeout' },
    }),
  );
  const fs = result.findings.filter((f) => f.module === 'ai.edge-function-open');
  assert.deepEqual(fs.map((f) => f.vars!['name']), ['chat']);
  assert.deepEqual(result.facts['ai.edge-function-open'], { checked: 3, open: 1, protected: 0 });
});

test('ai.edge-function-open: without ownership nothing is sent', async () => {
  const { result, http } = await run(site(RESPONSES), false);
  assert.ok(result.notChecked.some((n) => n.module === 'ai.edge-function-open' && n.reason === 'ownership'));
  assert.equal(http.requests.filter((r) => r.method === 'POST' || r.url.includes('/functions/v1/')).length, 0);
  assert.equal(result.findings.filter((f) => f.module === 'ai.edge-function-open').length, 0);
});
