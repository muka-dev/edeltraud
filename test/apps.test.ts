import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { boltFirebase, nextjsVercel, cursorPlainHttp, hardenedLovable, truncatedBigApp } from './fixtures/apps.ts';
import { FAKE } from './fixtures/sites.ts';

const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id).sort();
const RAW = [FAKE.openai, FAKE.anthropic, FAKE.stripeLive, FAKE.github, FAKE.serviceRole, FAKE.googleGemini, FAKE.googleFirebase];
const stack = (r: { facts: Record<string, unknown> }) => r.facts['stack'] as string[];

function noRawKeys(result: unknown) {
  const json = JSON.stringify(result);
  for (const k of RAW) assert.ok(!json.includes(k), 'raw key leaked into result');
}

for (const plan of ['ampel', 'report'] as const) {
  test(`boltFirebase (${plan}): Firebase web key is public, Gemini key is critical`, async () => {
    const { result } = await runOn(boltFirebase(), 'https://recipes.example.com/', plan);
    assert.deepEqual(ids(result), [
      'ai.client-llm-call/direct-call',
      'firebase.config/detected',
      'headers.security/csp-missing',
      'secrets.frontend/gemini-key',
    ]);
    const gem = result.findings.find((f) => f.id === 'secrets.frontend/gemini-key')!;
    assert.equal(gem.severity, 'critical');
    assert.equal(result.verdict.light, 'red');
    assert.ok(stack(result).includes('Firebase') && stack(result).includes('Vite') && stack(result).includes('Bolt'));
    assert.equal(result.facts['firebase.projectId'], 'recipe-buddy');
    noRawKeys(result);
  });

  test(`nextjsVercel (${plan}): Stripe secret found, publishable key not`, async () => {
    const { result } = await runOn(nextjsVercel(), 'https://shop.example.com/', plan);
    assert.deepEqual(ids(result), [
      'cookies.flags/cookie-flags',
      'headers.security/csp-missing',
      'headers.security/frame-missing',
      'headers.security/permissions-missing',
      'secrets.frontend/stripe-secret',
    ]);
    assert.equal(result.findings.find((f) => f.id === 'secrets.frontend/stripe-secret')!.severity, 'critical');
    assert.equal(result.findings.find((f) => f.id === 'cookies.flags/cookie-flags')!.vars?.missing, 'HttpOnly');
    assert.equal(result.verdict.light, 'red');
    assert.equal(result.facts['stack.nextjs'], true);
    assert.equal(result.facts['host.vercel'], true);
    assert.equal(result.facts['stack.stripe'], true);
    noRawKeys(result);
  });

  test(`cursorPlainHttp (${plan}): http-only and inline GitHub token`, async () => {
    const { result } = await runOn(cursorPlainHttp(), 'https://board.example.com/', plan);
    assert.deepEqual(ids(result), [
      'cookies.flags/cookie-flags',
      'headers.security/csp-missing',
      'headers.security/frame-missing',
      'headers.security/nosniff-missing',
      'headers.security/permissions-missing',
      'headers.security/referrer-missing',
      'secrets.frontend/github-token',
      'tls.basics/http-only',
      'tls.basics/no-redirect',
    ]);
    assert.equal(result.findings.find((f) => f.id === 'tls.basics/http-only')!.severity, 'high');
    assert.equal(result.verdict.light, 'red');
    noRawKeys(result);
  });

  test(`hardenedLovable (${plan}): green apart from supabase.config`, async () => {
    const { result } = await runOn(hardenedLovable(), 'https://secure.example.com/', plan);
    assert.deepEqual(ids(result), ['supabase.config/detected']);
    assert.equal(result.verdict.light, 'green');
    assert.equal(result.complete, true);
    assert.ok(stack(result).includes('Lovable') && stack(result).includes('Supabase'));
    noRawKeys(result);
  });
}

test('stack detection: Stripe pk_live key is not mistaken for Clerk', async () => {
  const { result } = await runOn(nextjsVercel(), 'https://shop.example.com/', 'ampel');
  assert.ok(!stack(result).includes('Clerk'), 'Clerk reported for a Stripe key');
});

test('truncatedBigApp (ampel): bundle limit gives a budget notChecked, verdict still works', async () => {
  const { result, http } = await runOn(truncatedBigApp(), 'https://big.example.com/', 'ampel');
  const bundleFetches = http.log.filter((l) => /\/assets\/chunk-\d+[^ ]*\.js$/.test(l));
  assert.equal(bundleFetches.length, 5);
  const nc = result.notChecked.filter((n) => n.module === 'collect.bundles');
  assert.equal(nc.length, 1);
  assert.equal(nc[0]!.reason, 'budget');
  assert.match(nc[0]!.detail ?? '', /^7 further scripts/);
  // key in chunk 3 is seen, key in chunk 9 is not loaded
  assert.deepEqual(ids(result), ['secrets.frontend/openai-key']);
  assert.equal(result.verdict.light, 'red');
  noRawKeys(result);
});

test('truncatedBigApp (ampel): a scan cut short by the bundle limit is not complete', async () => {
  const { result } = await runOn(truncatedBigApp(), 'https://big.example.com/', 'ampel');
  assert.equal(result.complete, false);
});

test('truncatedBigApp (report): all 12 scripts loaded, no budget entry', async () => {
  const { result } = await runOn(truncatedBigApp(), 'https://big.example.com/', 'report');
  assert.ok(!result.notChecked.some((n) => n.module === 'collect.bundles'));
  assert.deepEqual(ids(result), ['secrets.frontend/anthropic-key', 'secrets.frontend/openai-key']);
  assert.equal(result.verdict.light, 'red');
  noRawKeys(result);
});
