import { test } from 'node:test';
import assert from 'node:assert/strict';
import type { AddressInfo } from 'node:net';
import { createApi } from '../src/api/server.ts';
import { ReplayHttp } from '../src/fetch/replay.ts';
import { vulnerableSite } from './fixtures/sites.ts';

async function withApi(opts: Parameters<typeof createApi>[0], fn: (base: string) => Promise<void>) {
  const server = createApi(opts).listen(0);
  await new Promise((r) => server.once('listening', r));
  try {
    await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`);
  } finally {
    server.close();
  }
}

const post = (base: string, body: unknown, headers: Record<string, string> = {}) =>
  fetch(`${base}/v1/scan`, { method: 'POST', headers: { 'content-type': 'application/json', ...headers }, body: JSON.stringify(body) });

test('scan, CORS, cache and per-IP rate limit', async () => {
  const http = new ReplayHttp(vulnerableSite());
  await withApi({ http, pow: false, perIp: { limit: 2, windowMs: 60_000 } }, async (base) => {
    const r1 = await post(base, { url: 'vibe.example.com', lang: 'en' }, { origin: 'https://m-ko.de' });
    assert.equal(r1.status, 200);
    assert.equal(r1.headers.get('access-control-allow-origin'), 'https://m-ko.de');
    const p = await r1.json();
    assert.equal(p.light, 'red');
    assert.equal(p.findings.length, 3);
    assert.equal(p.lang, 'en');

    const calls = http.log.length;
    const r2 = await post(base, { url: 'https://vibe.example.com/' });
    assert.equal(r2.status, 200);
    assert.equal(http.log.length, calls, 'second scan served from cache');

    assert.equal((await post(base, { url: 'other1.example.com' })).status, 200);
    const r4 = await post(base, { url: 'other2.example.com' });
    assert.equal(r4.status, 429);
    assert.ok(Number(r4.headers.get('retry-after')) > 0);
  });
});

test('rejects internal targets, bad input and foreign origins', async () => {
  await withApi({ http: new ReplayHttp({}), pow: false }, async (base) => {
    assert.equal((await post(base, { url: 'http://169.254.169.254/latest/meta-data' })).status, 400);
    assert.equal((await post(base, { url: 'localhost' })).status, 400);
    assert.equal((await post(base, { nope: 1 })).status, 400);
    const r = await fetch(`${base}/v1/scan`, { method: 'POST', body: 'x' });
    assert.equal(r.status, 400);
    const foreign = await post(base, { url: 'a.example.com' }, { origin: 'https://evil.example' });
    assert.equal(foreign.headers.get('access-control-allow-origin'), null);
    assert.equal((await fetch(`${base}/health`)).status, 200);
  });
});

import { mkdtempSync, writeFileSync, mkdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { ProofOfWork, solve, leadingZeroBits } from '../src/api/pow.ts';
import { clientKey } from '../src/api/ratelimit.ts';

const solved = async (base: string) => {
  const c = await (await fetch(`${base}/v1/challenge`)).json();
  return { salt: c.salt, nonce: solve(c), expires: c.expires, signature: c.signature };
};

test('proof of work: required, single use, tamper-proof', async () => {
  await withApi({ http: new ReplayHttp(vulnerableSite()), pow: { difficulty: 8 } }, async (base) => {
    assert.equal((await (await post(base, { url: 'vibe.example.com' })).json()).error, 'pow_required');
    const s = await solved(base);
    assert.equal((await post(base, { url: 'vibe.example.com', pow: { ...s, nonce: s.nonce + 1e9 } })).status, 400);
    assert.equal((await (await post(base, { url: 'vibe.example.com', pow: { ...s, expires: s.expires + 1 } })).json()).error, 'pow_invalid');
    const ok = await post(base, { url: 'vibe.example.com', pow: s });
    assert.equal(ok.status, 200);
    assert.equal((await ok.json()).cached, false);
    assert.equal((await (await post(base, { url: 'vibe.example.com', pow: s })).json()).error, 'pow_used');
    const again = await post(base, { url: 'vibe.example.com', pow: await solved(base) });
    assert.equal((await again.json()).cached, true);
  });
});

test('proof of work: expiry and difficulty', () => {
  let t = 1_000;
  const pow = new ProofOfWork({ difficulty: 10, ttlMs: 100, now: () => t });
  const c = pow.issue();
  assert.equal(c.difficulty, 10);
  const sol = { salt: c.salt, nonce: solve(c), expires: c.expires, signature: c.signature };
  t = 2_000;
  assert.equal(pow.verify(sol), 'pow_expired');
  assert.equal(leadingZeroBits(new Uint8Array([0, 0x10])), 11);
  assert.equal(leadingZeroBits(new Uint8Array([0x80])), 0);
});

test('client key: IPv4 as is, IPv6 by /64, mapped IPv4 as IPv4', () => {
  assert.equal(clientKey('203.0.113.7'), '203.0.113.7');
  assert.equal(clientKey('::ffff:203.0.113.7'), '203.0.113.7');
  assert.equal(clientKey('2001:db8:1:2:aaaa::1'), '2001:db8:1:2::/64');
  assert.equal(clientKey('2001:db8:1:2:ffff:ffff:ffff:ffff'), '2001:db8:1:2::/64');
  assert.equal(clientKey('2001:db8::1'), '2001:db8:0:0::/64');
});

test('limits: per domain across subdomains, global cap, busy, opt-out', async () => {
  const sites = { ...vulnerableSite() };
  for (const h of ['a', 'b', 'c']) sites[`https://${h}.example.org/`] = { body: '<html></html>' };
  await withApi({ http: new ReplayHttp(sites), pow: false, perIp: [{ limit: 100, windowMs: 60_000 }], perTarget: { limit: 2, windowMs: 60_000 }, blockedDomains: ['optout.example'] }, async (base) => {
    assert.equal((await post(base, { url: 'a.example.org' })).status, 200);
    assert.equal((await post(base, { url: 'b.example.org' })).status, 200);
    const r = await post(base, { url: 'c.example.org' });
    assert.equal(r.status, 429);
    assert.equal((await r.json()).scope, 'target');
    assert.equal((await post(base, { url: 'www.optout.example' })).status, 403);
  });
  await withApi({ http: new ReplayHttp(sites), pow: false, global: { limit: 1, windowMs: 60_000 } }, async (base) => {
    assert.equal((await post(base, { url: 'a.example.org' })).status, 200);
    const r = await post(base, { url: 'b.example.org' });
    assert.equal((await r.json()).scope, 'global');
  });
  // A slow target keeps the only slot busy; the second scan is refused without using quota.
  let release!: () => void;
  const slow = { fetch: () => new Promise<never>((_, rej) => { release = () => rej(new Error('closed')); }) };
  await withApi({ http: slow, pow: false, maxConcurrent: 1 }, async (base) => {
    const first = post(base, { url: 'slow.example.org' });
    await new Promise((r) => setTimeout(r, 50));
    const busy = await post(base, { url: 'other.example.org' });
    assert.equal(busy.status, 503);
    assert.equal(busy.headers.get('retry-after'), '10');
    release();
    await first;
  });
});

test('static page: served with strict CSP, no traversal, no dotfiles', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'web-'));
  mkdirSync(join(dir, 'assets'));
  writeFileSync(join(dir, 'index.html'), '<!doctype html><title>Ampel</title>');
  writeFileSync(join(dir, 'assets', 'app.js'), 'x');
  writeFileSync(join(dir, '.env'), 'SECRET=1');
  await withApi({ http: new ReplayHttp({}), webDir: dir }, async (base) => {
    const r = await fetch(`${base}/`);
    assert.equal(r.status, 200);
    assert.match(r.headers.get('content-security-policy') ?? '', /script-src 'self'/);
    assert.equal(r.headers.get('x-frame-options'), 'DENY');
    assert.equal((await fetch(`${base}/assets/app.js`)).headers.get('content-type'), 'text/javascript; charset=utf-8');
    assert.equal((await fetch(`${base}/.env`)).status, 404);
    assert.equal((await fetch(`${base}/assets/%2e%2e/%2e%2e/package.json`)).status, 404);
    assert.equal((await fetch(`${base}/../package.json`)).status, 404);
  });
});

test('behind the proxy, a forged X-Forwarded-For entry does not dodge the limit', async () => {
  await withApi({ http: new ReplayHttp(vulnerableSite()), pow: false, trustProxy: true, perIp: { limit: 1, windowMs: 60_000 } }, async (base) => {
    const h = (forged: string) => ({ 'x-forwarded-for': `${forged}, 198.51.100.9` });
    assert.equal((await post(base, { url: 'a1.example.net' }, h('1.1.1.1'))).status, 200);
    assert.equal((await post(base, { url: 'a2.example.net' }, h('2.2.2.2'))).status, 429);
  });
});

test('commerce routes: checkout validates input, webhook gets the raw body, ownership page', async () => {
  const calls: unknown[] = [];
  const commerce = {
    checkout: async (i: unknown) => (calls.push(i), { checkoutUrl: 'https://sandbox-pay.example/checkout?_ptxn=txn_1' }),
    webhook: async (raw: Buffer, sig: string | undefined) => (calls.push({ raw: raw.toString(), sig }), sig === 'ts=1;h1=ok' ? 200 : 400),
    ownership: async (m: 'GET' | 'POST', job: string) => ({ status: 200, html: `<p>${m} ${job}</p>` }),
  };
  await withApi({ http: new ReplayHttp({}), pow: false, webDir: null, commerce }, async (base) => {
    const ok = await fetch(`${base}/v1/checkout`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'app.example.com', product: 'report', lang: 'en' }) });
    assert.equal(ok.status, 200);
    assert.match((await ok.json()).checkoutUrl, /^https:/);
    assert.deepEqual(calls[0], { url: 'https://app.example.com/', product: 'report', lang: 'en' });
    const bad = await fetch(`${base}/v1/checkout`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'app.example.com', product: 'everything' }) });
    assert.equal(bad.status, 400);
    const internal = await fetch(`${base}/v1/checkout`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ url: 'http://10.0.0.1', product: 'report' }) });
    assert.equal(internal.status, 400);
    const body = '{"event_id":"evt_1"}';
    assert.equal((await fetch(`${base}/v1/paddle/webhook`, { method: 'POST', headers: { 'paddle-signature': 'ts=1;h1=ok' }, body })).status, 200);
    assert.deepEqual(calls[1], { raw: body, sig: 'ts=1;h1=ok' });
    assert.equal((await fetch(`${base}/v1/paddle/webhook`, { method: 'POST', body })).status, 400);
    const page = await fetch(`${base}/v1/ownership/check?job=abc&sig=x`);
    assert.equal(await page.text(), '<p>GET abc</p>');
    assert.match(page.headers.get('content-security-policy') ?? '', /default-src 'none'/);
  });
});

test('payment page: only /pay may load Paddle.js; config only when payment is set up', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'web-'));
  writeFileSync(join(dir, 'index.html'), '<!doctype html>');
  writeFileSync(join(dir, 'pay.html'), '<!doctype html>');
  await withApi({ http: new ReplayHttp({}), webDir: dir, payConfig: { clientToken: 'test_abc', environment: 'sandbox' } }, async (base) => {
    const pay = await fetch(`${base}/pay?_ptxn=txn_01abc`);
    assert.equal(pay.status, 200);
    assert.match(pay.headers.get('content-security-policy') ?? '', /script-src 'self' https:\/\/cdn\.paddle\.com/);
    assert.match(pay.headers.get('content-security-policy') ?? '', /frame-ancestors 'none'/);
    assert.doesNotMatch((await fetch(`${base}/`)).headers.get('content-security-policy') ?? '', /paddle/);
    assert.deepEqual(await (await fetch(`${base}/v1/pay/config`)).json(), { clientToken: 'test_abc', environment: 'sandbox' });
  });
  await withApi({ http: new ReplayHttp({}), webDir: dir }, async (base) => {
    assert.equal((await fetch(`${base}/v1/pay/config`)).status, 404);
  });
});

test('static page: PNG (link preview image) is served with its type', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'web-'));
  writeFileSync(join(dir, 'index.html'), '<!doctype html>');
  writeFileSync(join(dir, 'og.png'), Buffer.from([0x89, 0x50, 0x4e, 0x47]));
  await withApi({ http: new ReplayHttp({}), webDir: dir }, async (base) => {
    const r = await fetch(`${base}/og.png`);
    assert.equal(r.status, 200);
    assert.equal(r.headers.get('content-type'), 'image/png');
    const head = await fetch(`${base}/og.png`, { method: 'HEAD' });
    assert.equal(head.status, 200);
    assert.equal(head.headers.get('content-length'), '4');
    assert.equal((await fetch(`${base}/`, { method: 'HEAD' })).status, 200);
  });
});
