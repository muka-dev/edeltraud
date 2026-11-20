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
  await withApi({ http, perIp: { limit: 2, windowMs: 60_000 } }, async (base) => {
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
  await withApi({ http: new ReplayHttp({}) }, async (base) => {
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
