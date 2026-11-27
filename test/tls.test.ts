import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import tls from 'node:tls';
import { runOn } from './helpers.ts';
import { cleanSite } from './fixtures/sites.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { LiveTls } from '../src/fetch/tls.ts';

const plan = parsePlan({
  plan: 't',
  limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.tls', 'tls.basics'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const DAY = 86_400_000;
const CHECKED = Date.parse('2026-11-20T12:00:00.000Z');
const at = (ms: number) => new Date(ms).toISOString();

async function scan(tlsFix: Record<string, unknown> | null, url = 'https://clean.example.com/') {
  const { result } = await runOn(cleanSite(), url, plan, {
    modules: [...MODULES],
    ...(tlsFix ? { tls: { 'clean.example.com': tlsFix as any } } : {}),
  });
  return result;
}
const ids = (r: { findings: { id: string; severity: string }[] }) => r.findings.filter((f) => f.id.startsWith('tls.basics/')).map((f) => `${f.id}:${f.severity}`);

test('cert-expiring: 90-day cert with 40/10/3 days left', async () => {
  const mk = (left: number) => ({ validFrom: at(CHECKED + left * DAY - 90 * DAY), validTo: at(CHECKED + left * DAY) });
  assert.deepEqual(ids(await scan(mk(40))), []);
  assert.deepEqual(ids(await scan(mk(10))), ['tls.basics/cert-expiring:medium']);
  assert.deepEqual(ids(await scan(mk(3))), ['tls.basics/cert-expiring:high']);
  const r = await scan(mk(10));
  const f = r.findings.find((x) => x.id === 'tls.basics/cert-expiring')!;
  assert.equal(f.vars?.['days'], '10');
  assert.equal(f.vars?.['date'], at(CHECKED + 10 * DAY).slice(0, 10));
});

test('cert-expiring: short-lived 6-day cert with 2 days left stays quiet; expired is not reported here', async () => {
  assert.deepEqual(ids(await scan({ validFrom: at(CHECKED - 4 * DAY), validTo: at(CHECKED + 2 * DAY) })), []);
  assert.deepEqual(ids(await scan({ validFrom: at(CHECKED - 100 * DAY), validTo: at(CHECKED - DAY) })), []);
});

test('legacy-protocol: reported only when accepted', async () => {
  assert.deepEqual(ids(await scan({ legacy: { 'TLSv1': true, 'TLSv1.1': false } })), ['tls.basics/legacy-protocol:low']);
  assert.deepEqual(ids(await scan({ legacy: { 'TLSv1': false, 'TLSv1.1': false } })), []);
});

test('collect.tls: unsupported without inspector, condition for http, error for unknown host', async () => {
  const none = await scan(null);
  assert.ok(none.notChecked.some((n) => n.module === 'collect.tls' && n.reason === 'unsupported'));
  const http = await scan({}, 'http://clean.example.com/');
  assert.ok(http.notChecked.some((n) => n.module === 'collect.tls' && n.reason === 'condition'));
  const { result } = await runOn(cleanSite(), 'https://clean.example.com/', plan, { tls: { 'other.example.com': {} } });
  assert.ok(result.notChecked.some((n) => n.module === 'collect.tls' && n.reason === 'error'));
});

test('LiveTls against a local server', async (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'tls-test-'));
  let key: string, cert: string;
  try {
    execFileSync('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', join(dir, 'k.pem'), '-out', join(dir, 'c.pem'), '-days', '7', '-subj', '/CN=localhost/O=Test Org', '-addext', 'subjectAltName=DNS:localhost'], { stdio: 'ignore' });
    key = readFileSync(join(dir, 'k.pem'), 'utf8');
    cert = readFileSync(join(dir, 'c.pem'), 'utf8');
  } catch {
    rmSync(dir, { recursive: true, force: true });
    return t.skip('openssl unavailable');
  }
  const server = tls.createServer({ key, cert, minVersion: 'TLSv1.2' }, (s) => s.end());
  server.on('tlsClientError', () => {});
  await new Promise<void>((res) => server.listen(0, '127.0.0.1', res));
  const port = (server.address() as { port: number }).port;
  try {
    const live = new LiveTls({ lookup: (_h, o, cb) => ((o as any).all ? (cb as any)(null, [{ address: '127.0.0.1', family: 4 }]) : (cb as any)(null, '127.0.0.1', 4)) });
    const info = await live.inspect('localhost', { port, legacyProtocols: true });
    assert.equal(info.host, 'localhost');
    assert.equal(info.port, port);
    assert.equal(info.authorized, false);
    assert.ok(info.authorizationError);
    assert.equal(info.subject, 'localhost');
    assert.equal(info.issuer, 'Test Org');
    assert.deepEqual(info.altNames, ['localhost']);
    assert.match(info.protocol ?? '', /^TLSv1\.[23]$/);
    assert.ok(info.validFrom && info.validTo && Date.parse(info.validTo) > Date.parse(info.validFrom));
    assert.notEqual(info.legacy['TLSv1.1'], true);
    const fast = await live.inspect('localhost', { port, legacyProtocols: false });
    assert.deepEqual(fast.legacy, { 'TLSv1': null, 'TLSv1.1': null });
    // default lookup refuses loopback
    await assert.rejects(new LiveTls().inspect('localhost', { port }));
  } finally {
    server.close();
    rmSync(dir, { recursive: true, force: true });
  }
});
