import { test } from 'node:test';
import assert from 'node:assert/strict';
import { issueToken, checkToken, verifyOwnership, covers, OwnershipError, TOKEN_TTL_MS } from '../src/ownership/ownership.ts';
import { ReplayDns } from '../src/fetch/dns.ts';
import { ReplayHttp } from '../src/fetch/replay.ts';

const SECRET = 'x'.repeat(32);
const NOW = Date.parse('2026-11-20T12:00:00Z');

test('tokens are bound to host and account and expire', () => {
  const { token, dns, file } = issueToken(SECRET, 'App.Example.com', 'acc-1', NOW);
  assert.deepEqual(dns.map((d) => d.name), ['_edeltraud.app.example.com', 'example.com']);
  assert.equal(file.url, `https://app.example.com/.well-known/edeltraud-${token}.txt`);
  checkToken(SECRET, 'app.example.com', 'acc-1', token, NOW);
  assert.throws(() => checkToken(SECRET, 'other.example.com', 'acc-1', token, NOW), OwnershipError);
  assert.throws(() => checkToken(SECRET, 'app.example.com', 'acc-2', token, NOW), OwnershipError);
  assert.throws(() => checkToken('y'.repeat(32), 'app.example.com', 'acc-1', token, NOW), OwnershipError);
  assert.throws(() => checkToken(SECRET, 'app.example.com', 'acc-1', token, NOW + TOKEN_TTL_MS + 1), /expired/);
  assert.throws(() => checkToken(SECRET, 'app.example.com', 'acc-1', 'nonsense', NOW), /malformed/);
  assert.throws(() => issueToken('short', 'a.example.com', 'x'), /secret/);
});

test('verification via DNS on the host, on the domain (covers subdomains), or via file', async () => {
  const { token } = issueToken(SECRET, 'app.example.com', 'acc', NOW);
  const v = `edeltraud-verify=${token}`;
  const a = await verifyOwnership({ secret: SECRET, host: 'app.example.com', account: 'acc', token, now: NOW, dns: new ReplayDns({ '_edeltraud.app.example.com TXT': [v] }) });
  assert.equal(a.scope, 'host');
  assert.ok(covers(a, 'app.example.com', NOW) && !covers(a, 'other.example.com', NOW));

  const b = await verifyOwnership({ secret: SECRET, host: 'app.example.com', account: 'acc', token, now: NOW, dns: new ReplayDns({ 'example.com TXT': ['v=spf1 -all', v] }) });
  assert.equal(b.scope, 'domain');
  assert.ok(covers(b, 'shop.example.com', NOW) && covers(b, 'example.com', NOW) && !covers(b, 'example.org', NOW));
  assert.ok(!covers(b, 'shop.example.com', NOW + 31 * 86_400_000), 'verification expires after 30 days');

  const url = `https://app.example.com/.well-known/edeltraud-${token}.txt`;
  const c = await verifyOwnership({ secret: SECRET, host: 'app.example.com', account: 'acc', token, now: NOW, dns: new ReplayDns({}), http: new ReplayHttp({ [url]: { body: `${token}\n` } }) });
  assert.equal(c.method, 'file');
});

test('verification fails for wrong content, foreign redirects and missing tokens', async () => {
  const { token } = issueToken(SECRET, 'app.example.com', 'acc', NOW);
  const url = `https://app.example.com/.well-known/edeltraud-${token}.txt`;
  const run = (site: Record<string, object>) =>
    verifyOwnership({ secret: SECRET, host: 'app.example.com', account: 'acc', token, now: NOW, dns: new ReplayDns({}), http: new ReplayHttp(site) });
  await assert.rejects(run({}), /not found/);
  // SPA fallback: index.html with 200 is not proof
  await assert.rejects(run({ [url]: { body: '<html>app</html>' } }), /not found/);
  // redirect to another host that serves the token is not proof for this host
  await assert.rejects(run({ [url]: { redirect: 'https://attacker.example.net/t.txt' }, 'https://attacker.example.net/t.txt': { body: token } }), /not found/);
});
