import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { CANDIDATES } from '../src/modules/probe/paths.ts';
import { takeoverTarget } from '../src/modules/analyze/dangling.ts';

const plan = parsePlan({
  plan: 't', limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.dns', 'paths.sensitive', 'dns.dangling'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const modules = [...MODULES];
const O = 'https://app.example.com';
const html = (body: string, extra: Record<string, string> = {}) => ({ headers: { 'content-type': 'text/html', ...extra }, body });
const base = (): Record<string, any> => ({ [O + '/']: html('<html><body>app</body></html>'), 'http://app.example.com/': { redirect: O + '/' } });
const run = (site: any, o: { verified?: boolean; dns?: any } = {}) =>
  runOn(site, O + '/', plan, { modules, ownershipVerified: o.verified ?? true, ...(o.dns ? { dns: o.dns } : {}) });
const ids = (r: any, p: string) => r.result.findings.filter((f: any) => f.module === p).map((f: any) => f.id.split('/')[1] + ':' + (f.vars?.path ?? '')).sort();

const SECRET_VALUE = 'sk_live_' + 'Zx9'.repeat(8);
const DB_VALUE = 'postgres://u:' + 'pw'.repeat(5) + '@db.example.com/x';

test('paths: real .env reports only key names', async () => {
  const site = base();
  site[O + '/.env'] = { headers: { 'content-type': 'application/octet-stream' }, body: `# config\nSUPABASE_SERVICE_ROLE_KEY=${SECRET_VALUE}\nSTRIPE_SECRET_KEY=${SECRET_VALUE}\nDATABASE_URL=${DB_VALUE}\n` };
  const r = await run(site);
  const f = r.result.findings.filter((x: any) => x.module === 'paths.sensitive');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.id, 'paths.sensitive/env-exposed');
  assert.equal(f[0]!.severity, 'critical');
  assert.equal(f[0]!.evidence, 'SUPABASE_SERVICE_ROLE_KEY, STRIPE_SECRET_KEY, DATABASE_URL');
  const dump = JSON.stringify(r.result);
  assert.ok(!dump.includes(SECRET_VALUE) && !dump.includes(DB_VALUE) && !dump.includes('pwpwpw'));
});

test('paths: SPA fallback for every path gives no findings', async () => {
  const site = base();
  const spa = html('<html><body>' + '<!--x-->'.repeat(20) + 'app</body></html>');
  for (const p of ['/edeltraud-404-baseline', ...CANDIDATES.map((c) => c.path)]) site[O + p] = spa;
  const r = await run(site);
  assert.deepEqual(ids(r, 'paths.sensitive'), []);
});

test('paths: SPA fallback that happens to contain a dashboard word is not an admin finding', async () => {
  const site = base();
  const spa = html('<html><body>Dashboard</body></html>');
  site[O + '/edeltraud-404-baseline'] = spa;
  site[O + '/admin'] = spa;
  assert.deepEqual(ids(await run(site), 'paths.sensitive'), []);
  // no baseline match and no password input -> low
  const s2 = base();
  s2[O + '/admin'] = html('<html><body><h1>Dashboard</h1></body></html>');
  assert.deepEqual(ids(await run(s2), 'paths.sensitive'), ['admin-open:/admin']);
  const s3 = base();
  s3[O + '/admin'] = html('<html><body>Dashboard <input type="password"></body></html>');
  assert.deepEqual(ids(await run(s3), 'paths.sensitive'), []);
});

test('paths: git, phpinfo, backups via HEAD, docker-compose, npmrc', async () => {
  const site = base();
  site[O + '/.git/config'] = { headers: { 'content-type': 'text/plain' }, body: '[core]\n\trepositoryformatversion = 0\n' };
  site[O + '/.git/HEAD'] = { body: 'ref: refs/heads/main\n' };
  site[O + '/phpinfo.php'] = html('<html><title>phpinfo()</title>PHP Version 8.2</html>');
  site[O + '/backup.zip'] = { headers: { 'content-type': 'application/zip', 'content-length': '123456' } };
  site[O + '/db.sql'] = { headers: { 'content-type': 'text/html', 'content-length': '500' } }; // html: ignored
  site[O + '/docker-compose.yml'] = { headers: { 'content-type': 'text/yaml' }, body: 'version: "3"\nservices:\n  web:\n    image: x\n' };
  site[O + '/.npmrc'] = { headers: { 'content-type': 'text/plain' }, body: `_authToken=${SECRET_VALUE}\n` };
  const r = await run(site);
  assert.deepEqual(ids(r, 'paths.sensitive'), [
    'backup-exposed:/backup.zip', 'env-exposed:/.npmrc', 'git-exposed:/.git/HEAD', 'git-exposed:/.git/config', 'info-exposed:/docker-compose.yml', 'info-exposed:/phpinfo.php',
  ]);
  const bk = r.result.findings.find((x: any) => x.id === 'paths.sensitive/backup-exposed');
  assert.equal(bk!.vars!.size, '123456');
  assert.equal(bk!.severity, 'high');
  assert.ok(!JSON.stringify(r.result).includes(SECRET_VALUE));
  assert.ok(r.http.log.includes(`HEAD ${O}/backup.zip`));
  assert.ok(r.http.log.every((l: string) => /^(GET|HEAD) /.test(l)));
});

test('paths: 404 and non-matching content give nothing', async () => {
  const site = base();
  site[O + '/.env'] = { body: 'just one line\nKEY=value' };
  site[O + '/.git/config'] = { body: 'not a git config' };
  site[O + '/server-status'] = { status: 403, body: 'Apache Server Status' };
  assert.deepEqual(ids(await run(site), 'paths.sensitive'), []);
});

test('paths: without ownership no request and notChecked ownership', async () => {
  const site = base();
  site[O + '/.env'] = { body: 'A_KEY=1\nB_KEY=2\n' };
  const r = await run(site, { verified: false });
  assert.ok(r.result.notChecked.some((n: any) => n.module === 'paths.sensitive' && n.reason === 'ownership'));
  assert.ok(!r.http.log.some((l: string) => l.includes('/.env') || l.includes('baseline')));
  assert.deepEqual(ids(r, 'paths.sensitive'), []);
});

test('takeoverTarget', () => {
  assert.equal(takeoverTarget(['Old-App.herokuapp.com.']), 'old-app.herokuapp.com');
  assert.equal(takeoverTarget(['x.s3.eu-west-1.amazonaws.com']), 'x.s3.eu-west-1.amazonaws.com');
  assert.equal(takeoverTarget(['cdn.example.net']), null);
  assert.equal(takeoverTarget(['notherokuapp.com']), null);
});

test('dns.dangling: CNAME to herokuapp without A record', async () => {
  const r = await run(base(), { dns: { 'app.example.com CNAME': ['old-app.herokuapp.com'] } });
  const f = r.result.findings.filter((x: any) => x.module === 'dns.dangling');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.severity, 'high');
  assert.deepEqual(f[0]!.vars, { host: 'app.example.com', target: 'old-app.herokuapp.com' });
});

test('dns.dangling: healthy CNAME with A record, unknown target, failed A query -> nothing', async () => {
  const healthy = await run(base(), { dns: { 'app.example.com CNAME': ['old-app.herokuapp.com'], 'app.example.com A': ['1.2.3.4'] } });
  assert.deepEqual(ids(healthy, 'dns.dangling'), []);
  const other = await run(base(), { dns: { 'app.example.com CNAME': ['lb.example.net'] } });
  assert.deepEqual(ids(other, 'dns.dangling'), []);
  const failed = await run(base(), { dns: { 'app.example.com CNAME': ['old-app.herokuapp.com'], 'app.example.com A': 'SERVFAIL' } });
  assert.deepEqual(ids(failed, 'dns.dangling'), []);
  const none = await run(base());
  assert.deepEqual(ids(none, 'dns.dangling'), []);
});
