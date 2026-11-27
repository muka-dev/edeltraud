import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { collectWellknown } from '../src/modules/collect/wellknown.ts';
import { securityTxt, robotsHints, stackGenerator, parseGenerators, compareVersions, parseRobots } from '../src/modules/analyze/wellknown.ts';

const plan = parsePlan({
  plan: 't', limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.wellknown', 'wellknown.securitytxt', 'wellknown.robots-hints', 'stack.generator'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const modules = [...MODULES];
const U = 'https://x.example.com/';
const DATE = 'Sat, 21 Nov 2026 10:00:00 GMT';
const html = (head = '') => ({ headers: { 'content-type': 'text/html', date: DATE }, body: `<!doctype html><html><head>${head}</head><body></body></html>` });
const txt = (body: string) => ({ headers: { 'content-type': 'text/plain' }, body });
const run = (site: any) => runOn({ [U]: html(), ...site }, U, plan, { modules });
const ids = (r: any, p: string) => r.result.findings.filter((f: any) => f.module === p).map((f: any) => f.id.split('/')[1]).sort();

// An SPA answers 200 with index.html on every path.
const spa = () => {
  const s: any = { [U]: html('<link rel="manifest" href="/m.json">') };
  for (const p of ['/.well-known/security.txt', '/security.txt', '/robots.txt', '/sitemap.xml', '/manifest.json', '/m.json']) s['https://x.example.com' + p] = html();
  return s;
};

test('SPA fallback does not count as security.txt / robots / sitemap / manifest', async () => {
  const r = await runOn(spa(), U, plan, { modules });
  assert.deepEqual(ids(r, 'wellknown.securitytxt'), ['securitytxt-missing']);
  assert.deepEqual(ids(r, 'wellknown.robots-hints'), []);
  assert.ok(!r.result.notChecked.some((n: any) => n.module === 'collect.wellknown'));
  // plain text 200 with HTML-free but directive-free body is also rejected
  const r2 = await run({ 'https://x.example.com/.well-known/security.txt': txt('Welcome to our site'), 'https://x.example.com/robots.txt': txt('hello') });
  assert.deepEqual(ids(r2, 'wellknown.securitytxt'), ['securitytxt-missing']);
});

test('real files are stored; fallback /security.txt used when .well-known is no real file', async () => {
  const site = {
    'https://x.example.com/.well-known/security.txt': html(),
    'https://x.example.com/security.txt': txt('Contact: mailto:sec@x.example.com\nExpires: 2027-06-01T00:00:00Z\n'),
    'https://x.example.com/robots.txt': txt('User-agent: *\nDisallow: /private-area\nSitemap: https://x.example.com/sitemap.xml'),
    'https://x.example.com/sitemap.xml': { headers: { 'content-type': 'application/xml' }, body: '<?xml version="1.0"?><urlset><url><loc>https://x.example.com/a</loc></url><url><loc>https://x.example.com/b/c</loc></url></urlset>' },
    'https://x.example.com/manifest.json': { headers: { 'content-type': 'application/manifest+json' }, body: '{"name":"X App","start_url":"/"}' },
  };
  const r = await run(site);
  assert.deepEqual(ids(r, 'wellknown.securitytxt'), []);
  const calls = (r as any).http.log as string[];
  assert.ok(calls.some((c) => c.endsWith('/security.txt') && !c.includes('well-known')));
  assert.ok(calls.length <= 1 + 5 + 1, `requests: ${calls.length}`);
});

test('collector output shape', async () => {
  const site: any = {
    'https://x.example.com/.well-known/security.txt': txt('Contact: mailto:a@b.c\nExpires: 2027-01-01T00:00:00Z'),
    'https://x.example.com/robots.txt': txt('User-agent: *\nDisallow:'),
    'https://x.example.com/sitemap.xml': { headers: { 'content-type': 'text/xml' }, body: `<urlset>${Array.from({ length: 30 }, (_, i) => `<url><loc>https://x.example.com/p${i}</loc></url>`).join('')}</urlset>` },
    [U]: html('<link rel="manifest" href="/site.webmanifest"><link rel="manifest" href="https://evil.example.org/m.json">'),
    'https://x.example.com/site.webmanifest': txt('{"name":"N","short_name":"n","display":"standalone"}'),
  };
  const { runPlan } = await import('../src/core/processor.ts');
  const { ReplayHttp } = await import('../src/fetch/replay.ts');
  const { createRegistry } = await import('../src/modules/index.ts');
  const http = new ReplayHttp(site);
  const out: any = await runPlan({ plan, target: { url: U, host: 'x.example.com', ownershipVerified: false }, registry: createRegistry(modules), http });
  const res = await collectWellknown.run({ target: out.result.target, artifacts: { get: () => undefined, list: () => [{ type: 'page', key: U, data: { finalUrl: U, headers: { date: DATE }, html: site[U].body } }] }, facts: { get: () => undefined, has: () => false }, http, log: { debug() {}, warn() {} }, signal: new AbortController().signal } as any, {});
  const d: any = res.artifacts![0]!.data;
  assert.equal(d.checkedAt, '2026-11-21T10:00:00.000Z');
  assert.equal(d.securityTxt.url, 'https://x.example.com/.well-known/security.txt');
  assert.equal(d.robots.status, 200);
  assert.equal(d.sitemap.urls, 30);
  assert.equal(d.sitemap.sample.length, 20);
  assert.equal(d.sitemap.sample[0], '/p0');
  assert.equal(d.manifest.url, 'https://x.example.com/site.webmanifest');
  assert.equal(d.manifest.valid, true);
  assert.equal(d.manifest.shortName, 'n');
});

test('security.txt: missing, expired, incomplete, valid', async () => {
  const sec = (body: string) => ({ 'https://x.example.com/.well-known/security.txt': txt(body) });
  assert.deepEqual(ids(await run({}), 'wellknown.securitytxt'), ['securitytxt-missing']);
  const expired = await run(sec('Contact: mailto:a@b.c\nExpires: 2025-01-01T00:00:00Z'));
  assert.deepEqual(ids(expired, 'wellknown.securitytxt'), ['securitytxt-expired']);
  const f = expired.result.findings.find((x: any) => x.id.endsWith('securitytxt-expired'))!;
  assert.equal(f.severity, 'low');
  assert.equal(f.vars!.date, '2025-01-01');
  const inc = await run(sec('Contact: mailto:a@b.c\n'));
  assert.deepEqual(ids(inc, 'wellknown.securitytxt'), ['securitytxt-incomplete']);
  assert.equal(inc.result.findings.find((x: any) => x.id.endsWith('incomplete'))!.severity, 'info');
  assert.deepEqual(ids(await run(sec('contact: mailto:a@b.c\nexpires: 2027-03-01T00:00:00Z')), 'wellknown.securitytxt'), []);
});

test('robots: sensitive paths, traps, blocks-all', async () => {
  const rob = (body: string) => ({ 'https://x.example.com/robots.txt': txt(body) });
  const r = await run(rob('User-agent: *\nDisallow: /admin/\nDisallow: /wp-admin/ # comment\nDisallow: /.env\nDisallow: /testimonials\nDisallow: /search'));
  assert.deepEqual(ids(r, 'wellknown.robots-hints'), ['robots-sensitive']);
  const f = r.result.findings[0]!;
  assert.equal(f.vars!.count, '3');
  assert.ok(f.vars!.sample!.includes('/admin/'));
  assert.ok(!f.vars!.sample!.includes('testimonials'));
  assert.deepEqual(ids(await run(rob('User-agent: *\nDisallow: /search\nAllow: /')), 'wellknown.robots-hints'), []);
  const all = await run(rob('User-agent: *\nDisallow: /'));
  assert.deepEqual(ids(all, 'wellknown.robots-hints'), ['robots-blocks-all']);
  const noindex = await runOn({ [U]: html('<meta name="robots" content="noindex, nofollow">') }, U, plan, { modules });
  assert.deepEqual(ids(noindex, 'wellknown.robots-hints'), ['robots-blocks-all']);
  assert.deepEqual(parseRobots('User-agent: a\nUser-agent: b\nDisallow: /x')[0]!.agents, ['a', 'b']);
});

test('generator meta parse and version comparison', async () => {
  assert.deepEqual(parseGenerators('<meta name="generator" content="Astro v4.5.0">'), [{ name: 'Astro', version: '4.5.0' }]);
  assert.deepEqual(parseGenerators("<meta content='Hugo 0.121.0' name='generator'>"), [{ name: 'Hugo', version: '0.121.0' }]);
  assert.deepEqual(parseGenerators('<meta name="generator" content="WordPress 6.4.2" /><meta name="generator" content="Gatsby 5.13.0">').map((g) => g.name), ['WordPress', 'Gatsby']);
  assert.deepEqual(parseGenerators('<meta name="generator" content="Nuxt">'), [{ name: 'Nuxt', version: null }]);
  assert.deepEqual(parseGenerators('<meta name="description" content="Astro v4.5.0">'), []);
  assert.ok(compareVersions('4.5.0', '7.4.7') < 0);
  assert.ok(compareVersions('7.4.7', '7.4.7') === 0);
  assert.ok(compareVersions('7.10', '7.4.7') > 0);
  assert.ok(compareVersions('7.4', '7.4.1') < 0);

  const old = await runOn({ [U]: html('<meta name="generator" content="Astro v4.5.0">') }, U, plan, { modules });
  assert.deepEqual(old.result.facts['stack.generator'], { name: 'Astro', version: '4.5.0' });
  const f = old.result.findings.find((x: any) => x.module === 'stack.generator')!;
  assert.equal(f.messageKey, 'deps.generator-outdated');
  assert.equal(f.severity, 'low');
  const cur = await runOn({ [U]: html('<meta name="generator" content="Astro v7.4.7">') }, U, plan, { modules });
  assert.ok(!cur.result.findings.some((x: any) => x.module === 'stack.generator'));
  const wp = await runOn({ [U]: html('<meta name="generator" content="WordPress 4.0">') }, U, plan, { modules });
  assert.ok(!wp.result.findings.some((x: any) => x.module === 'stack.generator'), 'no WordPress rule');
  assert.equal((wp.result.facts['stack.generator'] as any).name, 'WordPress');
});
