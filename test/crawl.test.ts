import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { crawlable, robotsDisallow } from '../src/modules/collect/crawl.ts';
import { FAKE } from './fixtures/sites.ts';

const modules = [...MODULES];
const U = 'https://x.example.com/';
const O = 'https://x.example.com';
const plan = (maxPages = 5, wellknown = true) =>
  parsePlan({
    plan: 't', limits: { totalMs: 10000, requests: 60, browser: false },
    modules: ['collect.page', ...(wellknown ? ['collect.wellknown'] : []), { 'collect.crawl': { maxPages } }, 'collect.bundles', 'secrets.frontend', 'privacy.third-party'],
    presentation: { showFindings: 'all', fixPrompts: true },
  });
const page = (body: string) => ({ headers: { 'content-type': 'text/html' }, body: `<!doctype html><html><head></head><body>${body}</body></html>` });
const START = page(`<a href="/about">a</a> <a href="/team#x">t</a> <a href="https://other.example.org/x">o</a>
<a href="https://sub.x.example.com/y">s</a> <a href="/logout">l</a> <a href="/account/delete">d</a> <a href="/checkout">c</a>
<a href="/files/report.pdf">p</a> <a href="/reset?token=abc">r</a> <a href="/private/x">pr</a> <a href="mailto:a@b.c">m</a>`);
const sitemap = (paths: string[]) => ({
  headers: { 'content-type': 'application/xml' },
  body: `<?xml version="1.0"?><urlset>${paths.map((p) => `<url><loc>${O}${p}</loc></url>`).join('')}</urlset>`,
});
const site = (): Record<string, any> => ({
  [U]: START,
  [O + '/robots.txt']: { headers: { 'content-type': 'text/plain' }, body: 'User-agent: *\nDisallow: /private/\n' },
  [O + '/sitemap.xml']: sitemap(['/', '/pricing', '/blog/one']),
  [O + '/pricing']: page('pricing'),
  [O + '/blog/one']: page('blog'),
  [O + '/about']: page('<iframe src="https://www.youtube.com/embed/x"></iframe>'),
  [O + '/team']: page('team'),
  [O + '/private/x']: page('private'),
});
const fetched = (r: any) => r.http.log.map((l: string) => l.replace('GET ', ''));
const subpages = (r: any) => r.artifacts.list('subpage').map((a: any) => a.key);

test('crawl: sitemap first, then links, up to maxPages; other origins, destructive and non-HTML URLs skipped', async () => {
  const r = await runOn(site(), U, plan(5), { modules });
  assert.deepEqual(subpages(r), [O + '/pricing', O + '/blog/one', O + '/about', O + '/team']);
  const log = fetched(r);
  for (const bad of ['other.example.org', 'sub.x.example.com', '/logout', '/account/delete', '/checkout', 'report.pdf', '/reset', '/private/']) {
    assert.ok(!log.some((l: string) => l.includes(bad)), bad);
  }
  assert.ok(r.result.complete);
  // third parties embedded on a subpage only are listed too
  assert.match(r.result.findings.find((f: any) => f.id === 'privacy.third-party/third-party')?.vars?.list ?? '', /YouTube/);
  assert.ok(r.http.requests.every((q: any) => (q.method ?? 'GET') === 'GET'));

  const r2 = await runOn(site(), U, plan(2), { modules });
  assert.deepEqual(subpages(r2), [O + '/pricing', O + '/blog/one']);
  assert.ok(!fetched(r2).includes(O + '/about'));
});

test('crawl: without collect.wellknown it reads robots.txt and sitemap.xml itself', async () => {
  const r = await runOn(site(), U, plan(5, false), { modules });
  assert.deepEqual(subpages(r), [O + '/pricing', O + '/blog/one', O + '/about', O + '/team']);
  assert.ok(!fetched(r).includes(O + '/private/x'));
});

test('crawl: SPA fallback (same HTML as the start page) is dropped', async () => {
  const s = site();
  s[O + '/pricing'] = START;
  s[O + '/about'] = { ...START, headers: { 'content-type': 'text/html; charset=utf-8' } };
  s[O + '/team'] = { headers: { 'content-type': 'application/json' }, body: '{}' };
  const r = await runOn(s, U, plan(5), { modules });
  assert.deepEqual(subpages(r), [O + '/blog/one']);
});

test('crawl: plan budget exhaustion keeps loaded pages and does not make the run incomplete', async () => {
  const p = plan(5);
  p.limits.requests = 9; // page + http + 5 wellknown + 2 subpages
  const r = await runOn(site(), U, p, { modules });
  assert.equal(subpages(r).length, 2);
  const nc = r.result.notChecked.find((n: any) => n.module === 'collect.crawl');
  assert.equal(nc?.reason, 'condition');
});

test('robots rules and URL filter', () => {
  const d = robotsDisallow('User-agent: googlebot\nDisallow: /g\n\nUser-agent: *\nDisallow: /*.php$\nDisallow: /tmp');
  assert.equal(crawlable('/g/x', U, O, d), O + '/g/x');
  assert.equal(crawlable('/index.php', U, O, d), null);
  assert.equal(crawlable('/index.php?a=1', U, O, d), O + '/index.php?a=1');
  assert.equal(crawlable('/tmp/a', U, O, d), null);
  assert.equal(crawlable('/display', U, O, []), O + '/display');
  assert.equal(crawlable('/sign-out', U, O, []), null);
  assert.equal(crawlable('/list?page=2', U, O, []), O + '/list?page=2');
  assert.equal(crawlable('/x?session_id=1', U, O, []), null);
  assert.equal(crawlable('http://x.example.com/', U, O, []), null);
});

test('a secret only on a subpage: found in the report plan, not in ampel; subpage scripts go through collect.bundles', async () => {
  const s: Record<string, any> = {
    [U]: page('<a href="/settings">s</a>'),
    [O + '/settings']: page(`<script src="/assets/settings-a1b2c3.js"></script><script>window.cfg={k:"${FAKE.github}"}</script>`),
    [O + '/assets/settings-a1b2c3.js']: { body: `const o=new OpenAI({apiKey:"${FAKE.openai}"});` },
  };
  const ids = (r: any) => r.result.findings.filter((f: any) => f.module === 'secrets.frontend').map((f: any) => f.id).sort();
  const report = await runOn(s, U, 'report');
  assert.deepEqual(ids(report), ['secrets.frontend/github-token', 'secrets.frontend/openai-key']);
  assert.equal(report.result.findings.find((f: any) => f.id === 'secrets.frontend/github-token')!.location.url, O + '/settings');
  const ampel = await runOn(s, U, 'ampel');
  assert.deepEqual(ids(ampel), []);
  assert.ok(!fetched(ampel).includes(O + '/settings'));
});
