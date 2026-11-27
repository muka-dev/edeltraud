import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { LiveBrowser, defaultAllowUrl } from '../src/fetch/browser.ts';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { cleanSite } from './fixtures/sites.ts';

const plan = parsePlan({
  plan: 't', limits: { totalMs: 20000, requests: 20, browser: true },
  modules: ['collect.page', { 'collect.render': { waitMs: 0 } }],
  presentation: { showFindings: 'all', fixPrompts: true },
});

test('collect.render: unsupported without a browser, artifact with one, error for a dead page', async () => {
  const none = await runOn(cleanSite(), 'https://clean.example.com/', plan);
  assert.ok(none.result.notChecked.some((n) => n.module === 'collect.render' && n.reason === 'unsupported'));
  assert.equal(none.result.complete, true);

  const ok = await runOn(cleanSite(), 'https://clean.example.com/', plan, { render: { 'https://clean.example.com/': { title: 'Clean' } } });
  assert.equal((ok.artifacts.list('render')[0]!.data as { title: string }).title, 'Clean');

  const dead = await runOn(cleanSite(), 'https://clean.example.com/', plan, { render: {} });
  assert.ok(dead.result.notChecked.some((n) => n.module === 'collect.render' && n.reason === 'error'));
  assert.equal(dead.result.complete, false);
});

test('a plan without a browser refuses collect.render', async () => {
  await assert.rejects(runOn(cleanSite(), 'https://x.example.com/', parsePlan({ plan: 'n', limits: { totalMs: 1000, requests: 5, browser: false }, modules: ['collect.render'] })), /needs a browser/);
});

test('SSRF rule for browser requests', async () => {
  assert.equal(await defaultAllowUrl('http://127.0.0.1/'), false);
  assert.equal(await defaultAllowUrl('http://169.254.169.254/latest/meta-data'), false);
  assert.equal(await defaultAllowUrl('file:///etc/passwd'), false);
  assert.equal(await defaultAllowUrl('data:text/plain,x'), true);
});

test('LiveBrowser renders a local page (skipped without Chromium)', async (t) => {
  const server = http.createServer((req, res) => {
    if (req.url === '/') {
      res.setHeader('content-type', 'text/html');
      res.setHeader('set-cookie', 'sid=1; Path=/');
      res.end(`<html><head><title>T</title><script src="/a.js"></script></head><body>
<a href="/impressum">Impressum</a><img src="http://10.0.0.1/x.png"></body></html>`);
    } else if (req.url === '/a.js') {
      res.setHeader('content-type', 'text/javascript');
      res.end('localStorage.setItem("token","secret-value");console.error("boom");document.title="T2";');
    } else {
      res.statusCode = 404;
      res.end('nope');
    }
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  const base = `http://127.0.0.1:${port}`;
  try {
    const b = new LiveBrowser({ allowUrl: async (u) => u.startsWith(base) || u.startsWith('data:') });
    let data;
    try {
      data = await b.render(base + '/', { waitMs: 100, maxRequests: 50, timeoutMs: 15000 });
    } catch (e) {
      if (/Playwright is not installed|Executable doesn't exist|launch/i.test(String(e))) return t.skip(String(e).slice(0, 80));
      throw e;
    }
    assert.equal(data.title, 'T2');
    assert.ok(data.requests.some((r) => r.url === base + '/a.js' && r.status === 200));
    assert.deepEqual(data.storage.local, ['token']);
    assert.ok(!JSON.stringify(data).includes('secret-value'), 'storage values are never kept');
    assert.ok(data.console.some((c) => c.type === 'error' && c.text === 'boom'));
    assert.ok(data.cookies.some((c) => c.name === 'sid'));
    assert.ok(data.links.some((l) => l.href === base + '/impressum' && l.text === 'Impressum'));
    assert.ok(data.blocked.includes('http://10.0.0.1/x.png'));
  } finally {
    server.close();
  }
});
