import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { jwt } from './fixtures/sites.ts';

const MODS = [...MODULES];
const mkPlan = (modules: string[], browser: boolean) =>
  parsePlan({ plan: 't', limits: { totalMs: 10000, requests: 50, browser }, modules, presentation: { showFindings: 'all', fixPrompts: true } });
const staticPlan = mkPlan(['collect.page', 'collect.legal', 'privacy.legal-pages', 'mixed.content', 'sri.missing'], false);
const renderPlan = mkPlan(['collect.page', 'collect.render', 'collect.legal', 'privacy.legal-pages', 'ops.errors-console', 'mixed.content', 'sri.missing'], true);
const ids = (r: { findings: { id: string }[] }) => [...new Set(r.findings.map((f) => f.id))].sort();
const page = (html: string, headers: Record<string, string> = {}) => ({ headers: { 'content-type': 'text/html', ...headers }, body: html });
const U = 'https://x.example.com/';
const TEXT = '<p>Willkommen auf unserer Seite mit ausreichend sichtbarem Text für die Prüfung.</p>';

// ---- privacy.legal-pages -------------------------------------------------

test('legal: static links found and reachable -> no findings, 2 requests at most', async () => {
  const site = {
    [U]: page(`<html lang="de"><body>${TEXT}<a href="/impressum">Impressum</a><a href="/datenschutz">Datenschutzerklärung</a></body></html>`),
    'https://x.example.com/impressum': { body: 'ok' },
    'https://x.example.com/datenschutz': { body: 'ok' },
  };
  const { result, artifacts, http } = await runOn(site, U, staticPlan, { modules: MODS });
  assert.deepEqual(ids(result).filter((i) => i.startsWith('privacy.')), []);
  const d = artifacts.list('legal-pages')[0]!.data as { source: string; imprint: { status: number }; privacy: { status: number } };
  assert.equal(d.source, 'html');
  assert.equal(d.imprint.status, 200);
  assert.equal(http.log.filter((l) => l.includes('impressum') || l.includes('datenschutz')).length, 2);
});

test('legal: Datenschutz only in the rendered DOM is found with a browser', async () => {
  const site = { [U]: page('<html lang="en"><body><div id="root"></div></body></html>'), 'https://x.example.com/privacy': { body: 'ok' } };
  const render = { [U]: { html: '<html lang="en"><body><footer></footer></body></html>', links: [{ href: '/privacy', text: 'Privacy Policy' }] } };
  const { result } = await runOn(site, U, renderPlan, { modules: MODS, render });
  assert.ok(!ids(result).includes('privacy.legal-pages/no-privacy-link'));
  assert.ok(!ids(result).includes('privacy.legal-pages/no-imprint-link'), 'English .com site: imprint optional');
});

test('legal: SPA shell without render -> unsupported, no artifact, scan stays complete', async () => {
  const site = { [U]: page('<html><body><div id="root"></div><script src="/a.js"></script></body></html>'), 'https://x.example.com/a.js': { body: '' } };
  const { result, artifacts } = await runOn(site, U, staticPlan, { modules: MODS });
  assert.ok(result.notChecked.some((n) => n.module === 'collect.legal' && n.reason === 'unsupported' && n.detail === 'needs rendering'));
  assert.equal(artifacts.list('legal-pages').length, 0);
  assert.ok(!ids(result).some((i) => i.startsWith('privacy.')));
});

test('legal: no links -> privacy medium; imprint only for German pages or .de/.at/.ch', async () => {
  const plain = `<html lang="en"><body>${TEXT}<a href="/about">About</a></body></html>`;
  const en = await runOn({ [U]: page(plain) }, U, staticPlan, { modules: MODS });
  assert.deepEqual(ids(en.result).filter((i) => i.startsWith('privacy.')), ['privacy.legal-pages/no-privacy-link']);
  assert.equal(en.result.findings.find((f) => f.id === 'privacy.legal-pages/no-privacy-link')!.severity, 'medium');

  const de = await runOn({ [U]: page(plain.replace('lang="en"', 'lang="de-AT"')) }, U, staticPlan, { modules: MODS });
  const imp = de.result.findings.find((f) => f.id === 'privacy.legal-pages/no-imprint-link')!;
  assert.equal(imp.severity, 'low');

  const tld = await runOn({ 'https://shop.example.at/': page(plain) }, 'https://shop.example.at/', staticPlan, { modules: MODS });
  assert.ok(ids(tld.result).includes('privacy.legal-pages/no-imprint-link'));
});

test('legal: Impressum answered 404 -> unreachable with href and status', async () => {
  const site = {
    [U]: page(`<html lang="de"><body>${TEXT}<a href="/impressum">Impressum</a><a href="/datenschutz">Datenschutz</a></body></html>`),
    'https://x.example.com/datenschutz': { body: 'ok' },
  };
  const { result } = await runOn(site, U, staticPlan, { modules: MODS });
  const f = result.findings.find((x) => x.id === 'privacy.legal-pages/unreachable-imprint')!;
  assert.deepEqual(f.vars, { href: 'https://x.example.com/impressum', status: '404' });
  assert.equal(f.severity, 'medium');
  assert.ok(!ids(result).includes('privacy.legal-pages/no-privacy-link'));
});

test('legal: external and pt links; third-party host links are ignored', async () => {
  const site = {
    [U]: page(`<html lang="pt-BR"><body>${TEXT}<a href="https://other.org/privacy">Privacy</a><a href="/politica-de-privacidade">Política</a><a href="/aviso-legal">Aviso legal</a></body></html>`),
    'https://x.example.com/politica-de-privacidade': { body: 'ok' },
    'https://x.example.com/aviso-legal': { body: 'ok' },
  };
  const { artifacts } = await runOn(site, U, staticPlan, { modules: MODS });
  const d = artifacts.list('legal-pages')[0]!.data as { privacy: { href: string }; imprint: { href: string } };
  assert.equal(d.privacy.href, 'https://x.example.com/politica-de-privacidade');
  assert.equal(d.imprint.href, 'https://x.example.com/aviso-legal');
});

// ---- ops.errors-console ---------------------------------------------------

test('console: errors, failed requests, secrets (masked)', async () => {
  const secret = jwt({ role: 'service_role', iss: 'supabase' });
  const render = {
    [U]: {
      html: '<html><body>x</body></html>',
      pageErrors: ['TypeError: x is undefined ' + 'a'.repeat(300)],
      console: [
        { type: 'error', text: `Failed with token ${secret}`, url: null },
        { type: 'log', text: 'hello', url: null },
      ],
      requests: [
        { url: 'https://x.example.com/api/data', method: 'GET', resourceType: 'fetch', status: 500, failure: null },
        { url: 'https://x.example.com/favicon.ico', method: 'GET', resourceType: 'other', status: 404, failure: null },
        { url: 'https://x.example.com/ok.js', method: 'GET', resourceType: 'script', status: 200, failure: null },
        { url: 'https://third.example.org/x', method: 'GET', resourceType: 'fetch', status: 404, failure: null },
        { url: 'https://x.example.com/blocked', method: 'GET', resourceType: 'fetch', status: null, failure: 'blocked:internal' },
      ],
    },
  };
  const { result } = await runOn({ [U]: page(TEXT) }, U, renderPlan, { modules: MODS, render });
  const ce = result.findings.find((f) => f.id === 'ops.errors-console/console-errors')!;
  assert.equal(ce.vars!['count'], '2');
  assert.ok(ce.vars!['sample']!.length <= 120);
  const fr = result.findings.find((f) => f.id === 'ops.errors-console/failed-requests')!;
  assert.equal(fr.vars!['count'], '1');
  const cs = result.findings.find((f) => f.id === 'ops.errors-console/console-secret')!;
  assert.equal(cs.category, 'security');
  assert.ok(!JSON.stringify(result.findings).includes(secret));
});

test('console: clean page, log-only output, bare Bearer word -> nothing', async () => {
  const render = { [U]: { html: '<html></html>', console: [{ type: 'log', text: 'Bearer of good news', url: null }, { type: 'warning', text: 'deprecated', url: null }] } };
  const { result } = await runOn({ [U]: page(TEXT) }, U, renderPlan, { modules: MODS, render });
  assert.deepEqual(ids(result).filter((i) => i.startsWith('ops.')), []);
});

test('console: sample masks a key inside an error message', async () => {
  const key = 'sk-' + 'proj-' + 'Zq8'.repeat(10);
  const render = { [U]: { html: '<html></html>', console: [{ type: 'error', text: `401 for key ${key}`, url: null }] } };
  const { result } = await runOn({ [U]: page(TEXT) }, U, renderPlan, { modules: MODS, render });
  assert.ok(!JSON.stringify(result.findings).includes(key));
  assert.ok(ids(result).includes('ops.errors-console/console-secret'));
});

// ---- mixed.content --------------------------------------------------------

test('mixed: http script and form are active, http image is passive (static HTML)', async () => {
  const html = `<html><body>${TEXT}<script src="http://cdn.example.org/a.js"></script><img src="http://img.example.org/p.png"><form action="http://x.example.com/post"></form></body></html>`;
  const { result } = await runOn({ [U]: page(html) }, U, staticPlan, { modules: MODS });
  const a = result.findings.find((f) => f.id === 'mixed.content/active')!;
  assert.equal(a.severity, 'medium');
  assert.equal(a.vars!['count'], '2');
  assert.equal(result.findings.find((f) => f.id === 'mixed.content/passive')!.severity, 'low');
});

test('mixed: http in <a href>, xmlns, text and inline script strings are not mixed content', async () => {
  const html = `<html><body>${TEXT}<a href="http://example.org/">link</a><svg xmlns="http://www.w3.org/2000/svg"></svg>
<p>see http://example.org/x.png</p><script>document.write('<img src="http://evil.example.org/a.png">')</script><!-- <img src="http://c.example.org/a.png"> --></body></html>`;
  const { result } = await runOn({ [U]: page(html) }, U, staticPlan, { modules: MODS });
  assert.deepEqual(ids(result).filter((i) => i.startsWith('mixed.')), []);
});

test('mixed: upgrade-insecure-requests silences static hits; render requests still count', async () => {
  const html = `<html><body>${TEXT}<script src="http://cdn.example.org/a.js"></script></body></html>`;
  const hdr = { 'content-security-policy': 'upgrade-insecure-requests' };
  const s = await runOn({ [U]: page(html, hdr) }, U, staticPlan, { modules: MODS });
  assert.deepEqual(ids(s.result).filter((i) => i.startsWith('mixed.')), []);
  const render = { [U]: { html: '', requests: [{ url: 'http://t.example.org/pixel.gif', method: 'GET', resourceType: 'image', status: 200, failure: null }] } };
  const r = await runOn({ [U]: page(html, hdr) }, U, renderPlan, { modules: MODS, render });
  assert.deepEqual(ids(r.result).filter((i) => i.startsWith('mixed.')), ['mixed.content/passive']);
});

test('mixed: http page is not judged', async () => {
  const h = 'http://plain.example.com/';
  const { result } = await runOn({ [h]: page(`<html><body>${TEXT}<script src="http://a.example.org/a.js"></script></body></html>`) }, h, mkPlan(['collect.page', 'mixed.content'], false), { modules: MODS });
  assert.deepEqual(ids(result).filter((i) => i.startsWith('mixed.')), []);
});

// ---- sri.missing ----------------------------------------------------------

test('sri: pinned CDN script without integrity is reported, with integrity or same-site not', async () => {
  const html = `<html><head>
<script src="https://cdn.jsdelivr.net/npm/lodash@4.17.21/lodash.min.js"></script>
<script src="https://unpkg.com/a@1/a.js" integrity="sha384-abc" crossorigin="anonymous"></script>
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.5.0/css/bootstrap.min.css">
<script src="/local.js"></script><script src="https://static.example.com/own.js"></script></head><body>${TEXT}</body></html>`;
  const { result } = await runOn({ [U]: page(html) }, U, staticPlan, { modules: MODS });
  const f = result.findings.find((x) => x.id === 'sri.missing/missing')!;
  assert.equal(f.severity, 'low');
  assert.equal(f.vars!['count'], '2');
  assert.match(f.vars!['sample']!, /jsdelivr/);
});

test('sri: self-updating services are not reported', async () => {
  const html = `<html><head>
<script async src="https://www.googletagmanager.com/gtag/js?id=G-1"></script>
<script src="https://js.stripe.com/v3/"></script>
<script src="https://static.cloudflareinsights.com/beacon.min.js"></script>
<script src="https://www.google.com/recaptcha/api.js"></script>
<script src="https://connect.facebook.net/en_US/sdk.js"></script>
<script src="https://cdn.gpteng.co/gptengineer.js" type="module"></script>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">
<link rel="icon" href="https://other.example.org/i.png"></head><body>${TEXT}</body></html>`;
  const { result } = await runOn({ [U]: page(html) }, U, staticPlan, { modules: MODS });
  assert.ok(!ids(result).includes('sri.missing/missing'));
});

test('sri: script injected only in the rendered DOM is reported', async () => {
  const render = { [U]: { html: '<html><head><script src="https://cdn.jsdelivr.net/npm/x@1/x.js"></script></head></html>' } };
  const { result } = await runOn({ [U]: page(TEXT) }, U, renderPlan, { modules: MODS, render });
  assert.ok(ids(result).includes('sri.missing/missing'));
});
