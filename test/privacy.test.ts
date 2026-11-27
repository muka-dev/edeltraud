import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { privacyModules, isSpaShell, staticUrls } from '../src/modules/analyze/privacy.ts';
import { classifyHost } from '../src/modules/analyze/thirdparty-db.ts';
import type { RenderData } from '../src/core/types.ts';

const MODS = [...MODULES];
const IDS = privacyModules.map((m) => m.manifest.id);
const URL_ = 'https://x.example.com/';
const renderPlan = parsePlan({
  plan: 't', limits: { totalMs: 10000, requests: 50, browser: true },
  modules: ['collect.page', { 'collect.render': { waitMs: 0 } }, ...IDS],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const staticPlan = parsePlan({
  plan: 's', limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', ...IDS],
  presentation: { showFindings: 'all', fixPrompts: true },
});

const shell = `<!doctype html><html><head><meta name="generator" content="lovable"></head><body><div id="root"></div><script type="module" src="/assets/index-a1b2c3d4.js"></script></body></html>`;
const site = (html: string) => ({ [URL_]: { headers: { 'content-type': 'text/html' }, body: html } });
const req = (url: string, resourceType = 'script') => ({ url, method: 'GET', resourceType, status: 200, failure: null });
const cookie = (name: string, domain = 'x.example.com') => ({ name, domain, path: '/', expires: -1, httpOnly: false, secure: true, sameSite: 'Lax' });
const kinds = (fs: { id: string }[]) => fs.map((f) => f.id).sort();
const render = (r: Partial<RenderData>) => ({ [URL_]: r });

test('Lovable app: GA4, Hotjar and Google Fonts before consent', async () => {
  const { result } = await runOn(site(shell), URL_, renderPlan, {
    modules: MODS,
    render: render({
      requests: [
        req(URL_, 'document'),
        req('https://x.example.com/assets/index-a1b2c3d4.js'),
        req('https://fonts.googleapis.com/css2?family=Inter', 'stylesheet'),
        req('https://fonts.gstatic.com/s/inter/v1/a.woff2', 'font'),
        req('https://www.google-analytics.com/g/collect?v=2&tid=G-X&gcs=G111', 'ping'),
        req('https://static.hotjar.com/c/hotjar-1.js'),
        req('https://abc.supabase.co/rest/v1/x', 'fetch'),
      ],
      cookies: [cookie('_ga'), cookie('_ga_ABC123'), cookie('_hjSessionUser_1'), cookie('sb-abc-auth-token'), cookie('__cf_bm')],
    }),
  });
  assert.deepEqual(kinds(result.findings), [
    'privacy.consent-before-tracking/cookies-before-consent',
    'privacy.consent-before-tracking/tracking-before-consent',
    'privacy.google-fonts/google-fonts',
    'privacy.third-party/third-country',
    'privacy.third-party/third-party',
  ]);
  const tp = result.findings.find((f) => f.id === 'privacy.third-party/third-party')!;
  assert.equal(tp.vars!.count, '4');
  assert.match(tp.vars!.list!, /Google Analytics \(US\)/);
  assert.match(tp.vars!.list!, /Hotjar \(MT\)/);
  assert.equal(tp.severity, 'info');
  const cookies = result.findings.find((f) => f.id.endsWith('/cookies-before-consent'))!;
  assert.equal(cookies.vars!.list, '_ga, _ga_ABC123, _hjSessionUser_1');
  assert.equal(cookies.vars!.cmp, '–');
  const tr = result.findings.find((f) => f.id.endsWith('/tracking-before-consent'))!;
  assert.match(tr.vars!.list!, /Hotjar \(MT\)/);
  assert.equal(tr.severity, 'medium');
  assert.equal(result.findings.find((f) => f.id === 'privacy.google-fonts/google-fonts')!.vars!.host, 'fonts.googleapis.com, fonts.gstatic.com');
  const tps = result.facts['privacy.thirdParties'] as { name: string; country: string }[];
  assert.ok(tps.some((t) => t.name === 'Hotjar' && t.country === 'MT'));
  assert.equal(result.complete, true);
});

test('Consent Mode denied: info instead of a tracking finding', async () => {
  const { result } = await runOn(site(shell), URL_, renderPlan, {
    modules: MODS,
    render: render({
      requests: [
        req('https://www.googletagmanager.com/gtag/js?id=G-X'),
        req('https://www.google-analytics.com/g/collect?v=2&gcs=G100&gcd=13l3l3l3l1', 'ping'),
        req('https://stats.g.doubleclick.net/g/collect?v=2&gcs=G100', 'ping'),
      ],
      cookies: [cookie('CookieConsent')],
      html: '<script src="https://consent.cookiebot.com/uc.js"></script>',
    }),
  });
  assert.deepEqual(kinds(result.findings.filter((f) => f.module === 'privacy.consent-before-tracking')), ['privacy.consent-before-tracking/consent-mode-denied']);
  const f = result.findings.find((x) => x.id.endsWith('consent-mode-denied'))!;
  assert.equal(f.severity, 'info');
  assert.equal(f.vars!.cmp, 'Cookiebot');
  assert.equal(result.facts['privacy.cmp'], 'Cookiebot');

  // Same pings, but one without gcs, or with a _ga cookie: back to medium.
  const mixed = await runOn(site(shell), URL_, renderPlan, {
    modules: MODS,
    render: render({ requests: [req('https://www.google-analytics.com/g/collect?gcs=G100'), req('https://www.google-analytics.com/g/collect?gcs=G111')] }),
  });
  assert.ok(mixed.result.findings.some((x) => x.id.endsWith('/tracking-before-consent')));
  const withCookie = await runOn(site(shell), URL_, renderPlan, {
    modules: MODS,
    render: render({ requests: [req('https://www.google-analytics.com/g/collect?gcs=G100')], cookies: [cookie('_ga')] }),
  });
  assert.ok(withCookie.result.findings.some((x) => x.id.endsWith('/tracking-before-consent')));
  assert.ok(withCookie.result.findings.some((x) => x.id.endsWith('/cookies-before-consent')));
});

test('clean app: same-site and Stripe only gives just the third-party info', async () => {
  const { result } = await runOn(site(shell), URL_, renderPlan, {
    modules: MODS,
    render: render({
      requests: [
        req(URL_, 'document'),
        req('https://api.x.example.com/data', 'fetch'),
        req('https://x.example.com/_vercel/insights/script.js'),
        req('https://js.stripe.com/v3/'),
        req('data:image/png;base64,AAAA', 'image'),
      ],
      cookies: [cookie('session'), cookie('csrf'), cookie('__cf_bm'), cookie('cf_clearance'), cookie('sb-x-auth-token'), cookie('OptanonConsent')],
    }),
  });
  assert.deepEqual(kinds(result.findings), ['privacy.third-party/third-country', 'privacy.third-party/third-party']);
  assert.equal(result.findings.find((f) => f.id.endsWith('/third-party'))!.vars!.count, '1');
  const none = await runOn(site(shell), URL_, renderPlan, { modules: MODS, render: render({ requests: [req(URL_, 'document')] }) });
  assert.deepEqual(none.result.findings, []);
});

test('third-country is not reported for EU services only', async () => {
  const { result } = await runOn(site(shell), URL_, renderPlan, {
    modules: MODS,
    render: render({ requests: [req('https://client.crisp.chat/l.js'), req('https://eu.i.posthog.com/e/'), req('https://cdn.example.org/a.js')] }),
  });
  assert.deepEqual(kinds(result.findings), ['privacy.consent-before-tracking/tracking-before-consent', 'privacy.third-party/third-party']);
  assert.match(result.findings.find((f) => f.id.endsWith('/third-party'))!.vars!.list!, /cdn\.example\.org \(unbekannt\)/);
});

test('static HTML (ampel, no browser): third parties and Google Fonts from the page', async () => {
  const html = `<!doctype html><html><head><title>Hi</title>
<link rel="preconnect" href="https://fonts.gstatic.com">
<link href="https://fonts.googleapis.com/css2?family=Inter" rel="stylesheet">
<link rel="canonical" href="https://other.example.net/">
<script async src="https://www.googletagmanager.com/gtag/js?id=G-X"></script>
<script src="https://static.hotjar.com/c/hotjar.js"></script></head>
<body><h1>Welcome</h1><p>Some real content for visitors of this page, long enough to count.</p><a href="https://twitter.com/x">x</a></body></html>`;
  const { result } = await runOn(site(html), URL_, staticPlan, { modules: MODS });
  assert.deepEqual(kinds(result.findings), ['privacy.google-fonts/google-fonts', 'privacy.third-party/third-country', 'privacy.third-party/third-party']);
  assert.equal(result.findings.find((f) => f.id.endsWith('/third-party'))!.vars!.count, '3');
  assert.ok(!result.findings.some((f) => f.module === 'privacy.consent-before-tracking'));
  assert.equal(result.complete, true);

  const css = `<html><body><p>${'text '.repeat(20)}</p><style>@import url("https://fonts.googleapis.com/css?family=Roboto");</style></body></html>`;
  const r2 = await runOn(site(css), URL_, staticPlan, { modules: MODS });
  assert.ok(r2.result.findings.some((f) => f.id === 'privacy.google-fonts/google-fonts'));
});

test('SPA shell without render: unsupported, scan stays complete', async () => {
  const { result } = await runOn(site(shell), URL_, staticPlan, { modules: MODS });
  assert.deepEqual(result.findings, []);
  const nc = result.notChecked.filter((n) => n.reason === 'unsupported' && n.detail === 'needs rendering').map((n) => n.module).sort();
  assert.deepEqual(nc, ['privacy.google-fonts', 'privacy.third-party']);
  assert.equal(result.complete, true);
});

test('classifyHost, shell detection and URL extraction', () => {
  assert.equal(classifyHost('https://cdn.x.example.com/a.js', 'x.example.com'), null);
  assert.equal(classifyHost('data:text/plain,x', 'x.example.com'), null);
  const c = classifyHost('https://region1.google-analytics.com/g/collect', 'x.example.com');
  assert.ok(c && 'id' in c && c.id === 'google-analytics' && c.tracking);
  assert.equal((classifyHost('https://www.facebook.com/tr?id=1', 'x.example.com') as { id: string }).id, 'meta-pixel-tr');
  assert.equal((classifyHost('https://www.facebook.com/someone', 'x.example.com') as { unknown?: boolean }).unknown, true);
  assert.equal((classifyHost('https://o1.ingest.de.sentry.io/api/1/envelope/', 'x.example.com') as { country: string }).country, 'DE');
  assert.equal((classifyHost('https://o1.ingest.sentry.io/api/1/envelope/', 'x.example.com') as { country: string }).country, 'US');
  assert.equal((classifyHost('https://www.google.com/maps/embed?pb=1', 'x.example.com') as { id: string }).id, 'google-maps-embed');
  assert.equal(isSpaShell(shell), true);
  assert.equal(isSpaShell('<body><h1>Hi</h1><p>x</p><p>y</p></body>'), false);
  assert.deepEqual(staticUrls('<a href="https://a.com/">x</a><img src="//b.com/i.png"><link rel="icon" href="/f.ico">', 'https://x.com/'), ['https://b.com/i.png', 'https://x.com/f.ico']);
});
