// End-to-end: report plan with DNS and TLS fixtures, all wave-2 modules together.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { cleanSite } from './fixtures/sites.ts';

const ids = (r: { findings: { id: string }[] }) => [...new Set(r.findings.map((f) => f.id))].sort();
const DAY = 86_400_000;
const NOW = Date.parse('2026-11-20T12:00:00.000Z');
const iso = (ms: number) => new Date(ms).toISOString();

/** Old-school app on its own domain: dev server, jQuery 3.4.1, Django debug page, weak CSP, lax mail DNS, cert about to expire. */
function sloppySite() {
  const html = `<!doctype html><html lang="de"><head>
<script type="module" src="/@vite/client"></script>
<script src="/static/vendor.js"></script></head><body></body></html>`;
  return {
    'https://shop.example.de/': {
      headers: {
        'content-type': 'text/html',
        'content-security-policy': "script-src 'self' 'unsafe-inline' https:; frame-ancestors 'none'",
        'strict-transport-security': 'max-age=63072000',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'permissions-policy': 'camera=()',
      },
      body: html,
    },
    'http://shop.example.de/': { redirect: 'https://shop.example.de/' },
    'https://shop.example.de/static/vendor.js': { body: '/*! jQuery v3.4.1 | (c) JS Foundation and other contributors | jquery.org/license */\n!function(){}();' },
    'https://shop.example.de/edeltraud-check-404': {
      status: 404,
      body: "<h1>Page not found</h1><p>You're seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>",
    },
  };
}

const sloppyDns = {
  'shop.example.de A': ['203.0.113.10'],
  'example.de MX': ['10 mail.example.de'],
  'example.de TXT': ['v=spf1 include:_spf.example.net ?all'],
  '_dmarc.example.de TXT': ['v=DMARC1; p=none'],
};
const sloppyTls = {
  'shop.example.de': { validFrom: iso(NOW - 87 * DAY), validTo: iso(NOW + 3 * DAY), legacy: { 'TLSv1': true, 'TLSv1.1': true } },
};

test('report plan: wave-2 modules find their signals together', async () => {
  const { result } = await runOn(sloppySite(), 'https://shop.example.de/', 'report', { dns: sloppyDns, tls: sloppyTls });
  const got = ids(result);
  for (const id of [
    'build.dev-mode/dev-server',
    'deps.vulnerable/lib-jquery',
    'errors.verbose/debug-page',
    'headers.csp-quality/unsafe-inline',
    'headers.csp-quality/wildcard',
    'dns.mail/spf-lax',
    'dns.mail/dmarc-none',
    'tls.basics/cert-expiring',
    'tls.basics/legacy-protocol',
  ]) assert.ok(got.includes(id), `missing ${id} in ${got.join(', ')}`);
  assert.equal(result.findings.find((f) => f.id === 'tls.basics/cert-expiring')!.severity, 'high');
  assert.equal(result.complete, true);
  assert.equal(result.verdict.light, 'red');
});

test('report plan: well-kept app with DNS and TLS stays green', async () => {
  const { result } = await runOn(cleanSite(), 'https://clean.example.com/', 'report', {
    dns: {
      'clean.example.com A': ['203.0.113.20'],
      'example.com MX': ['10 mx.example.com'],
      'example.com TXT': ['v=spf1 mx -all', 'google-site-verification=abc'],
      '_dmarc.example.com TXT': ['v=DMARC1; p=reject; rua=mailto:dmarc@example.com'],
    },
    tls: { 'clean.example.com': { validFrom: iso(NOW - 30 * DAY), validTo: iso(NOW + 60 * DAY) } },
  });
  assert.deepEqual(ids(result), ['firebase.config/detected', 'supabase.config/detected']);
  assert.equal(result.complete, true);
  assert.equal(result.verdict.light, 'green');
});

test('report plan: app on a provider domain gets no mail findings', async () => {
  const site = Object.fromEntries(Object.entries(cleanSite()).map(([k, v]) => [k.replace('clean.example.com', 'my-app.lovable.app'), v]));
  const { result } = await runOn(site, 'https://my-app.lovable.app/', 'report', { dns: {}, tls: {} });
  assert.ok(!result.findings.some((f) => f.module === 'dns.mail'));
  assert.ok(result.notChecked.some((n) => n.module === 'dns.mail' && n.reason === 'condition'));
});

test('ampel stays within its request budget and skips legacy TLS handshakes', async () => {
  const { result } = await runOn(sloppySite(), 'https://shop.example.de/', 'ampel', { dns: sloppyDns, tls: sloppyTls });
  assert.ok(result.requests <= 12);
  assert.ok(!result.findings.some((f) => f.id === 'tls.basics/legacy-protocol'));
  assert.ok(result.findings.some((f) => f.id === 'tls.basics/cert-expiring'));
});

/** Lovable-style SPA: GA4 + Hotjar + Google Fonts on first load, console error, footer links only after rendering. */
test('report plan with browser: privacy hints, console errors and legal pages from the rendered page', async () => {
  const site = cleanSite();
  site['https://clean.example.com/datenschutz'] = { body: '<h1>Datenschutz</h1>' };
  const render = {
    'https://clean.example.com/': {
      html: '<html lang="de"><body><div id="root"><footer><a href="/datenschutz">Datenschutz</a></footer></div></body></html>',
      requests: [
        { url: 'https://clean.example.com/assets/index-Q1w2e3r4.js', method: 'GET', resourceType: 'script', status: 200, failure: null },
        { url: 'https://www.googletagmanager.com/gtag/js?id=G-ABC', method: 'GET', resourceType: 'script', status: 200, failure: null },
        { url: 'https://region1.google-analytics.com/g/collect?v=2&tid=G-ABC', method: 'POST', resourceType: 'fetch', status: 204, failure: null },
        { url: 'https://static.hotjar.com/c/hotjar-1.js', method: 'GET', resourceType: 'script', status: 200, failure: null },
        { url: 'https://fonts.googleapis.com/css2?family=Inter', method: 'GET', resourceType: 'stylesheet', status: 200, failure: null },
        { url: 'https://clean.example.com/api/me', method: 'GET', resourceType: 'fetch', status: 500, failure: null },
      ],
      cookies: [
        { name: '_ga', domain: '.clean.example.com', path: '/', expires: 1900000000, httpOnly: false, secure: false, sameSite: 'Lax' },
      ],
      console: [{ type: 'error', text: 'TypeError: Cannot read properties of undefined', url: null }],
      links: [{ href: 'https://clean.example.com/datenschutz', text: 'Datenschutz' }],
    },
  };
  const { result } = await runOn(site, 'https://clean.example.com/', 'report', { render });
  const got = ids(result);
  for (const id of [
    'privacy.consent-before-tracking/tracking-before-consent',
    'privacy.consent-before-tracking/cookies-before-consent',
    'privacy.google-fonts/google-fonts',
    'privacy.third-party/third-party',
    'privacy.third-party/third-country',
    'ops.errors-console/console-errors',
    'ops.errors-console/failed-requests',
    'privacy.legal-pages/no-imprint-link',
  ]) assert.ok(got.includes(id), `missing ${id} in ${got.join(', ')}`);
  assert.ok(!got.includes('privacy.legal-pages/no-privacy-link'), 'privacy link from the rendered footer must count');
  assert.equal(result.complete, true);
});
