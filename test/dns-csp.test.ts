import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn, parsePlan } from './helpers.ts';
import { MODULES } from '../src/modules/index.ts';
import { registrableDomain } from '../src/modules/collect/dns.ts';
import { parseCsp } from '../src/modules/analyze/csp.ts';
import { cleanSite } from './fixtures/sites.ts';
import { boltFirebase } from './fixtures/apps.ts';

const plan = parsePlan({
  plan: 't', limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.dns', 'dns.mail', 'headers.csp-quality'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const modules = [...MODULES];
const run = (site: any, url: string, dns?: any) => runOn(site, url, plan, { modules, ...(dns ? { dns } : {}) });
const ids = (r: any, p: string) => r.result.findings.filter((f: any) => f.id.startsWith(p)).map((f: any) => f.id.split('/')[1]).sort();

test('registrableDomain', () => {
  assert.equal(registrableDomain('www.example.com'), 'example.com');
  assert.equal(registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(registrableDomain('example.de'), 'example.de');
  assert.equal(registrableDomain('app.empresa.com.br'), 'empresa.com.br');
});

test('dns: no mail records, with MX -> medium; null MX -> low', async () => {
  const site = cleanSite();
  const r = await run(site, 'https://clean.example.com/', { 'example.com MX': ['10 mx.example.com'], 'clean.example.com A': ['1.2.3.4'] });
  const f = r.result.findings.filter((x: any) => x.module === 'dns.mail');
  assert.deepEqual(ids(r, 'dns.mail').sort(), ['dmarc-missing', 'spf-missing']);
  assert.ok(f.every((x: any) => x.severity === 'medium' && x.vars.domain === 'example.com'));
  assert.equal(r.result.facts['dns.mx'], true);
  const r2 = await run(cleanSite(), 'https://clean.example.com/', { 'example.com MX': ['0 .'] });
  assert.ok(r2.result.findings.filter((x: any) => x.module === 'dns.mail').every((x: any) => x.severity === 'low'));
  assert.equal(r2.result.facts['dns.mx'], false);
});

test('dns: good, lax, multiple, p=none', async () => {
  const good = { 'example.com MX': ['10 m.x'], 'example.com TXT': ['v=spf1 include:_spf.google.com ~all', 'google-site-verification=abc'], '_dmarc.example.com TXT': ['v=DMARC1; p=reject'] };
  assert.deepEqual(ids(await run(cleanSite(), 'https://clean.example.com/', good), 'dns.mail'), []);
  const redirect = { ...good, 'example.com TXT': ['V=SPF1 redirect=_spf.example.net'] };
  assert.deepEqual(ids(await run(cleanSite(), 'https://clean.example.com/', redirect), 'dns.mail'), []);
  for (const [spf, pol] of [['v=spf1 +all', '+all'], ['v=spf1 mx all', 'all'], ['v=spf1 ?all', '?all']]) {
    const r = await run(cleanSite(), 'https://clean.example.com/', { ...good, 'example.com TXT': [spf!] });
    assert.deepEqual(ids(r, 'dns.mail'), ['spf-lax']);
    assert.equal(r.result.findings.find((x: any) => x.id === 'dns.mail/spf-lax')!.vars!.policy, pol);
  }
  const multi = await run(cleanSite(), 'https://clean.example.com/', { ...good, 'example.com TXT': ['v=spf1 -all', 'v=spf1 ~all'] });
  assert.deepEqual(ids(multi, 'dns.mail'), ['spf-multiple']);
  const none = await run(cleanSite(), 'https://clean.example.com/', { ...good, '_dmarc.example.com TXT': ['v=DMARC1; p=none; rua=mailto:a@b.c'] });
  assert.deepEqual(ids(none, 'dns.mail'), ['dmarc-none']);
});

test('dns: platform host skipped; failures reported; no dns -> unsupported', async () => {
  const site = { 'https://app.lovable.app/': { headers: { 'content-type': 'text/html' }, body: '<html></html>' }, 'http://app.lovable.app/': { redirect: 'https://app.lovable.app/' } };
  const r = await run(site, 'https://app.lovable.app/', { 'app.lovable.app A': ['1.1.1.1'] });
  assert.equal(r.result.facts['dns.platform'], 'lovable.app');
  assert.deepEqual(ids(r, 'dns.mail'), []);
  assert.ok(r.result.notChecked.some((n: any) => n.module === 'dns.mail' && n.reason === 'condition' && n.detail === 'app on provider domain lovable.app'));
  const f = await run(cleanSite(), 'https://clean.example.com/', { 'example.com TXT': 'SERVFAIL' });
  assert.ok(f.result.notChecked.some((n: any) => n.module === 'collect.dns' && n.reason === 'error'));
  assert.ok(!ids(f, 'dns.mail').includes('spf-missing'));
  const u = await run(cleanSite(), 'https://clean.example.com/');
  assert.ok(u.result.notChecked.some((n: any) => n.module === 'collect.dns' && n.reason === 'unsupported'));
});

const withCsp = (csp: string | null, extra: Record<string, string> = {}, html = '<html><head></head></html>') => ({
  'https://c.example.com/': { headers: { 'content-type': 'text/html', ...(csp ? { 'content-security-policy': csp } : {}), ...extra }, body: html },
  'http://c.example.com/': { redirect: 'https://c.example.com/' },
});
const csp = async (site: any) => ids(await run(site, 'https://c.example.com/'), 'headers.csp-quality');

test('csp: parse and findings', async () => {
  assert.deepEqual([...parseCsp("Default-Src 'self'; img-src data: https:;; ").entries()], [['default-src', ["'self'"]], ['img-src', ['data:', 'https:']]]);
  assert.deepEqual(await csp(withCsp("img-src 'self'")), ['no-script-src', 'object-src']);
  assert.deepEqual(await csp(withCsp("script-src 'self' 'unsafe-inline'; object-src 'none'")), ['unsafe-inline']);
  assert.deepEqual(await csp(withCsp("script-src 'self' 'unsafe-inline' 'nonce-abc'; object-src 'none'")), []);
  assert.deepEqual(await csp(withCsp("default-src 'self' 'unsafe-eval'")), ['unsafe-eval']);
  const w = await run(withCsp("script-src * https: *.com 'self'; object-src 'none'"), 'https://c.example.com/');
  assert.deepEqual(w.result.findings.filter((f: any) => f.id.endsWith('wildcard')).map((f: any) => f.vars.source), ['*', 'https:', '*.com']);
  // img-src wildcard is not a script policy problem
  assert.deepEqual(await csp(withCsp("default-src 'self'; img-src * data:")), []);
});

test('csp: meta tag, report-only, none', async () => {
  const meta = `<html><head><meta http-equiv="Content-Security-Policy" content="script-src 'self' 'unsafe-inline'; object-src 'none'"></head></html>`;
  assert.deepEqual(await csp(withCsp(null, {}, meta)), ['unsafe-inline']);
  assert.deepEqual(await csp(withCsp(null, { 'content-security-policy-report-only': "default-src 'self'" })), ['report-only']);
  assert.deepEqual(await csp(withCsp(null)), []);
});

test('csp: fixture sites with sane CSP produce no csp findings', async () => {
  assert.deepEqual(ids(await run(cleanSite(), 'https://clean.example.com/'), 'headers.csp-quality'), []);
  const { result } = await runOn(boltFirebase(), 'https://recipes.example.com/', plan, { modules });
  assert.deepEqual(result.findings.filter((f) => f.module === 'headers.csp-quality'), []);
});
