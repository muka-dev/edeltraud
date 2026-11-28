import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { a11yIssues } from '../src/modules/analyze/a11y.ts';
import { findingText } from '../src/i18n/index.ts';
import type { Finding, Lang } from '../src/core/types.ts';

const MODS = [...MODULES];
const URL_ = 'https://x.example.com/';
const plan = (browser = false) =>
  parsePlan({
    plan: 't', limits: { totalMs: 10000, requests: 50, browser },
    modules: ['collect.page', ...(browser ? [{ 'collect.render': { waitMs: 0 } }] : []), { 'collect.crawl': { maxPages: 3 } }, 'collect.errorpages', 'a11y.basics', 'a11y.statement', 'seo.basics', 'ops.404'],
    presentation: { showFindings: 'all', fixPrompts: true },
  });
const html = { 'content-type': 'text/html' };

const GOOD_HEAD = `<title>Vibe – Notizen mit KI</title><meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Notizen schreiben, KI fasst zusammen."><link rel="canonical" href="https://x.example.com/">
  <meta property="og:title" content="Vibe"><meta property="og:image" content="https://x.example.com/og.png">`;
const GOOD_BODY = `<header><a href="/"><img src="/logo.svg" alt="Vibe"></a><button aria-label="Menü öffnen"><svg aria-hidden="true"></svg></button></header>
  <main><h1>Notizen mit KI</h1><img src="/deko.png" alt=""><img src="/x.png" role="presentation">
  <form><label for="mail">E-Mail</label><input id="mail" type="email"><label>Name <input name="name"></label>
  <input type="hidden" name="csrf"><input type="search" aria-label="Suche"><button type="submit">Senden</button></form></main>
  <footer><a href="/impressum">Impressum</a> <a href="/datenschutz">Datenschutz</a> <a href="/barrierefreiheit">Erklärung zur Barrierefreiheit</a></footer>`;
const good = `<!doctype html><html lang="de"><head>${GOOD_HEAD}</head><body>${GOOD_BODY}</body></html>`;
const bad = `<!doctype html><html><head><meta name="viewport" content="width=device-width, user-scalable=no">
  <meta name="robots" content="noindex, nofollow"></head><body>
  <h1>Eins</h1><h1>Zwei</h1><img src="/img/hero.png?v=3"><img src="/a.png" aria-hidden="true">
  <a href="https://twitter.com/x"><svg viewBox="0 0 1 1"><path d="M0"/></svg></a><button class="close"><i class="icon-x"></i></button>
  <input type="email" id="newsletter" placeholder="E-Mail"><textarea name="msg"></textarea>
  <p>Ein Absatz mit genug Text, damit das hier keine leere App-Hülle ist.</p><a href="/impressum">Impressum</a></body></html>`;
const shell = `<!doctype html><html lang="en"><head><title>App</title></head><body><div id="root"></div><script type="module" src="/assets/index-a1b2c3d4.js"></script></body></html>`;

const ids = (fs: Finding[], prefix: string) => fs.filter((f) => f.id.startsWith(prefix)).map((f) => f.id).sort();
const byKind = (fs: Finding[], id: string) => fs.find((f) => f.id === id)!;
const notFound = { status: 404, headers: html, body: '<h1>Not found</h1>' };
const site = (start: string, extra: Record<string, unknown> = {}) => ({
  [URL_]: { headers: html, body: start },
  'https://x.example.com/edeltraud-check-404': notFound,
  'https://x.example.com/api/edeltraud-check-404': { status: 404, headers: { 'content-type': 'application/json' }, body: '{"error":"not found"}' },
  ...extra,
});

test('a11y.basics: clean page has no findings, every rule fires on the bad page', async () => {
  const ok = await runOn(site(good), URL_, plan(), { modules: MODS });
  assert.deepEqual(ids(ok.result.findings, 'a11y.'), []);
  assert.deepEqual(ids(ok.result.findings, 'seo.'), []);
  assert.deepEqual(ids(ok.result.findings, 'ops.404'), []);

  const { result } = await runOn(site(bad), URL_, plan(), { modules: MODS });
  assert.deepEqual(ids(result.findings, 'a11y.basics'), [
    'a11y.basics/control-name', 'a11y.basics/img-alt', 'a11y.basics/input-label', 'a11y.basics/no-lang', 'a11y.basics/no-title', 'a11y.basics/zoom-blocked',
  ]);
  const img = byKind(result.findings, 'a11y.basics/img-alt');
  assert.equal(img.vars!.count, '1');
  assert.equal(img.vars!.sample, 'img[src=hero.png]');
  assert.equal(img.severity, 'low');
  assert.equal(img.category, 'accessibility');
  const inp = byKind(result.findings, 'a11y.basics/input-label');
  assert.equal(inp.vars!.count, '2');
  assert.equal(inp.vars!.sample, 'input[type=email]#newsletter, textarea[name=msg]');
  const ctl = byKind(result.findings, 'a11y.basics/control-name');
  assert.equal(ctl.vars!.count, '2');
  assert.equal(ctl.vars!.sample, 'a[href=https://twitter.com/x], button.close');
  assert.equal(byKind(result.findings, 'a11y.basics/no-lang').severity, 'medium');
  assert.equal(byKind(result.findings, 'a11y.basics/zoom-blocked').severity, 'medium');
});

test('a11y.basics: zoom rule thresholds and label variants', () => {
  const rules = (h: string) => [...a11yIssues(h).keys()].sort();
  const base = (meta: string) => `<html lang="de"><head><title>T</title>${meta}</head><body></body></html>`;
  assert.deepEqual(rules(base('<meta name="viewport" content="width=device-width, maximum-scale=1">')), ['zoom-blocked']);
  assert.deepEqual(rules(base('<meta name="viewport" content="width=device-width, maximum-scale=5">')), []);
  assert.deepEqual(rules(base('<meta name="viewport" content="user-scalable=0">')), ['zoom-blocked']);
  assert.deepEqual(rules('<html lang=""><title> </title></html>'), ['no-lang', 'no-title']);
  // <title> inside an SVG is not the page title.
  assert.deepEqual(rules('<html lang="de"><body><svg><title>Icon</title></svg></body></html>'), ['no-title']);
  const ok = '<html lang="de"><title>T</title><input title="Suche"><select aria-labelledby="l"></select><a href="/x" title="Start"></a><a href="/y"><img src="a.png" alt="Start"></a><a name="anchor"></a>';
  assert.deepEqual(rules(ok), []);
});

test('a11y.basics: counts subpages, samples at most 3', async () => {
  const sub = `<html lang="de"><head><title>Preise</title></head><body><p>Preise und Pakete für alle, mit genug Text auf der Seite.</p><img src="/1.png"><img src="/2.png"><img src="/3.png"><img src="/4.png"></body></html>`;
  const start = good.replace('<a href="/impressum">', '<a href="/preise">Preise</a><a href="/impressum">').replace('alt="Vibe"', '');
  const { result } = await runOn(site(start, { 'https://x.example.com/preise': { headers: html, body: sub } }), URL_, plan(), { modules: MODS });
  const img = byKind(result.findings, 'a11y.basics/img-alt');
  assert.equal(img.vars!.count, '5');
  assert.equal(img.vars!.pages, '2');
  assert.equal(img.vars!.sample!.split(', ').length, 3);
});

test('SPA shell without rendering: a11y skipped as condition, SEO head checks still run', async () => {
  const { result } = await runOn(site(shell), URL_, plan(), { modules: MODS });
  assert.deepEqual(ids(result.findings, 'a11y.'), []);
  const nc = result.notChecked.filter((n) => n.module.startsWith('a11y.'));
  assert.deepEqual(nc.map((n) => [n.module, n.reason]).sort(), [['a11y.basics', 'condition'], ['a11y.statement', 'condition']]);
  assert.match(nc[0]!.detail!, /rendered/);
  // Head tags are in the shell; h1 cannot be judged without the rendered page.
  assert.deepEqual(ids(result.findings, 'seo.'), ['seo.basics/canonical-missing', 'seo.basics/description-missing', 'seo.basics/og-missing']);
});

test('SPA shell with rendering: a11y and h1 use the rendered DOM', async () => {
  const { result } = await runOn(site(shell), URL_, plan(true), {
    modules: MODS,
    render: { [URL_]: { html: `<html lang="en"><head><title>App</title></head><body><div id="root"><img src="/a.png"><a href="/accessibility">Accessibility statement</a></div></body></html>`, links: [{ href: 'https://x.example.com/accessibility', text: 'Accessibility statement' }] } },
  });
  assert.deepEqual(ids(result.findings, 'a11y.'), ['a11y.basics/img-alt']);
  assert.ok(ids(result.findings, 'seo.').includes('seo.basics/h1-missing'));
});

test('a11y.statement: missing link is a low, possible hint; PT and EN texts count', async () => {
  const { result } = await runOn(site(bad), URL_, plan(), { modules: MODS });
  const f = byKind(result.findings, 'a11y.statement/missing');
  assert.equal(f.severity, 'low');
  assert.equal(f.confidence, 'possible');
  for (const link of ['<a href="/legal/a11y">Acessibilidade</a>', '<a href="/accessibility">A11y</a>', '<a href="/hilfe">Declaração de acessibilidade</a>']) {
    const r = await runOn(site(bad.replace('</body>', `${link}</body>`)), URL_, plan(), { modules: MODS });
    assert.deepEqual(ids(r.result.findings, 'a11y.statement'), [], link);
  }
});

test('seo.basics: noindex, long title, h1 count, OG, header noindex', async () => {
  const { result } = await runOn(site(bad), URL_, plan(), { modules: MODS });
  assert.deepEqual(ids(result.findings, 'seo.'), [
    'seo.basics/canonical-missing', 'seo.basics/description-missing', 'seo.basics/h1-multiple', 'seo.basics/noindex', 'seo.basics/og-missing', 'seo.basics/title-missing',
  ]);
  assert.equal(byKind(result.findings, 'seo.basics/noindex').severity, 'medium');
  assert.equal(byKind(result.findings, 'seo.basics/noindex').vars!.source, 'meta robots');
  assert.equal(byKind(result.findings, 'seo.basics/h1-multiple').vars!.count, '2');
  assert.equal(byKind(result.findings, 'seo.basics/og-missing').vars!.list, 'og:title, og:image');

  const long = good.replace('<title>Vibe – Notizen mit KI</title>', `<title>${'Sehr langer Titel '.repeat(5)}</title>`).replace('<h1>Notizen mit KI</h1>', '');
  const r = await runOn({ ...site(long), [URL_]: { headers: { ...html, 'X-Robots-Tag': 'noindex' }, body: long } }, URL_, plan(), { modules: MODS });
  assert.deepEqual(ids(r.result.findings, 'seo.'), ['seo.basics/h1-missing', 'seo.basics/noindex', 'seo.basics/title-long']);
  assert.equal(byKind(r.result.findings, 'seo.basics/noindex').vars!.source, 'X-Robots-Tag');
  assert.equal(byKind(r.result.findings, 'seo.basics/title-long').vars!.length, '89');
});

test('ops.404: soft 404 from the SPA fallback, clean 404 and JSON 200 are fine', async () => {
  const spa = { headers: html, body: good };
  const { result } = await runOn(site(good, { 'https://x.example.com/edeltraud-check-404': spa, 'https://x.example.com/api/edeltraud-check-404': spa }), URL_, plan(), { modules: MODS });
  const f = byKind(result.findings, 'ops.404/soft-404');
  assert.equal(f.severity, 'low');
  assert.equal(f.category, 'operations');
  assert.equal(f.vars!.paths, '/edeltraud-check-404, /api/edeltraud-check-404');
  assert.equal(f.vars!.status, '200');
  const json = await runOn(site(good, { 'https://x.example.com/api/edeltraud-check-404': { headers: { 'content-type': 'application/json' }, body: '{}' } }), URL_, plan(), { modules: MODS });
  assert.deepEqual(ids(json.result.findings, 'ops.404'), []);
});

test('texts exist and are filled in all languages, with the BFSG note', async () => {
  const { result } = await runOn(site(bad, { 'https://x.example.com/edeltraud-check-404': { headers: html, body: bad } }), URL_, plan(), { modules: MODS });
  const fs = result.findings.filter((f) => /^(a11y|seo|ops\.404)/.test(f.module));
  assert.equal(fs.length, 14);
  for (const lang of ['de', 'en', 'pt', 'pt-BR'] as Lang[]) {
    for (const f of fs) {
      const t = findingText(lang, f.messageKey, f.vars);
      assert.ok(t.title && t.explain && t.fix && !t.title.startsWith(f.messageKey), `${lang} ${f.messageKey}`);
      assert.ok(!/\{\w+\}/.test(t.title + t.explain + t.fix), `${lang} ${f.messageKey} placeholder`);
      if (f.module === 'a11y.basics') assert.match(t.explain, /BFSG/);
    }
  }
});
