import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { LiveBrowser } from '../src/fetch/browser.ts';
import { findingText } from '../src/i18n/index.ts';
import { cleanSite } from './fixtures/sites.ts';
import type { Lang, RenderAudit } from '../src/core/types.ts';

const URL_ = 'https://clean.example.com/';
const plan = parsePlan({
  plan: 't', limits: { totalMs: 10000, requests: 20, browser: true },
  modules: ['collect.page', { 'collect.render': { waitMs: 0, audit: true } }, 'a11y.axe', 'perf.weight', 'perf.vitals'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const MB = 1024 * 1024;
const audit: RenderAudit = {
  axe: {
    version: '4.14.1',
    violations: [
      { id: 'color-contrast', impact: 'serious', nodes: 7, targets: ['.hint', 'footer > p', '#price'] },
      { id: 'image-alt', impact: 'critical', nodes: 2, targets: ['img'] },
      { id: 'aria-allowed-attr', impact: 'critical', nodes: 1, targets: ['#menu'] },
    ],
  },
  perf: { lcpMs: 4800, cls: 0.12, tbtMs: 150, bytes: { script: 1.6 * MB, image: 2 * MB, document: 50_000 }, largestImages: [{ url: 'https://clean.example.com/hero.png', bytes: 1.2 * MB }, { url: 'https://clean.example.com/s.png', bytes: 20_000 }] },
};

test('a11y.axe and perf.*: findings from the render audit, basics rules not repeated', async () => {
  const { result } = await runOn(cleanSite(), URL_, plan, { render: { [URL_]: { html: '<html lang="de"></html>', audit } } });
  const by = (id: string) => result.findings.find((f) => f.id === id);
  assert.equal(by('a11y.axe/color-contrast')?.severity, 'medium');
  assert.equal(by('a11y.axe/color-contrast')?.messageKey, 'a11y.contrast');
  assert.equal(by('a11y.axe/aria-allowed-attr')?.severity, 'high');
  assert.equal(by('a11y.axe/image-alt'), undefined, 'covered by a11y.basics');
  assert.match(by('a11y.axe/aria-allowed-attr')!.vars!.link!, /rules\/axe\/4\.14\/aria-allowed-attr$/);
  assert.equal(by('perf.weight/total')?.severity, 'low');
  assert.ok(by('perf.weight/script'));
  assert.equal(by('perf.weight/image')?.vars?.count, '1');
  assert.equal(by('perf.vitals/lcp')?.severity, 'medium');
  assert.equal(by('perf.vitals/cls')?.severity, 'low');
  assert.equal(by('perf.vitals/tbt'), undefined);
  for (const lang of ['de', 'en', 'pt', 'pt-BR'] as Lang[]) {
    for (const f of result.findings) {
      const t = findingText(lang, f.messageKey, f.vars);
      assert.ok(t.title && !/\{\w+\}/.test(t.title + t.explain + t.fix), `${lang} ${f.messageKey}`);
    }
  }
});

test('lab modules: condition without audit, error when axe failed', async () => {
  const none = await runOn(cleanSite(), URL_, plan, { render: { [URL_]: {} } });
  assert.deepEqual(none.result.notChecked.filter((n) => n.reason === 'condition').map((n) => n.module).sort(), ['a11y.axe', 'perf.vitals', 'perf.weight']);
  const err = await runOn(cleanSite(), URL_, plan, { render: { [URL_]: { audit: { axe: { error: 'boom' } } } } });
  assert.ok(err.result.notChecked.some((n) => n.module === 'a11y.axe' && n.reason === 'error'));
});

test('LiveBrowser audit runs bundled axe-core despite a strict CSP (skipped without Chromium)', async (t) => {
  const server = http.createServer((_req, res) => {
    res.setHeader('content-type', 'text/html');
    res.setHeader('content-security-policy', "script-src 'self'");
    res.end('<html lang="de"><head><title>T</title></head><body><p style="color:#ccc;background:#fff">blass</p><div role="buttonx">x</div></body></html>');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  try {
    const b = new LiveBrowser({ allowUrl: async (u) => u.startsWith(base) });
    let data;
    try {
      data = await b.render(base + '/', { waitMs: 100, maxRequests: 20, timeoutMs: 15000, audit: true });
    } catch (e) {
      if (/Playwright is not installed|Executable doesn't exist|launch/i.test(String(e))) return t.skip(String(e).slice(0, 80));
      throw e;
    }
    const axe = data.audit?.axe;
    assert.ok(axe && 'violations' in axe, JSON.stringify(axe));
    assert.ok(axe.violations.some((v) => v.id === 'color-contrast'), JSON.stringify(axe));
    assert.ok(!JSON.stringify(axe).includes('blass'), 'no element text leaves the page');
    assert.ok((data.audit!.perf!.bytes.document ?? 0) > 0);
  } finally {
    server.close();
  }
});
