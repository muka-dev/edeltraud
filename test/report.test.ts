import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { runOn } from './helpers.ts';
import { vulnerableSite } from './fixtures/sites.ts';
import { present, renderText } from '../src/report/present.ts';
import { CATALOGS, LANGS, hasPrompts, prompts } from '../src/i18n/index.ts';

test('ampel shows 3 findings, locks the rest as counts, no prompts', async () => {
  const { result, plan } = await runOn(vulnerableSite(), 'https://vibe.example.com/', 'ampel');
  const p = present(result, plan, 'de');
  assert.equal(p.findings.length, 3);
  assert.ok(p.findings.every((f) => f.prompt === undefined));
  assert.equal(p.findings[0]!.severity, 'critical');
  const lockedTotal = Object.values(p.locked).reduce((a, b) => a + b, 0);
  assert.equal(lockedTotal, result.findings.length - 3);
  assert.match(p.lockedText ?? '', /Weitere Befunde im Bericht: .*hoch/);
  // locked findings leave no details in the presented output
  const hidden = result.findings.filter((f) => !p.findings.some((v) => v.fingerprint === f.fingerprint));
  const json = JSON.stringify(p);
  for (const h of hidden) assert.ok(!json.includes(h.fingerprint));
});

test('report shows everything with prompts, in all languages', async () => {
  const { result, plan } = await runOn(vulnerableSite(), 'https://vibe.example.com/', 'report');
  for (const lang of LANGS) {
    const p = present(result, plan, lang);
    assert.equal(p.findings.length, result.findings.length);
    for (const f of p.findings) {
      // Prompts are the private part; the open core runs without them.
      if (hasPrompts()) assert.ok(f.prompt && f.prompt.length > 20, `${lang} ${f.id} prompt`);
      assert.ok(!/\{\w+\}/.test(f.title + f.explain + f.fix + (f.prompt ?? '')), `${lang} ${f.id} unfilled placeholder`);
    }
    assert.ok(renderText(p).includes(p.disclaimer));
  }
});

test('every message key used in the code exists in every language', () => {
  const keys = new Set<string>();
  const walk = (dir: string) => {
    for (const e of readdirSync(dir, { withFileTypes: true })) {
      const p = `${dir}/${e.name}`;
      if (e.isDirectory()) walk(p);
      else if (p.endsWith('.ts')) for (const m of readFileSync(p, 'utf8').matchAll(/messageKey(?::|\s*=)\s*['"]([\w.-]+)['"]/g)) keys.add(m[1]!);
    }
  };
  walk('src/modules');
  assert.ok(keys.size > 10);
  for (const lang of LANGS) {
    for (const k of keys) assert.ok(CATALOGS[lang].findings[k], `${lang}: missing ${k}`);
    assert.deepEqual(Object.keys(CATALOGS[lang].ui).sort(), Object.keys(CATALOGS.en.ui).sort(), `${lang}: ui keys`);
    assert.deepEqual(Object.keys(CATALOGS[lang].findings).sort(), Object.keys(CATALOGS.en.findings).sort(), `${lang}: finding keys`);
    if (hasPrompts()) assert.deepEqual(Object.keys(prompts(lang)).sort(), Object.keys(CATALOGS.en.findings).sort(), `${lang}: prompt keys`);
  }
});

test('wording rules: German without du/Sie, no promises of safety anywhere', () => {
  const de = JSON.stringify(CATALOGS.de) + JSON.stringify(prompts('de'));
  assert.ok(!/\b(du|dich|dir|dein\w*|Sie|Ihnen|Ihr\w*)\b/.test(de), 'German text must not address the reader');
  for (const lang of LANGS) {
    const t = (JSON.stringify(CATALOGS[lang]) + JSON.stringify(prompts(lang))).toLowerCase();
    for (const bad of ['ist sicher', 'is secure', 'is safe', 'está segura', 'está seguro', 'garantiert', 'guaranteed', 'zertifiziert', 'certified', 'compliant', 'dsgvo-konform']) {
      assert.ok(!t.includes(bad), `${lang}: "${bad}"`);
    }
  }
});

test('without the private prompt catalogs the report simply has no prompts', async () => {
  const { execFileSync } = await import('node:child_process');
  const out = execFileSync(process.execPath, ['scripts/demo.ts', 'report', 'en'], {
    env: { ...process.env, EDELTRAUD_PROMPTS_DIR: '/nonexistent' },
    encoding: 'utf8',
  });
  assert.ok(out.includes('Secret OpenAI key'));
  assert.ok(!out.includes('Prompt:'));
});
