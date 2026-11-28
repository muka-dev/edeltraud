import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parsePlan, loadPlan } from '../src/core/plan.ts';
import { resolveParams } from '../src/core/params.ts';
import { layers } from '../src/core/graph.ts';
import { verdict, dedupe } from '../src/core/verdict.ts';
import { finding, mask, normaliseLocation } from '../src/core/finding.ts';
import { createRegistry, MODULES } from '../src/modules/index.ts';
import { preparePlan } from '../src/core/processor.ts';
import type { ModuleManifest } from '../src/core/types.ts';

const m = (id: string, requires: string[] = [], provides: string[] = [], extra: Partial<ModuleManifest> = {}): ModuleManifest => ({
  id, version: '1', kind: 'analyzer', mode: 'passive', category: 'security', requires, provides, params: {}, budget: {}, ...extra,
});

test('plans parse bare ids and parameter maps, reject duplicates', () => {
  const p = parsePlan('plan: x\nmodules:\n  - a\n  - b: { n: 2 }\n');
  assert.deepEqual(p.modules, [{ module: 'a', params: {} }, { module: 'b', params: { n: 2 } }]);
  assert.throws(() => parsePlan('plan: x\nmodules: [a, a]'));
  assert.throws(() => parsePlan('plan: X!\nmodules: [a]'));
  assert.throws(() => loadPlan('../etc/passwd'));
});

test('all shipped plans are valid against the registry', () => {
  const reg = createRegistry();
  for (const name of ['ampel', 'report', 'deep', 'watch']) assert.doesNotThrow(() => preparePlan(loadPlan(name), reg), name);
});

test('parameters get defaults and are validated', () => {
  const schema = { n: { type: 'number', default: 5, min: 1, max: 10 }, b: { type: 'boolean', default: false } } as const;
  assert.deepEqual(resolveParams('x', schema, {}), { n: 5, b: false });
  assert.deepEqual(resolveParams('x', schema, { n: 7 }), { n: 7, b: false });
  assert.throws(() => resolveParams('x', schema, { n: 11 }));
  assert.throws(() => resolveParams('x', schema, { n: 'a' }));
  assert.throws(() => resolveParams('x', schema, { other: 1 }));
});

test('graph orders by requires, uses and when; reports unmet and cycles', () => {
  const { layers: ls, unmet } = layers([
    m('analyze', ['artifact:page'], [], { uses: ['artifact:js'] }),
    m('cond', [], [], { when: ['fact:x'] }),
    m('page', [], ['artifact:page']),
    m('js', ['artifact:page'], ['artifact:js', 'fact:x']),
    m('orphan', ['artifact:nothing']),
  ]);
  const pos = (id: string) => ls.findIndex((l) => l.some((x) => x.id === id));
  assert.ok(pos('page') < pos('js'));
  assert.ok(pos('js') < pos('analyze'));
  assert.ok(pos('js') < pos('cond'));
  assert.deepEqual(unmet.get('orphan'), ['artifact:nothing']);
  assert.throws(() => layers([m('a', ['x'], ['y']), m('b', ['y'], ['x'])]), /cycle/);
});

test('verdict rule', () => {
  const f = (severity: any, fp: string) => finding(m('t'), { kind: fp, severity, location: { url: fp }, messageKey: 'k' });
  assert.equal(verdict([]).light, 'green');
  assert.equal(verdict([f('medium', 'a'), f('medium', 'b')]).light, 'green');
  assert.equal(verdict([f('medium', 'a'), f('medium', 'b'), f('medium', 'c')]).light, 'yellow');
  assert.equal(verdict([f('high', 'a')]).light, 'yellow');
  assert.equal(verdict([f('high', 'a'), f('high', 'b')]).light, 'red');
  assert.equal(verdict([f('critical', 'a')]).light, 'red');
  assert.equal(dedupe([f('low', 'a'), f('low', 'a')]).length, 1);
});

test('masking never reveals the middle of a secret', () => {
  const s = 'sk-ant-api03-' + 'q'.repeat(90) + 'WXYZ';
  assert.equal(mask(s), 'sk-ant…WXYZ');
  assert.equal(mask('short'), 'sho…');
});

test('fingerprints ignore cache-busting bundle hashes', () => {
  assert.equal(normaliseLocation({ url: 'https://a.com/assets/index-Bx7kP2qa.js?v=1' }), normaliseLocation({ url: 'https://a.com/assets/index-Zz9yY8xX.js' }));
});

test('module ids are unique and manifests well-formed', () => {
  const ids = MODULES.map((x) => x.manifest.id);
  assert.equal(new Set(ids).size, ids.length);
  for (const x of MODULES) {
    assert.match(x.manifest.id, /^[a-z][a-z0-9]*(\.[a-z0-9-]+)+$/);
    assert.match(x.manifest.version, /^\d+\.\d+\.\d+$/);
    if (x.manifest.kind === 'analyzer') assert.equal(x.manifest.mode, 'passive', `${x.manifest.id}: analyzers are passive`);
  }
});
