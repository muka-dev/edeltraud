import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runPlan } from '../src/core/processor.ts';
import { parsePlan } from '../src/core/plan.ts';
import { createRegistry } from '../src/modules/index.ts';
import { ReplayHttp } from '../src/fetch/replay.ts';
import type { CheckModule } from '../src/core/types.ts';

const target = { url: 'https://t.example.com/', host: 't.example.com', ownershipVerified: false };

const base = (id: string, extra: Partial<CheckModule['manifest']> = {}) => ({
  id, version: '0.0.1', kind: 'analyzer' as const, mode: 'passive' as const, category: 'security' as const,
  requires: [], provides: [], params: {}, budget: {}, ...extra,
});

test('active modules are skipped without proof of ownership', async () => {
  let ran = false;
  const probe: CheckModule = { manifest: base('probe.x', { kind: 'probe', mode: 'active' }), run: () => ((ran = true), {}) };
  const plan = parsePlan({ plan: 't', modules: ['probe.x'] });
  const { result } = await runPlan({ plan, target, registry: createRegistry([probe]), http: new ReplayHttp({}) });
  assert.equal(ran, false);
  assert.deepEqual(result.notChecked, [{ module: 'probe.x', reason: 'ownership' }]);

  const verified = await runPlan({ plan, target: { ...target, ownershipVerified: true }, registry: createRegistry([probe]), http: new ReplayHttp({}) });
  assert.equal(ran, true);
  assert.equal(verified.result.notChecked.length, 0);
});

test('a failing module does not stop the plan; dependents are marked', async () => {
  const boom: CheckModule = { manifest: base('collect.boom', { kind: 'collector', provides: ['artifact:x'] }), run: () => { throw new Error('kaputt'); } };
  const user: CheckModule = { manifest: base('use.x', { requires: ['artifact:x'] }), run: () => ({}) };
  const other: CheckModule = { manifest: base('other.y'), run: () => ({ facts: { y: 1 } }) };
  const plan = parsePlan({ plan: 't', modules: ['collect.boom', 'use.x', 'other.y'] });
  const { result } = await runPlan({ plan, target, registry: createRegistry([boom, user, other]), http: new ReplayHttp({}) });
  assert.deepEqual(result.notChecked.find((n) => n.module === 'collect.boom'), { module: 'collect.boom', reason: 'error', detail: 'kaputt' });
  assert.equal(result.notChecked.find((n) => n.module === 'use.x')?.reason, 'dependency');
  assert.equal(result.facts['y'], 1);
});

test('request budget is enforced and analyzers get no network', async () => {
  let sawHttp: unknown = 'unset';
  const greedy: CheckModule = {
    manifest: base('collect.greedy', { kind: 'collector' }),
    async run(ctx) {
      for (let i = 0; i < 10; i++) await ctx.http!.fetch({ url: `https://t.example.com/${i}` });
      return {};
    },
  };
  const pure: CheckModule = { manifest: base('pure.a'), run: (ctx) => ((sawHttp = ctx.http), {}) };
  const plan = parsePlan({ plan: 't', limits: { requests: 3 }, modules: ['collect.greedy', 'pure.a'] });
  const http = new ReplayHttp({});
  const { result } = await runPlan({ plan, target, registry: createRegistry([greedy, pure]), http });
  assert.equal(http.log.length, 3);
  assert.equal(result.requests, 3);
  assert.equal(result.notChecked[0]?.reason, 'budget');
  assert.equal(sawHttp, undefined);
});

test('when-conditions switch modules off', async () => {
  const set: CheckModule = { manifest: base('stack.x', { provides: ['fact:stack.supabase'] }), run: () => ({ facts: { 'stack.supabase': false } }) };
  let ran = false;
  const sb: CheckModule = { manifest: base('sb.x', { when: ['fact:stack.supabase'] }), run: () => ((ran = true), {}) };
  const plan = parsePlan({ plan: 't', modules: ['sb.x', 'stack.x'] });
  const { result } = await runPlan({ plan, target, registry: createRegistry([set, sb]), http: new ReplayHttp({}) });
  assert.equal(ran, false);
  assert.equal(result.notChecked[0]?.reason, 'condition');
});

test('unknown modules and invalid parameters fail the plan early', async () => {
  const registry = createRegistry();
  await assert.rejects(runPlan({ plan: parsePlan({ plan: 't', modules: ['nope'] }), target, registry, http: new ReplayHttp({}) }), /unknown module/);
  await assert.rejects(
    runPlan({ plan: parsePlan({ plan: 't', modules: [{ 'collect.bundles': { maxBundles: 0 } }] }), target, registry, http: new ReplayHttp({}) }),
    /below/,
  );
});

test('module time limit', async () => {
  const slow: CheckModule = { manifest: base('slow.x', { budget: { ms: 20 } }), run: () => new Promise((r) => setTimeout(() => r({}), 500)) };
  const plan = parsePlan({ plan: 't', modules: ['slow.x'] });
  const { result } = await runPlan({ plan, target, registry: createRegistry([slow]), http: new ReplayHttp({}) });
  assert.equal(result.notChecked[0]?.reason, 'budget');
});
