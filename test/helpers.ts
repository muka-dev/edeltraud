import { runPlan } from '../src/core/processor.ts';
import { parsePlan, loadPlan } from '../src/core/plan.ts';
import { createRegistry } from '../src/modules/index.ts';
import { ReplayHttp, type FixtureResponse } from '../src/fetch/replay.ts';
import type { CheckModule, Plan } from '../src/core/types.ts';

export async function runOn(
  site: Record<string, FixtureResponse>,
  url: string,
  plan: Plan | string = 'ampel',
  extra: { ownershipVerified?: boolean; modules?: CheckModule<any>[] } = {},
) {
  const p = typeof plan === 'string' ? loadPlan(plan) : plan;
  const http = new ReplayHttp(site);
  const host = new URL(url).hostname;
  const out = await runPlan({
    plan: p,
    target: { url, host, ownershipVerified: extra.ownershipVerified ?? false },
    registry: createRegistry(extra.modules),
    http,
  });
  return { ...out, http, plan: p };
}

export { parsePlan };
