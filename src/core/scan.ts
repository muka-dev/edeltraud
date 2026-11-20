import { loadPlan } from './plan.ts';
import { runPlan, type RunOutput } from './processor.ts';
import type { Http, Logger, Plan } from './types.ts';
import { normaliseTarget } from '../fetch/ssrf.ts';
import { LiveHttp } from '../fetch/http.ts';
import { createRegistry } from '../modules/index.ts';

export interface ScanOptions {
  url: string;
  plan?: string | Plan;
  ownershipVerified?: boolean;
  http?: Http;
  log?: Logger;
  record?: boolean;
}

/** Convenience entry point used by CLI and API. */
export async function scan(opts: ScanOptions): Promise<RunOutput & { plan: Plan }> {
  const plan = typeof opts.plan === 'object' ? opts.plan : loadPlan(opts.plan ?? 'ampel');
  const u = normaliseTarget(opts.url);
  const out = await runPlan({
    plan,
    target: { url: u.toString(), host: u.hostname, ownershipVerified: opts.ownershipVerified ?? false },
    registry: createRegistry(),
    http: opts.http ?? new LiveHttp(),
    ...(opts.log ? { log: opts.log } : {}),
    ...(opts.record ? { record: true } : {}),
  });
  return { ...out, plan };
}
