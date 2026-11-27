import { runPlan } from '../src/core/processor.ts';
import { parsePlan, loadPlan } from '../src/core/plan.ts';
import { createRegistry } from '../src/modules/index.ts';
import { ReplayHttp, type FixtureResponse } from '../src/fetch/replay.ts';
import { ReplayDns } from '../src/fetch/dns.ts';
import { ReplayTls } from '../src/fetch/tls-replay.ts';
import { ReplayBrowser } from '../src/fetch/browser-replay.ts';
import type { CheckModule, Plan, RenderData, TlsInfo } from '../src/core/types.ts';

export async function runOn(
  site: Record<string, FixtureResponse>,
  url: string,
  plan: Plan | string = 'ampel',
  extra: {
    ownershipVerified?: boolean;
    modules?: CheckModule<any>[];
    /** 'name TYPE' → answers; without it, DNS collectors report 'unsupported'. */
    dns?: Record<string, string[] | 'SERVFAIL'>;
    /** host → handshake; without it, TLS collectors report 'unsupported'. */
    tls?: Record<string, Partial<TlsInfo>>;
    /** URL → rendered page; without it, collect.render reports 'unsupported'. */
    render?: Record<string, Partial<RenderData>>;
  } = {},
) {
  const p = typeof plan === 'string' ? loadPlan(plan) : plan;
  const http = new ReplayHttp(site);
  const host = new URL(url).hostname;
  const out = await runPlan({
    plan: p,
    target: { url, host, ownershipVerified: extra.ownershipVerified ?? false },
    registry: createRegistry(extra.modules),
    http,
    ...(extra.dns ? { dns: new ReplayDns(extra.dns) } : {}),
    ...(extra.tls ? { tls: new ReplayTls(extra.tls) } : {}),
    ...(extra.render ? { browser: new ReplayBrowser(extra.render) } : {}),
  });
  return { ...out, http, plan: p };
}

export { parsePlan };
