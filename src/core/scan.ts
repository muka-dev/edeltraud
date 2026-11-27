import { loadPlan } from './plan.ts';
import { runPlan, type RunOutput } from './processor.ts';
import type { Browser, Dns, Http, Logger, Plan, TlsInspector } from './types.ts';
import { normaliseTarget } from '../fetch/ssrf.ts';
import { LiveHttp } from '../fetch/http.ts';
import { LiveDns } from '../fetch/dns.ts';
import { LiveTls } from '../fetch/tls.ts';
import { LiveBrowser } from '../fetch/browser.ts';
import { createRegistry } from '../modules/index.ts';

export interface ScanOptions {
  url: string;
  plan?: string | Plan;
  ownershipVerified?: boolean;
  http?: Http;
  dns?: Dns;
  tls?: TlsInspector;
  browser?: Browser;
  log?: Logger;
  record?: boolean;
}

/** Convenience entry point used by CLI and API. */
export async function scan(opts: ScanOptions): Promise<RunOutput & { plan: Plan }> {
  const plan = typeof opts.plan === 'object' ? opts.plan : loadPlan(opts.plan ?? 'ampel');
  const u = normaliseTarget(opts.url);
  // Replayed HTTP comes without live DNS/TLS, so a replay never touches the network.
  const live = !opts.http;
  const dns = opts.dns ?? (live ? new LiveDns() : undefined);
  const tls = opts.tls ?? (live ? new LiveTls() : undefined);
  const browser = opts.browser ?? (live && plan.limits.browser ? new LiveBrowser() : undefined);
  const out = await runPlan({
    plan,
    target: { url: u.toString(), host: u.hostname, ownershipVerified: opts.ownershipVerified ?? false },
    registry: createRegistry(),
    http: opts.http ?? new LiveHttp(),
    // Replayed HTTP comes without live DNS/TLS, so a replay never touches the network.
    ...(dns ? { dns } : {}),
    ...(tls ? { tls } : {}),
    ...(browser ? { browser } : {}),
    ...(opts.log ? { log: opts.log } : {}),
    ...(opts.record ? { record: true } : {}),
  });
  return { ...out, plan };
}
