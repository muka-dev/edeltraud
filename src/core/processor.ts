import { layers } from './graph.ts';
import { PlanError, resolveParams } from './params.ts';
import { ArtifactStore, FactStore } from './stores.ts';
import { dedupe, verdict } from './verdict.ts';
import { BudgetedHttp, BudgetExceededError } from '../fetch/http.ts';
import type {
  Browser, CheckModule, Dns, Finding, Http, TlsInspector, Logger, ModuleManifest, NotChecked, Params, Plan, ScanResult, Target,
} from './types.ts';

export const TOOL_VERSION = '0.1.0';

export interface RunOptions {
  plan: Plan;
  target: Target;
  registry: ReadonlyMap<string, CheckModule>;
  http: Http;
  dns?: Dns;
  tls?: TlsInspector;
  browser?: Browser;
  log?: Logger;
  /** Keep the request/response log for replay fixtures. */
  record?: boolean;
  now?: () => number;
}

export interface RunOutput {
  result: ScanResult;
  artifacts: ArtifactStore;
  recorded: BudgetedHttp['recorded'];
}

const quiet: Logger = { debug() {}, warn() {} };

/** Validates the plan against the registry and resolves all parameters. */
export function preparePlan(plan: Plan, registry: ReadonlyMap<string, CheckModule>) {
  return plan.modules.map((step) => {
    const mod = registry.get(step.module);
    if (!mod) throw new PlanError(`${plan.plan}: unknown module '${step.module}'`);
    if (mod.manifest.budget.browser && !plan.limits.browser) {
      throw new PlanError(`${plan.plan}: ${step.module} needs a browser, the plan does not allow one`);
    }
    return { mod, params: resolveParams(step.module, mod.manifest.params, step.params) };
  });
}

/**
 * The check processor: runs a plan's modules in dependency order, within the plan's
 * time and request budget, and merges everything into one ScanResult.
 * Modules never throw past this function; failures become 'not checked' entries.
 */
export async function runPlan(opts: RunOptions): Promise<RunOutput> {
  const now = opts.now ?? Date.now;
  const log = opts.log ?? quiet;
  const started = now();
  const { plan, target } = opts;

  const steps = preparePlan(plan, opts.registry);
  const notChecked: NotChecked[] = [];

  // Active modules only after proof of ownership.
  const runnable = steps.filter(({ mod }) => {
    if (mod.manifest.mode === 'active' && !target.ownershipVerified) {
      notChecked.push({ module: mod.manifest.id, reason: 'ownership' });
      return false;
    }
    return true;
  });

  const byId = new Map(runnable.map((s) => [s.mod.manifest.id, s]));
  const { layers: order, unmet } = layers(runnable.map((s) => s.mod.manifest));

  const artifacts = new ArtifactStore();
  const facts = new FactStore();
  const http = new BudgetedHttp(opts.http, plan.limits.requests, opts.record);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), plan.limits.totalMs);
  const findings: Finding[] = [];
  const status: ScanResult['modules'] = [];
  let complete = true;

  try {
    for (const layer of order) {
      await Promise.all(
        layer.map(async (m) => {
          const { mod, params } = byId.get(m.id)!;
          const t0 = now();
          const skip = (reason: NotChecked['reason'], detail?: string) => {
            if (reason !== 'condition') complete = false;
            notChecked.push(detail ? { module: m.id, reason, detail } : { module: m.id, reason });
            status.push({ id: m.id, version: m.version, status: 'skipped', ms: 0 });
          };

          if (unmet.has(m.id)) return skip('dependency', `nothing in the plan provides ${unmet.get(m.id)!.join(', ')}`);
          if (controller.signal.aborted) return skip('budget', 'time limit reached');
          if (!conditionHolds(m, facts)) return skip('condition');
          const missing = missingInputs(m, artifacts, facts);
          if (missing.length) return skip('dependency', `no ${missing.join(', ')}`);

          try {
            const out = await withTimeout(
              Promise.resolve(
                mod.run(
                  {
                    target,
                    artifacts,
                    facts,
                    ...(m.kind === 'analyzer'
                      ? {}
                      : {
                          http: limitHttp(http, m.budget.requests),
                          ...(opts.dns ? { dns: opts.dns } : {}),
                          ...(opts.tls ? { tls: opts.tls } : {}),
                          ...(opts.browser && m.budget.browser && plan.limits.browser ? { browser: opts.browser } : {}),
                        }),
                    log,
                    signal: controller.signal,
                  },
                  params as Params,
                ),
              ),
              Math.min(m.budget.ms ?? plan.limits.totalMs, Math.max(0, started + plan.limits.totalMs - now())),
            );
            for (const a of out.artifacts ?? []) artifacts.add(a);
            for (const [k, v] of Object.entries(out.facts ?? {})) facts.set(k, v);
            findings.push(...(out.findings ?? []));
            notChecked.push(...(out.notChecked ?? []));
            // A module that could not do all its work (budget, fetch errors) makes the run incomplete:
            // 'nothing found' then must not read as green.
            if ((out.notChecked ?? []).some((n) => n.reason === 'budget' || n.reason === 'error' || n.reason === 'dependency')) complete = false;
            status.push({ id: m.id, version: m.version, status: 'ok', ms: now() - t0 });
          } catch (e) {
            complete = false;
            const budget = e instanceof BudgetExceededError || e instanceof TimeoutError;
            log.warn(`${m.id} failed`, e);
            notChecked.push({ module: m.id, reason: budget ? 'budget' : 'error', detail: errorText(e) });
            status.push({ id: m.id, version: m.version, status: 'error', ms: now() - t0 });
          }
        }),
      );
    }
  } finally {
    clearTimeout(timer);
  }

  const merged = dedupe(findings);
  const result: ScanResult = {
    tool: { name: 'edeltraud', version: TOOL_VERSION },
    plan: { name: plan.plan, version: plan.version },
    target,
    startedAt: new Date(started).toISOString(),
    durationMs: now() - started,
    complete,
    verdict: verdict(merged, complete),
    findings: merged,
    notChecked,
    facts: facts.toJSON(),
    modules: status,
    requests: http.count,
  };
  return { result, artifacts, recorded: http.recorded };
}

function conditionHolds(m: ModuleManifest, facts: FactStore): boolean {
  return (m.when ?? []).every((w) => Boolean(facts.get(w)));
}

/** Requirements that are still missing at run time (a provider ran but produced nothing). */
function missingInputs(m: ModuleManifest, artifacts: ArtifactStore, facts: FactStore): string[] {
  return m.requires.filter((r) =>
    r.startsWith('artifact:') ? artifacts.list(r.slice(9)).length === 0 : !facts.has(r),
  );
}


/** Per-module request cap on top of the plan budget. */
function limitHttp(http: BudgetedHttp, max?: number): Http {
  if (max === undefined) return http;
  let used = 0;
  return {
    fetch(req) {
      if (used >= max) return Promise.reject(new BudgetExceededError('module request budget exhausted'));
      used++;
      return http.fetch(req);
    },
  };
}

class TimeoutError extends Error {}

function withTimeout<T>(p: Promise<T>, ms: number): Promise<T> {
  let t: NodeJS.Timeout;
  return Promise.race([
    p,
    new Promise<T>((_, reject) => {
      t = setTimeout(() => reject(new TimeoutError(`timeout after ${ms} ms`)), ms);
    }),
  ]).finally(() => clearTimeout(t));
}

function errorText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
