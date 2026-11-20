import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parse } from 'yaml';
import { PlanError } from './params.ts';
import type { Plan, PlanStep } from './types.ts';

const PLAN_DIR = fileURLToPath(new URL('../../plans/', import.meta.url));

/**
 * Parses a plan. Module entries are either a bare id or a one-key map { id: params }.
 * Parameter values are validated later against the module registry (see processor).
 */
export function parsePlan(source: string | object): Plan {
  const raw = (typeof source === 'string' ? parse(source) : source) as Record<string, unknown>;
  if (!raw || typeof raw !== 'object') throw new PlanError('plan: not an object');
  const name = raw.plan;
  if (typeof name !== 'string' || !/^[a-z][a-z0-9-]*$/.test(name)) throw new PlanError('plan: missing or invalid name');
  const limits = (raw.limits ?? {}) as Record<string, unknown>;
  const pres = (raw.presentation ?? {}) as Record<string, unknown>;
  if (!Array.isArray(raw.modules) || raw.modules.length === 0) throw new PlanError(`${name}: modules must be a non-empty list`);

  const modules: PlanStep[] = raw.modules.map((entry: unknown, i: number) => {
    if (typeof entry === 'string') return { module: entry, params: {} };
    if (entry && typeof entry === 'object' && Object.keys(entry).length === 1) {
      const [id, params] = Object.entries(entry)[0]!;
      if (params !== null && (typeof params !== 'object' || Array.isArray(params))) {
        throw new PlanError(`${name}: parameters of ${id} must be a map`);
      }
      return { module: id, params: (params ?? {}) as PlanStep['params'] };
    }
    throw new PlanError(`${name}: module entry ${i} is invalid`);
  });
  const seen = new Set<string>();
  for (const s of modules) {
    if (seen.has(s.module)) throw new PlanError(`${name}: module ${s.module} listed twice`);
    seen.add(s.module);
  }

  const show = pres.showFindings ?? 'all';
  if (show !== 'all' && (typeof show !== 'number' || show < 0)) throw new PlanError(`${name}: showFindings must be 'all' or a number`);

  return {
    plan: name,
    version: typeof raw.version === 'number' ? raw.version : 1,
    limits: {
      totalMs: num(limits.totalMs, 15000),
      requests: num(limits.requests, 30),
      browser: limits.browser === true,
    },
    modules,
    presentation: { showFindings: show as number | 'all', fixPrompts: pres.fixPrompts === true },
  };
}

function num(v: unknown, d: number): number {
  return typeof v === 'number' && Number.isFinite(v) && v > 0 ? v : d;
}

/** Loads a named plan from plans/<name>.yaml. */
export function loadPlan(name: string): Plan {
  if (!/^[a-z][a-z0-9-]*$/.test(name)) throw new PlanError(`unknown plan '${name}'`);
  let text: string;
  try {
    text = readFileSync(PLAN_DIR + name + '.yaml', 'utf8');
  } catch {
    throw new PlanError(`unknown plan '${name}'`);
  }
  return parsePlan(text);
}
