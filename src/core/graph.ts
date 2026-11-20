import { PlanError } from './params.ts';
import type { ModuleManifest } from './types.ts';

/**
 * Orders modules into layers: every module comes after all modules that provide
 * something it requires or a fact it is conditioned on. Requirements nobody in the plan
 * provides are reported, not fatal: the processor marks such modules as not checked.
 */
export function layers(manifests: readonly ModuleManifest[]): { layers: ModuleManifest[][]; unmet: Map<string, string[]> } {
  const providers = new Map<string, string[]>();
  for (const m of manifests) for (const p of m.provides) providers.set(p, [...(providers.get(p) ?? []), m.id]);

  const deps = new Map<string, Set<string>>();
  const unmet = new Map<string, string[]>();
  for (const m of manifests) {
    const d = new Set<string>();
    for (const r of m.requires) {
      const ps = providers.get(r);
      if (!ps) unmet.set(m.id, [...(unmet.get(m.id) ?? []), r]);
      else ps.filter((p) => p !== m.id).forEach((p) => d.add(p));
    }
    for (const w of [...(m.when ?? []), ...(m.uses ?? [])]) (providers.get(w) ?? []).filter((p) => p !== m.id).forEach((p) => d.add(p));
    deps.set(m.id, d);
  }

  const byId = new Map(manifests.map((m) => [m.id, m]));
  const done = new Set<string>();
  const out: ModuleManifest[][] = [];
  while (done.size < manifests.length) {
    const layer = manifests.filter((m) => !done.has(m.id) && [...deps.get(m.id)!].every((d) => done.has(d)));
    if (layer.length === 0) {
      const rest = manifests.filter((m) => !done.has(m.id)).map((m) => m.id);
      throw new PlanError(`dependency cycle between: ${rest.join(', ')}`);
    }
    layer.forEach((m) => done.add(m.id));
    out.push(layer.map((m) => byId.get(m.id)!));
  }
  return { layers: out, unmet };
}
