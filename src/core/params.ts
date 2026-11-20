import type { ParamSchema, Params } from './types.ts';

export class PlanError extends Error {}

/** Applies defaults and validates plan parameters against a module's schema. */
export function resolveParams(moduleId: string, schema: ParamSchema, given: Record<string, unknown> = {}): Params {
  for (const k of Object.keys(given)) {
    if (!(k in schema)) throw new PlanError(`${moduleId}: unknown parameter '${k}'`);
  }
  const out: Params = {};
  for (const [k, spec] of Object.entries(schema)) {
    const v = given[k] ?? spec.default;
    switch (spec.type) {
      case 'number':
        if (typeof v !== 'number' || !Number.isFinite(v)) throw new PlanError(`${moduleId}.${k}: expected number`);
        if (spec.min !== undefined && v < spec.min) throw new PlanError(`${moduleId}.${k}: below ${spec.min}`);
        if (spec.max !== undefined && v > spec.max) throw new PlanError(`${moduleId}.${k}: above ${spec.max}`);
        break;
      case 'boolean':
        if (typeof v !== 'boolean') throw new PlanError(`${moduleId}.${k}: expected boolean`);
        break;
      case 'string':
        if (typeof v !== 'string') throw new PlanError(`${moduleId}.${k}: expected string`);
        if (spec.enum && !spec.enum.includes(v)) throw new PlanError(`${moduleId}.${k}: not one of ${spec.enum.join(', ')}`);
        break;
    }
    out[k] = v as number | boolean | string;
  }
  return out;
}
