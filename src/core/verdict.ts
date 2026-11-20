import { SEVERITIES, type Finding, type Severity, type Verdict } from './types.ts';

export const VERDICT_RULE = 'v2: red if ≥1 critical or ≥2 high; yellow if ≥1 high or ≥3 medium; green only if the scan was complete, else unknown';

export function countBySeverity(findings: readonly Finding[]): Record<Severity, number> {
  const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0])) as Record<Severity, number>;
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** The traffic light. Green only means: these checks found nothing. */
export function verdict(findings: readonly Finding[], complete = true): Verdict {
  const c = countBySeverity(findings);
  const light = c.critical >= 1 || c.high >= 2 ? 'red' : c.high >= 1 || c.medium >= 3 ? 'yellow' : complete ? 'green' : 'unknown';
  return { light, rule: VERDICT_RULE, counts: c };
}

const RANK: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.id.localeCompare(b.id));
}

/** Removes findings with the same fingerprint, keeping the most severe. */
export function dedupe(findings: readonly Finding[]): Finding[] {
  const best = new Map<string, Finding>();
  for (const f of findings) {
    const prev = best.get(f.fingerprint);
    if (!prev || RANK[f.severity] < RANK[prev.severity]) best.set(f.fingerprint, f);
  }
  return sortFindings([...best.values()]);
}
