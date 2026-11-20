import { findingText, ui } from '../i18n/index.ts';
import { SEVERITIES, type Finding, type Lang, type Plan, type ScanResult, type Severity } from '../core/types.ts';
import { countBySeverity } from '../core/verdict.ts';

export interface PresentedFinding {
  id: string;
  severity: Severity;
  severityLabel: string;
  confidence: Finding['confidence'];
  title: string;
  explain: string;
  fix: string;
  prompt?: string;
  location: Finding['location'];
  evidence?: string;
  fingerprint: string;
}

export interface Presented {
  lang: Lang;
  target: string;
  plan: string;
  light: ScanResult['verdict']['light'];
  headline: string;
  counts: Record<Severity, number>;
  findings: PresentedFinding[];
  /** Findings that exist but are only in the paid report. Counts only, no details. */
  locked: Record<Severity, number>;
  lockedText?: string;
  notChecked: { module: string; reason: string }[];
  always: string;
  disclaimer: string;
  stack: string[];
  durationMs: number;
}

/**
 * Turns a ScanResult into what a user sees, applying the plan's presentation rules.
 * Locked findings are reduced to counts here, so details never leave the server.
 */
export function present(result: ScanResult, plan: Plan, lang: Lang): Presented {
  const limit = plan.presentation.showFindings;
  // In the free view, info notes do not take one of the few visible slots.
  const ordered = limit === 'all' ? result.findings : [...result.findings.filter((f) => f.severity !== 'info'), ...result.findings.filter((f) => f.severity === 'info')];
  const visible = limit === 'all' ? ordered : ordered.slice(0, limit);
  const hidden = limit === 'all' ? [] : ordered.slice(limit);
  const locked = countBySeverity(hidden);
  const lockedList = SEVERITIES.filter((s) => s !== 'info' && locked[s] > 0).map((s) => `${locked[s]} ${ui(lang, `severity.${s}`)}`);

  const out: Presented = {
    lang,
    target: result.target.url,
    plan: result.plan.name,
    light: result.verdict.light,
    headline: ui(lang, `light.${result.verdict.light}`),
    counts: result.verdict.counts,
    findings: visible.map((f) => {
      const t = findingText(lang, f.messageKey, f.vars);
      const p: PresentedFinding = {
        id: f.id,
        severity: f.severity,
        severityLabel: ui(lang, `severity.${f.severity}`),
        confidence: f.confidence,
        title: t.title,
        explain: t.explain,
        fix: t.fix,
        location: f.location,
        fingerprint: f.fingerprint,
      };
      if (plan.presentation.fixPrompts && t.prompt) p.prompt = t.prompt;
      if (f.evidence) p.evidence = f.evidence;
      return p;
    }),
    locked,
    notChecked: result.notChecked
      .filter((n) => n.reason !== 'condition')
      .map((n) => ({ module: n.module, reason: ui(lang, `reason.${n.reason}`) })),
    always: ui(lang, 'always'),
    disclaimer: ui(lang, 'disclaimer'),
    stack: (result.facts['stack'] as string[] | undefined) ?? [],
    durationMs: result.durationMs,
  };
  if (lockedList.length) out.lockedText = ui(lang, 'locked', { list: lockedList.join(', ') });
  return out;
}

const DOT: Record<string, string> = { red: '🔴', yellow: '🟡', green: '🟢', unknown: '⚪' };

export function renderText(p: Presented): string {
  const lines = [`${DOT[p.light]} ${p.target}`, p.headline, ''];
  if (p.stack.length) lines.push(`Stack: ${p.stack.join(', ')}`, '');
  for (const f of p.findings) {
    lines.push(`[${f.severityLabel}] ${f.title}`);
    if (f.location.url) lines.push(`  ${f.location.url}${f.location.line ? `:${f.location.line}` : ''}${f.evidence ? `  ${f.evidence}` : ''}`);
    lines.push(`  ${f.explain}`, `  → ${f.fix}`);
    if (f.prompt) lines.push(`  Prompt: ${f.prompt}`);
    lines.push('');
  }
  if (p.lockedText) lines.push(p.lockedText, '');
  if (p.notChecked.length) {
    lines.push(`${p.notChecked.length ? '' : ''}— ${p.notChecked.map((n) => `${n.module}: ${n.reason}`).join('\n— ')}`, '');
  }
  lines.push(p.always, p.disclaimer);
  return lines.join('\n');
}
