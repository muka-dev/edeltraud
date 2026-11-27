import { finding } from '../../core/finding.ts';
import type { CheckModule, Confidence } from '../../core/types.ts';
import type { BundleData } from '../util.ts';

const ROLE_FIRST = /role\s*:\s*(["'`])system\1\s*,\s*content\s*:\s*(["'`])((?:\\[\s\S]|(?!\2)[^\\])*)\2/g;
const CONTENT_FIRST = /content\s*:\s*(["'`])((?:\\[\s\S]|(?!\1)[^\\])*)\1\s*,\s*role\s*:\s*(["'`])system\3/g;
// JSON-style keys survive in some bundles: {"role":"system","content":"..."}.
const ROLE_FIRST_JSON = /["']role["']\s*:\s*["']system["']\s*,\s*["']content["']\s*:\s*"((?:[^"\\]|\\.)*)"/g;
const PROMPT_START = /(["'`])(?:You are (?:a|an|the)\b|Du bist\b|Você é\b|Voce e\b|Act as\b)/g;
const NEAR_WORDS = /\b(?:prompt|system|instructions?|messages?)\b/i;
const SENSITIVE = /\b(?:secret|password|passwort|senha|internal|intern|do not reveal|don't reveal|never tell|never reveal|api[ _-]?key|admin)\b/i;

const MIN_ROLE_LENGTH = 80;
const MIN_TEXT_LENGTH = 120;

/** Reads a JS string literal whose opening quote sits at `start`. Returns its raw content or null. */
function readString(code: string, start: number): string | null {
  const q = code[start]!;
  const limit = Math.min(code.length, start + 20000);
  for (let i = start + 1; i < limit; i++) {
    const c = code[i]!;
    if (c === '\\') i++;
    else if (c === q) return code.slice(start + 1, i);
    else if (c === '\n' && q !== '`') return null;
  }
  return null;
}

const normalise = (s: string) => s.replace(/\\n|\\t/g, ' ').replace(/\\(["'`\\])/g, '$1').replace(/\s+/g, ' ').trim();

export interface PromptHit {
  text: string;
  viaRole: boolean;
}

/** Finds system prompts in shipped JavaScript. Distinct texts only. */
export function findSystemPrompts(code: string): PromptHit[] {
  const hits = new Map<string, PromptHit>();
  const add = (raw: string, viaRole: boolean) => {
    const text = normalise(raw);
    const prev = hits.get(text);
    if (!prev || (viaRole && !prev.viaRole)) hits.set(text, { text, viaRole });
  };
  for (const m of code.matchAll(ROLE_FIRST)) if (m[3]!.length > MIN_ROLE_LENGTH) add(m[3]!, true);
  for (const m of code.matchAll(CONTENT_FIRST)) if (m[2]!.length > MIN_ROLE_LENGTH) add(m[2]!, true);
  for (const m of code.matchAll(ROLE_FIRST_JSON)) if (m[1]!.length > MIN_ROLE_LENGTH) add(m[1]!, true);
  for (const m of code.matchAll(PROMPT_START)) {
    const start = m.index ?? 0;
    const raw = readString(code, start);
    if (raw === null || raw.length <= MIN_TEXT_LENGTH) continue;
    if (/<\/?[a-z][^>]*>/i.test(raw)) continue; // markup: marketing or UI copy, not a prompt
    const around = code.slice(Math.max(0, start - 300), start + raw.length + 300);
    if (!NEAR_WORDS.test(around)) continue;
    add(raw, false);
  }
  return [...hits.values()];
}

const ellipsize = (s: string, n: number) => (s.length > n ? s.slice(0, n).trimEnd() + '…' : s);

/** System prompts that ship inside the JavaScript bundle are readable by every visitor. */
export const aiSystemPromptExposed: CheckModule = {
  manifest: {
    id: 'ai.system-prompt-exposed',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'ai',
    requires: [],
    uses: ['artifact:js-bundle'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = aiSystemPromptExposed.manifest;
    try {
      const out = [];
      const seen = new Set<string>();
      for (const a of ctx.artifacts.list('js-bundle')) {
        const b = a.data as BundleData;
        const prompts = findSystemPrompts(b.code).filter((p) => !seen.has(p.text));
        if (prompts.length === 0) continue;
        for (const p of prompts) seen.add(p.text);
        const sensitive = prompts.some((p) => SENSITIVE.test(p.text));
        const confidence: Confidence = prompts.some((p) => p.viaRole) ? 'likely' : 'possible';
        const sample = ellipsize(prompts[0]!.text, 60);
        out.push(
          finding(m, {
            kind: 'system-prompt',
            severity: sensitive ? 'medium' : 'low',
            confidence,
            location: { url: b.url },
            evidence: `${prompts.length} prompt(s), first ${prompts[0]!.text.length} characters`,
            messageKey: 'ai.system-prompt-exposed',
            vars: { count: String(prompts.length), sample },
            discriminator: sample,
          }),
        );
      }
      return { findings: out };
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: 'error', detail: e instanceof Error ? e.message : String(e) }] };
    }
  },
};
