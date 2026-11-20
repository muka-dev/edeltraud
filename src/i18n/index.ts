import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import de from './de.json' with { type: 'json' };
import en from './en.json' with { type: 'json' };
import pt from './pt.json' with { type: 'json' };
import ptBR from './pt-BR.json' with { type: 'json' };
import type { Lang } from '../core/types.ts';

export interface FindingText {
  title: string;
  explain: string;
  fix: string;
  /** Ready-to-paste fix prompt. Paid part: empty if the private prompt catalogs are not installed. */
  prompt: string;
}
interface Catalog {
  ui: Record<string, string>;
  findings: Record<string, Omit<FindingText, 'prompt'>>;
}

export const CATALOGS: Record<Lang, Catalog> = { de, en, pt, 'pt-BR': ptBR };
export const LANGS: readonly Lang[] = ['de', 'en', 'pt', 'pt-BR'];
const FALLBACK: Record<Lang, Lang[]> = { de: ['de', 'en'], en: ['en'], pt: ['pt', 'en'], 'pt-BR': ['pt-BR', 'pt', 'en'] };

// Fix prompts are the paid part and are not published with the open core.
// They live in src/i18n/prompts/ (private) or in a directory named by EDELTRAUD_PROMPTS_DIR.
const PROMPT_DIR = process.env.EDELTRAUD_PROMPTS_DIR ?? fileURLToPath(new URL('./prompts/', import.meta.url));
const promptCache = new Map<Lang, Record<string, string>>();

export function prompts(lang: Lang): Record<string, string> {
  let p = promptCache.get(lang);
  if (!p) {
    const file = `${PROMPT_DIR.replace(/\/?$/, '/')}${lang}.json`;
    p = existsSync(file) ? (JSON.parse(readFileSync(file, 'utf8')) as Record<string, string>) : {};
    promptCache.set(lang, p);
  }
  return p;
}

export function hasPrompts(): boolean {
  return Object.keys(prompts('en')).length > 0;
}

export function isLang(x: unknown): x is Lang {
  return typeof x === 'string' && (LANGS as readonly string[]).includes(x);
}

function fill(text: string, vars: Record<string, string> = {}): string {
  return text.replace(/\{(\w+)\}/g, (m, k: string) => vars[k] ?? m);
}

export function ui(lang: Lang, key: string, vars?: Record<string, string>): string {
  for (const l of FALLBACK[lang]) {
    const t = CATALOGS[l].ui[key];
    if (t !== undefined) return fill(t, vars);
  }
  return key;
}

export function findingText(lang: Lang, key: string, vars?: Record<string, string>): FindingText {
  const l = FALLBACK[lang].find((x) => CATALOGS[x].findings[key]);
  const t = l ? CATALOGS[l].findings[key]! : undefined;
  if (!t) return { title: key, explain: '', fix: '', prompt: '' };
  const pl = FALLBACK[lang].find((x) => prompts(x)[key]);
  return {
    title: fill(t.title, vars),
    explain: fill(t.explain, vars),
    fix: fill(t.fix, vars),
    prompt: pl ? fill(prompts(pl)[key]!, vars) : '',
  };
}
