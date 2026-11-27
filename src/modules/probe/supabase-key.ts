import { decodeJwtPayload, type BundleData } from '../util.ts';

export interface SupabaseClientInfo {
  url: string;
  key: string;
  keyType: 'anon' | 'publishable';
}

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const PUBLISHABLE = /\bsb_publishable_[A-Za-z0-9_-]{16,}/g;
const SB_URL = /https:\/\/[a-z0-9]{20}\.supabase\.co/g;
const CREATE_CLIENT = /createClient\s*(?:<[^>(]*>)?\(\s*["'`](https:\/\/[^"'`\s]+)["'`]\s*,\s*["'`]([^"'`\s]+)["'`]/g;

interface KeyHit {
  key: string;
  keyType: 'anon' | 'publishable';
  index: number;
}

/** Public keys in a text. service_role and secret keys are never returned. */
function publicKeys(text: string): KeyHit[] {
  const out: KeyHit[] = [];
  for (const m of text.matchAll(JWT)) {
    if (decodeJwtPayload(m[0])?.role === 'anon') out.push({ key: m[0], keyType: 'anon', index: m.index ?? 0 });
  }
  for (const m of text.matchAll(PUBLISHABLE)) out.push({ key: m[0], keyType: 'publishable', index: m.index ?? 0 });
  return out;
}

function keyType(key: string): 'anon' | 'publishable' | null {
  if (key.startsWith('sb_publishable_')) return 'publishable';
  if (key.startsWith('eyJ') && decodeJwtPayload(key)?.role === 'anon') return 'anon';
  return null;
}

/**
 * Finds the Supabase project URL and the public key next to it in the page's JavaScript and HTML.
 * Accepts <20 chars>.supabase.co URLs and custom domains passed to createClient(url, key).
 * Never returns service_role or secret keys. The key is read at run time only, never stored in facts.
 */
export function findSupabaseClient(bundles: readonly BundleData[], html = ''): SupabaseClientInfo | null {
  const texts = [...bundles.map((b) => b.code), html];

  // 1. Explicit createClient(url, key) calls (also custom domains).
  for (const text of texts) {
    for (const m of text.matchAll(CREATE_CLIENT)) {
      const t = keyType(m[2]!);
      if (t) return { url: normaliseUrl(m[1]!), key: m[2]!, keyType: t };
    }
  }
  // 2. A project URL with a public key close by (minified code aliases createClient).
  for (const text of texts) {
    const keys = publicKeys(text);
    if (!keys.length) continue;
    for (const m of text.matchAll(SB_URL)) {
      const i = m.index ?? 0;
      const near = keys
        .map((k) => ({ k, d: Math.abs(k.index - i) }))
        .filter((x) => x.d <= 600)
        .sort((a, b) => a.d - b.d)[0];
      if (near) return { url: m[0], key: near.k.key, keyType: near.k.keyType };
    }
  }
  return null;
}

function normaliseUrl(u: string): string {
  try {
    const p = new URL(u);
    return p.origin;
  } catch {
    return u.replace(/\/+$/, '');
  }
}

/** Request headers for the PostgREST/auth/storage endpoints. Publishable keys are not JWTs: apikey only. */
export function supabaseHeaders(c: SupabaseClientInfo): Record<string, string> {
  return c.keyType === 'anon' ? { apikey: c.key, Authorization: `Bearer ${c.key}` } : { apikey: c.key };
}
