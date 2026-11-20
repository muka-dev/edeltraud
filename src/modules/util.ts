// Small helpers shared by modules. Pure functions only.

export interface PageData {
  url: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  setCookies: string[];
  html: string;
  redirects: string[];
}

export interface BundleData {
  url: string;
  /** 'inline' for <script> blocks in the HTML. */
  source: 'external' | 'inline';
  status: number;
  headers: Record<string, string>;
  code: string;
  truncated: boolean;
}

export function lineOf(text: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < text.length; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

/** True if both hosts belong to the same site (same host or one is a subdomain of the other's parent). */
export function sameSite(a: string, b: string): boolean {
  const base = (h: string) => h.toLowerCase().split('.').slice(-2).join('.');
  return a.toLowerCase() === b.toLowerCase() || base(a) === base(b);
}

export function decodeJwtPayload(jwt: string): Record<string, unknown> | null {
  const part = jwt.split('.')[1];
  if (!part) return null;
  try {
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
}

/** Extracts script URLs and inline scripts from HTML. Deliberately regex-based: robust enough for bundler output. */
export function extractScripts(html: string, baseUrl: string): { external: string[]; inline: string[] } {
  const external = new Set<string>();
  const inline: string[] = [];
  const scriptRe = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  for (const m of html.matchAll(scriptRe)) {
    const attrs = m[1] ?? '';
    const src = attrs.match(/\bsrc\s*=\s*["']?([^"'\s>]+)/i)?.[1];
    const type = attrs.match(/\btype\s*=\s*["']?([^"'\s>]+)/i)?.[1]?.toLowerCase();
    if (src) addUrl(external, src, baseUrl);
    else if (!type || type === 'module' || type.includes('javascript') || type === 'application/json') {
      if ((m[2] ?? '').trim()) inline.push(m[2]!);
    }
  }
  for (const m of html.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = m[1] ?? '';
    if (/\brel\s*=\s*["']?(modulepreload|preload)/i.test(attrs) && !/\bas\s*=\s*["']?(style|font|image)/i.test(attrs)) {
      const href = attrs.match(/\bhref\s*=\s*["']?([^"'\s>]+)/i)?.[1];
      if (href && /\.m?js(\?|$)/.test(href)) addUrl(external, href, baseUrl);
    }
  }
  return { external: [...external], inline };
}

/** Finds further chunk URLs referenced from a bundle (dynamic imports, Vite/Next asset paths). */
export function extractChunkRefs(code: string, bundleUrl: string): string[] {
  const out = new Set<string>();
  const re = /["'`]((?:\.{0,2}\/)?(?:[\w@.-]+\/)*[\w@.-]+\.m?js)["'`]/g;
  for (const m of code.matchAll(re)) {
    const p = m[1]!;
    if (/^(?:\.{1,2}\/|\/|assets\/|_next\/|static\/)/.test(p)) addUrl(out, p, bundleUrl);
  }
  return [...out];
}

function addUrl(set: Set<string>, ref: string, base: string): void {
  try {
    const u = new URL(ref, base);
    if (u.protocol === 'https:' || u.protocol === 'http:') set.add(u.toString());
  } catch {
    /* ignore */
  }
}
