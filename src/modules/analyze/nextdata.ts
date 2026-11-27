import { finding, mask } from '../../core/finding.ts';
import type { CheckModule, Finding, RenderData } from '../../core/types.ts';
import { lineOf, type BundleData, type PageData } from '../util.ts';
import { scanText } from './secrets.ts';

const NEXT_DATA = /<script\b[^>]*\bid=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/gi;
const FLIGHT = /self\.__next_f\.push\(\s*\[\s*1\s*,\s*("(?:[^"\\]|\\.)*")\s*\]\s*\)/g;

/** Returns the text of `__NEXT_DATA__` and the decoded App Router flight strings of an HTML document. */
export function extractNextData(html: string): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(NEXT_DATA)) if (m[1]!.trim()) out.push(m[1]!);
  for (const m of html.matchAll(FLIGHT)) {
    try {
      out.push(JSON.parse(m[1]!) as string);
    } catch {
      /* malformed chunk */
    }
  }
  return out;
}

const CONNECTION_STRING = /\b(postgres(?:ql)?|mongodb(?:\+srv)?|mysql|rediss?):\/\/([^\s"'\\<>/@]+):([^\s"'\\<>@]+)@[^\s"'\\<>]+/gi;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}\b/g;
const HASH_FIELD = /["'](password|passwordHash|password_hash|hashedPassword|hashed_password|hash|pwd)["']\s*:\s*"([^"\\]{6,})"/gi;
const HASH_VALUE = /^(?:\$2[abxy]?\$\d\d\$[./A-Za-z0-9]{50,}|\$argon2[a-z]*\$\S{20,}|\$pbkdf2\S{20,}|\$scrypt\S{20,}|[a-f0-9]{32,}|[A-Za-z0-9+/=_-]{40,})$/;
const ADMIN_FLAG = /"role"\s*:\s*"(?:admin|superadmin|owner)"|"(?:isAdmin|is_admin|isSuperuser)"\s*:\s*true/g;
const INTERNAL_URL = /\bhttps?:\/\/(?:localhost|127\.\d{1,3}\.\d{1,3}\.\d{1,3}|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|[a-z0-9.-]+\.internal)(?::\d+)?(?=[/"'\\\s?#<]|$)/gi;

const PROVIDER: Record<string, string> = { postgres: 'PostgreSQL', postgresql: 'PostgreSQL', mongodb: 'MongoDB', 'mongodb+srv': 'MongoDB', mysql: 'MySQL', redis: 'Redis', rediss: 'Redis' };

/** Values that look like a real password or a password hash (not a label such as "Password"). */
function looksLikeSecretValue(field: string, value: string): boolean {
  if (/\s/.test(value)) return false;
  if (HASH_VALUE.test(value)) return true;
  // Plain-text passwords only count when the field is explicitly a password and the value is not a word.
  return /^password$/i.test(field) && value.length >= 8 && /\d/.test(value) && /[^A-Za-z0-9]/.test(value);
}

/** Looks for secrets, personal data and internal addresses in the data Next.js embeds into the HTML. */
export const nextDataLeak: CheckModule = {
  manifest: {
    id: 'next.data-leak',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    uses: ['artifact:render', 'artifact:js-bundle'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = nextDataLeak.manifest;
    try {
      const page = ctx.artifacts.list('page')[0]!.data as PageData;
      const htmls: string[] = [page.html];
      for (const a of ctx.artifacts.list('render')) htmls.push((a.data as RenderData).html ?? '');
      for (const a of ctx.artifacts.list('js-bundle')) {
        const b = a.data as BundleData;
        if (b.source === 'inline') htmls.push(`<script>${b.code}</script>`);
      }
      const chunks = [...new Set(htmls.flatMap(extractNextData))];
      if (chunks.length === 0) return { findings: [] };

      const loc = { url: page.finalUrl };
      const out: Finding[] = [];

      // Secrets: reuse the frontend secret patterns, plus database connection strings with credentials.
      const secrets = new Map<string, { kind: string; provider: string; evidence: string; line: number }>();
      for (const text of chunks) {
        for (const h of scanText({ url: page.finalUrl, text })) {
          if (!secrets.has(h.value)) secrets.set(h.value, { kind: h.kind, provider: h.provider, evidence: h.kind === 'private-key' ? '-----BEGIN … PRIVATE KEY-----' : mask(h.value), line: lineOf(text, h.index) });
        }
        for (const c of text.matchAll(CONNECTION_STRING)) {
          if (secrets.has(c[0])) continue;
          secrets.set(c[0], { kind: 'connection-string', provider: PROVIDER[c[1]!.toLowerCase()] ?? 'database', evidence: `${c[1]!.toLowerCase()}://…`, line: lineOf(text, c.index ?? 0) });
        }
      }
      for (const s of secrets.values()) {
        out.push(
          finding(m, {
            kind: `secret-${s.kind}`,
            severity: 'critical',
            confidence: 'confirmed',
            location: loc,
            evidence: s.evidence,
            messageKey: 'next.data-secret',
            vars: { provider: s.provider },
            discriminator: `${s.kind}|${s.evidence}`,
          }),
        );
      }

      // Personal data: many distinct e-mail addresses, password-like fields, admin flags next to user lists.
      const emails = new Set<string>();
      const hashes = new Set<string>();
      let admins = 0;
      const internal = new Set<string>();
      for (const text of chunks) {
        for (const e of text.matchAll(EMAIL)) emails.add(e[0].toLowerCase());
        for (const h of text.matchAll(HASH_FIELD)) if (looksLikeSecretValue(h[1]!, h[2]!)) hashes.add(h[2]!);
        admins += [...text.matchAll(ADMIN_FLAG)].length;
        for (const u of text.matchAll(INTERNAL_URL)) internal.add(u[0].toLowerCase());
      }
      const manyEmails = emails.size > 3;
      const adminList = admins > 0 && emails.size >= 2;
      if (manyEmails || hashes.size > 0 || adminList) {
        const count = (manyEmails || adminList ? emails.size : 0) + hashes.size;
        const parts: string[] = [];
        if (manyEmails || adminList) parts.push(`${emails.size} e-mail addresses`);
        if (hashes.size > 0) parts.push(`${hashes.size} password fields`);
        if (adminList) parts.push(`${admins} admin flags`);
        out.push(
          finding(m, {
            kind: 'pii',
            severity: 'high',
            confidence: hashes.size > 0 ? 'likely' : 'possible',
            location: loc,
            evidence: parts.join(', '),
            messageKey: 'next.data-pii',
            vars: { count: String(count) },
            discriminator: parts.join('|'),
          }),
        );
      }
      if (internal.size > 0) {
        out.push(
          finding(m, {
            kind: 'internal',
            severity: 'low',
            confidence: 'likely',
            location: loc,
            evidence: `${internal.size} internal addresses`,
            messageKey: 'next.data-internal',
            vars: { count: String(internal.size) },
            discriminator: String(internal.size),
          }),
        );
      }
      return { findings: out };
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: 'error', detail: e instanceof Error ? e.message : String(e) }] };
    }
  },
};
