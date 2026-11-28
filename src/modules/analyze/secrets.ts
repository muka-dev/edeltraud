import { finding, mask } from '../../core/finding.ts';
import type { CheckModule, Finding, Severity } from '../../core/types.ts';
import type { SourceMapProbe } from '../collect/sourcemaps.ts';
import { decodeJwtPayload, lineOf, type BundleData, type PageData } from '../util.ts';

interface Pattern {
  kind: string;
  provider: string;
  re: RegExp;
  severity: Severity;
  messageKey: string;
}

// Keys that must never reach the browser. Public keys (Supabase anon/publishable,
// Stripe pk_, Firebase web config) are deliberately not listed.
export const PATTERNS: Pattern[] = [
  { kind: 'anthropic-key', provider: 'Anthropic', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'openai-key', provider: 'OpenAI', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'openai-key', provider: 'OpenAI', re: /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'openrouter-key', provider: 'OpenRouter', re: /\bsk-or-v1-[a-f0-9]{64}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'groq-key', provider: 'Groq', re: /\bgsk_[A-Za-z0-9]{52}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'xai-key', provider: 'xAI', re: /\bxai-[A-Za-z0-9]{70,}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'replicate-key', provider: 'Replicate', re: /\br8_[A-Za-z0-9]{37}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'huggingface-key', provider: 'Hugging Face', re: /\bhf_[A-Za-z0-9]{34,}\b/g, severity: 'high', messageKey: 'secrets.server-key' },
  { kind: 'stripe-secret', provider: 'Stripe', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'stripe-test-secret', provider: 'Stripe', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{20,}/g, severity: 'medium', messageKey: 'secrets.test-key' },
  { kind: 'supabase-secret', provider: 'Supabase', re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g, severity: 'critical', messageKey: 'secrets.supabase-service-role' },
  { kind: 'aws-access-key', provider: 'AWS', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, severity: 'high', messageKey: 'secrets.server-key' },
  { kind: 'github-token', provider: 'GitHub', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'sendgrid-key', provider: 'SendGrid', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'resend-key', provider: 'Resend', re: /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,}\b/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'slack-token', provider: 'Slack', re: /\bxox[abprs]-[A-Za-z0-9-]{20,}/g, severity: 'critical', messageKey: 'secrets.server-key' },
  { kind: 'private-key', provider: 'PEM', re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, severity: 'critical', messageKey: 'secrets.private-key' },
];

const JWT = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;
const GOOGLE_KEY = /\bAIza[0-9A-Za-z_-]{35}\b/g;

interface Source {
  url: string;
  text: string;
}

export function scanText(src: Source): { kind: string; provider: string; severity: Severity; messageKey: string; value: string; index: number }[] {
  const hits: ReturnType<typeof scanText> = [];
  for (const p of PATTERNS) {
    for (const m of src.text.matchAll(p.re)) {
      hits.push({ kind: p.kind, provider: p.provider, severity: p.severity, messageKey: p.messageKey, value: m[0], index: m.index ?? 0 });
    }
  }
  // Supabase legacy keys are JWTs: only service_role is secret.
  for (const m of src.text.matchAll(JWT)) {
    const payload = decodeJwtPayload(m[0]);
    if (payload?.role === 'service_role') {
      hits.push({ kind: 'supabase-service-role', provider: 'Supabase', severity: 'critical', messageKey: 'secrets.supabase-service-role', value: m[0], index: m.index ?? 0 });
    }
  }
  // Google keys are public in Firebase configs. Near a Gemini endpoint they are an LLM key.
  for (const m of src.text.matchAll(GOOGLE_KEY)) {
    const i = m.index ?? 0;
    const around = src.text.slice(Math.max(0, i - 400), i + 400);
    if (/generativelanguage\.googleapis\.com|GoogleGenerativeAI|@google\/genai|gemini-/i.test(around)) {
      hits.push({ kind: 'gemini-key', provider: 'Google Gemini', severity: 'critical', messageKey: 'secrets.server-key', value: m[0], index: i });
    } else if (!/authDomain|projectId|firebase|messagingSenderId|maps\.googleapis/i.test(around)) {
      hits.push({ kind: 'google-key', provider: 'Google', severity: 'low', messageKey: 'secrets.google-key', value: m[0], index: i });
    }
  }
  return hits;
}

/** Original sources inside downloaded source maps (sourcesContent); unreadable maps give nothing. */
function mapSources(p: SourceMapProbe): Source[] {
  if (!p.isSourceMap || !p.content) return [];
  try {
    const map = JSON.parse(p.content) as { sources?: unknown[]; sourcesContent?: unknown[] };
    const names = Array.isArray(map.sources) ? map.sources : [];
    return (Array.isArray(map.sourcesContent) ? map.sourcesContent : []).flatMap((text, i) =>
      typeof text === 'string' ? [{ url: `${p.url} → ${typeof names[i] === 'string' ? names[i] : `#${i}`}`, text }] : [],
    );
  } catch {
    return [];
  }
}

/** Finds secret keys in shipped JavaScript, HTML (start page and crawled pages) and the sources inside public source maps. Evidence is always masked. */
export const secretsFrontend: CheckModule = {
  manifest: {
    id: 'secrets.frontend',
    version: '0.2.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    uses: ['artifact:js-bundle', 'artifact:sourcemap', 'artifact:subpage'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const sources: Source[] = [
      { url: page.finalUrl, text: page.html },
      ...ctx.artifacts.list('subpage').map((a) => ({ url: (a.data as PageData).finalUrl, text: (a.data as PageData).html })),
      ...ctx.artifacts.list('js-bundle').map((a) => ({ url: (a.data as BundleData).url, text: (a.data as BundleData).code })),
      ...ctx.artifacts.list('sourcemap').flatMap((a) => mapSources(a.data as SourceMapProbe)),
    ];
    const findings: Finding[] = [];
    const seen = new Set<string>();
    for (const src of sources) {
      for (const h of scanText(src)) {
        if (seen.has(h.value)) continue; // the same key in several chunks counts once
        seen.add(h.value);
        const evidence = h.kind === 'private-key' ? '-----BEGIN … PRIVATE KEY-----' : mask(h.value);
        findings.push(
          finding(secretsFrontend.manifest, {
            kind: h.kind,
            severity: h.severity,
            confidence: h.severity === 'low' ? 'possible' : 'confirmed',
            location: { url: src.url, line: lineOf(src.text, h.index) },
            evidence,
            messageKey: h.messageKey,
            vars: { provider: h.provider },
            discriminator: evidence,
          }),
        );
      }
    }
    return { findings };
  },
};
