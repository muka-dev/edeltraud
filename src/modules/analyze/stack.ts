import type { CheckModule } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';

// Clerk publishable keys are pk_(live|test)_ + base64("<frontend-api-host>$").
// Stripe uses the same prefix, so only keys that decode to a host ending in '$' count.
function hasClerkKey(text: string): boolean {
  for (const m of text.matchAll(/\bpk_(?:live|test)_([A-Za-z0-9+/=]{16,})/g)) {
    const decoded = Buffer.from(m[1]!, 'base64').toString('utf8');
    if (/^[a-z0-9.-]+\.[a-z]{2,}\$$/i.test(decoded)) return true;
  }
  return false;
}

interface Signal {
  fact: string;
  label: string;
  test: (s: { html: string; code: string; headers: Record<string, string> }) => boolean;
}

const SIGNALS: Signal[] = [
  { fact: 'stack.supabase', label: 'Supabase', test: (s) => /[a-z0-9]{20}\.supabase\.co\b|@supabase\/supabase-js|supabase\.auth\./.test(s.code + s.html) },
  { fact: 'stack.firebase', label: 'Firebase', test: (s) => /firebaseapp\.com|firebaseio\.com|firebasestorage\.googleapis\.com|initializeApp\(\{[^}]*apiKey/.test(s.code + s.html) },
  { fact: 'stack.nextjs', label: 'Next.js', test: (s) => /\/_next\/static\/|__NEXT_DATA__/.test(s.html) || /next\.js/i.test(s.headers['x-powered-by'] ?? '') },
  { fact: 'stack.vite', label: 'Vite', test: (s) => /\/assets\/index-[\w-]{6,}\.js/.test(s.html) || /import\.meta\.env|__vite__/.test(s.code) },
  { fact: 'stack.react', label: 'React', test: (s) => /react-dom|__REACT_DEVTOOLS_GLOBAL_HOOK__|createRoot\(/.test(s.code) },
  { fact: 'stack.lovable', label: 'Lovable', test: (s) => /lovable(-uploads|\.app|\.dev|-tagger)|gpteng\.co|gpt-?engineer|generator"\s+content="lovable/i.test(s.html + s.code) },
  { fact: 'stack.bolt', label: 'Bolt', test: (s) => /bolt\.new|stackblitz/i.test(s.html) },
  { fact: 'stack.clerk', label: 'Clerk', test: (s) => /clerk\.accounts\.dev|@clerk\/|clerk\.browser\.js/.test(s.code + s.html) || hasClerkKey(s.code + s.html) },
  { fact: 'stack.stripe', label: 'Stripe', test: (s) => /js\.stripe\.com|pk_live_[A-Za-z0-9]{20,}/.test(s.code + s.html) },
  { fact: 'host.vercel', label: 'Vercel', test: (s) => 'x-vercel-id' in s.headers || /vercel/i.test(s.headers['server'] ?? '') },
  { fact: 'host.netlify', label: 'Netlify', test: (s) => 'x-nf-request-id' in s.headers || /netlify/i.test(s.headers['server'] ?? '') },
  { fact: 'host.cloudflare', label: 'Cloudflare', test: (s) => 'cf-ray' in s.headers },
];

/** Recognises frameworks, backends and hosts. Sets facts that switch further modules on. */
export const stackDetect: CheckModule = {
  manifest: {
    id: 'stack.detect',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'quality',
    requires: ['artifact:page'],
    uses: ['artifact:js-bundle'],
    provides: [...SIGNALS.map((s) => `fact:${s.fact}`), 'fact:stack', 'fact:supabase.url', 'fact:firebase.projectId'],
    params: {},
    budget: {},
  },
  run(ctx) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const code = ctx.artifacts.list('js-bundle').map((a) => (a.data as BundleData).code).join('\n');
    const s = { html: page.html, code, headers: page.headers };
    const facts: Record<string, unknown> = {};
    const found: string[] = [];
    for (const sig of SIGNALS) {
      const hit = sig.test(s);
      facts[sig.fact] = hit;
      if (hit) found.push(sig.label);
    }
    facts['stack'] = found;
    const sbUrl = (code + page.html).match(/https:\/\/([a-z0-9]{20})\.supabase\.co/)?.[0];
    if (sbUrl) facts['supabase.url'] = sbUrl;
    const fbProject = (code + page.html).match(/projectId\s*:\s*["']([a-z0-9-]{4,})["']/)?.[1];
    if (fbProject) facts['firebase.projectId'] = fbProject;
    return { facts };
  },
};
