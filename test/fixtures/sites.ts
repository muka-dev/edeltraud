// Test sites for replay. Fake keys are assembled at run time so that no string in the
// repository looks like a real secret (and push protection stays quiet).
import type { FixtureResponse } from '../../src/fetch/replay.ts';

const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
export const jwt = (payload: object) => `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(payload)}.${'s'.repeat(43)}`;

export const FAKE = {
  openai: 'sk-' + 'proj-' + 'Ab1'.repeat(30),
  anthropic: 'sk-' + 'ant-api03-' + 'x9Y'.repeat(32),
  stripeLive: 'sk_' + 'live_' + '4eC39HqLyjWDarjtT1zdp7dc'.repeat(1),
  stripePub: 'pk_' + 'live_' + '51Habcdefghijklmnopqrstuv',
  anon: jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'anon' }),
  serviceRole: jwt({ iss: 'supabase', ref: 'abcdefghijklmnopqrst', role: 'service_role' }),
  googleFirebase: 'AIza' + 'SyD' + 'a'.repeat(32),
  googleGemini: 'AIza' + 'SyG' + 'b'.repeat(32),
  github: 'gh' + 'p_' + 'Z'.repeat(36),
};

const SB = 'https://abcdefghijklmnopqrst.supabase.co';

/** A typical vibe-coded app with several flaws. */
export function vulnerableSite(): Record<string, FixtureResponse> {
  const html = `<!doctype html><html lang="en"><head>
<script type="module" crossorigin src="/assets/index-Bx7kP2qa.js"></script>
<link rel="modulepreload" href="/assets/vendor-9fKd2LxQ.js">
<meta name="generator" content="lovable"></head><body><div id="root"></div>
<script src="https://cdn.gpteng.co/gptengineer.js" type="module"></script></body></html>`;
  const index = `import{createClient as c}from"./vendor-9fKd2LxQ.js";
const supabase=c("${SB}","${FAKE.anon}");
const admin=c("${SB}","${FAKE.serviceRole}");
const openai=new OpenAI({apiKey:"${FAKE.openai}",dangerouslyAllowBrowser:!0});
fetch("https://api.openai.com/v1/chat/completions");
const lazy=()=>import("./Dashboard-a1b2c3d4.js");
//# sourceMappingURL=index-Bx7kP2qa.js.map`;
  return {
    'https://vibe.example.com/': {
      headers: { 'content-type': 'text/html', 'x-powered-by': 'Express 4.17.1' },
      setCookies: ['session=abc123; Path=/'],
      body: html,
    },
    'http://vibe.example.com/': { status: 200, body: html },
    'https://vibe.example.com/assets/index-Bx7kP2qa.js': { body: index },
    'https://vibe.example.com/assets/vendor-9fKd2LxQ.js': { body: '/* @supabase/supabase-js */ export function createClient(){}' },
    'https://vibe.example.com/assets/Dashboard-a1b2c3d4.js': { body: `const k="${FAKE.anthropic}";` },
    'https://vibe.example.com/assets/index-Bx7kP2qa.js.map': { body: '{"version":3,"sources":["src/main.tsx"],"mappings":"AAAA"}' },
    // SPA fallback: every unknown path answers with index.html and 200
    'https://vibe.example.com/assets/vendor-9fKd2LxQ.js.map': { body: html },
  };
}

/** A reasonably configured app: public keys only, headers set. */
export function cleanSite(): Record<string, FixtureResponse> {
  const html = `<!doctype html><html lang="de"><head><script type="module" src="/assets/index-Q1w2e3r4.js"></script></head><body><div id="root"></div></body></html>`;
  const index = `const supabase=createClient("${SB}","${FAKE.anon}");
const firebaseConfig={apiKey:"${FAKE.googleFirebase}",authDomain:"demo.firebaseapp.com",projectId:"demo-app"};
const stripe=Stripe("${FAKE.stripePub}");`;
  return {
    'https://clean.example.com/': {
      headers: {
        'content-type': 'text/html',
        'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
        'strict-transport-security': 'max-age=63072000; includeSubDomains',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'strict-origin-when-cross-origin',
        'permissions-policy': 'camera=()',
      },
      setCookies: ['sb-session=x; Path=/; Secure; HttpOnly; SameSite=Lax'],
      body: html,
    },
    'http://clean.example.com/': { redirect: 'https://clean.example.com/' },
    // A well-kept app publishes a security contact (RFC 9116).
    'https://clean.example.com/.well-known/security.txt': {
      headers: { 'content-type': 'text/plain' },
      body: 'Contact: mailto:security@clean.example.com\nExpires: 2099-12-31T23:00:00.000Z\n',
    },
    'https://clean.example.com/assets/index-Q1w2e3r4.js': { body: index },
  };
}
