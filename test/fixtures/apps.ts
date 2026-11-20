// Realistic vibe-coded example apps for replay tests. Fake keys come from FAKE in sites.ts and are
// assembled at run time, so no literal in this file looks like a real secret.
import type { FixtureResponse } from '../../src/fetch/replay.ts';
import { FAKE } from './sites.ts';

type Site = Record<string, FixtureResponse>;

const FULL_HEADERS = {
  'content-type': 'text/html',
  'content-security-policy': "default-src 'self'; frame-ancestors 'none'",
  'strict-transport-security': 'max-age=63072000; includeSubDomains',
  'x-content-type-options': 'nosniff',
  'referrer-policy': 'strict-origin-when-cross-origin',
  'permissions-policy': 'camera=(), microphone=()',
};

const filler = (n: number) => '/* ' + 'padding '.repeat(n) + '*/';

/** Bolt-style Vite app on Firebase: public web config (no finding), Gemini key in the client (critical), no CSP. */
export function boltFirebase(): Site {
  const html = `<!doctype html><html lang="en"><head><meta charset="utf-8">
<title>Recipe Buddy</title><meta name="description" content="Made with bolt.new">
<script type="module" crossorigin src="/assets/index-Kd82mQpa.js"></script></head>
<body><div id="root"></div></body></html>`;
  const code = `import{initializeApp as i}from"./firebase-app.js";
const firebaseConfig={apiKey:"${FAKE.googleFirebase}",authDomain:"recipe-buddy.firebaseapp.com",projectId:"recipe-buddy",storageBucket:"recipe-buddy.appspot.com",messagingSenderId:"1234567890"};
i(firebaseConfig);
${filler(120)}
const GEMINI_KEY="${FAKE.googleGemini}";
async function ask(q){return fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key="+GEMINI_KEY,{method:"POST",body:JSON.stringify({contents:[{parts:[{text:q}]}]})})}
`;
  const headers = { ...FULL_HEADERS };
  delete (headers as Record<string, string>)['content-security-policy'];
  return {
    'https://recipes.example.com/': { headers: { ...headers, 'x-frame-options': 'DENY' }, body: html },
    'http://recipes.example.com/': { redirect: 'https://recipes.example.com/' },
    'https://recipes.example.com/assets/index-Kd82mQpa.js': { body: code },
  };
}

/** Next.js on Vercel: Stripe secret key in a chunk, publishable key fine, CSP/frame/permissions missing, cookie without HttpOnly. */
export function nextjsVercel(): Site {
  const next = JSON.stringify({ props: { pageProps: {} }, page: '/', buildId: 'b1u2i3l4d5' });
  const html = `<!doctype html><html lang="en"><head>
<script src="/_next/static/chunks/webpack-1a2b3c4d5e6f.js" defer></script>
<script src="/_next/static/chunks/framework-7a8b9c0d1e2f.js" defer></script>
<script src="/_next/static/chunks/main-3c4d5e6f7a8b.js" defer></script>
<script src="/_next/static/chunks/pages/_app-9d0e1f2a3b4c.js" defer></script>
<script src="/_next/static/chunks/pages/index-5e6f7a8b9c0d.js" defer></script>
</head><body><div id="__next"></div><script id="__NEXT_DATA__" type="application/json">${next}</script></body></html>`;
  const chunk = (name: string, body: string) => [`https://shop.example.com/_next/static/chunks/${name}.js`, { body }] as const;
  return {
    'https://shop.example.com/': {
      headers: {
        'content-type': 'text/html',
        'x-vercel-id': 'fra1::iad1::abcde-1700000000000-0123456789ab',
        server: 'Vercel',
        'strict-transport-security': 'max-age=63072000',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'origin-when-cross-origin',
      },
      setCookies: ['session=f00ba4; Path=/; Secure; SameSite=Lax'],
      body: html,
    },
    'http://shop.example.com/': { redirect: 'https://shop.example.com/' },
    ...Object.fromEntries([
      chunk('webpack-1a2b3c4d5e6f', '(()=>{var e={};})();'),
      chunk('framework-7a8b9c0d1e2f', '/* react-dom */ createRoot(document.body);'),
      chunk('main-3c4d5e6f7a8b', 'window.__next=1;'),
      chunk('pages/_app-9d0e1f2a3b4c', `const stripe=Stripe("${FAKE.stripePub}");`),
      chunk('pages/index-5e6f7a8b9c0d', `const STRIPE_SECRET="${FAKE.stripeLive}";fetch("/api/checkout");`),
    ]),
  };
}

/** Cursor-built app that is only served over http (https redirects to http); GitHub token in an inline script. */
export function cursorPlainHttp(): Site {
  const html = `<!doctype html><html><head><title>Team Board</title></head><body><div id="app"></div>
<script>
  const GH_TOKEN = "${FAKE.github}";
  fetch("https://api.github.com/repos/acme/board/issues", { headers: { Authorization: "token " + GH_TOKEN } });
</script></body></html>`;
  return {
    'https://board.example.com/': { redirect: 'http://board.example.com/' },
    'http://board.example.com/': { headers: { 'content-type': 'text/html' }, setCookies: ['sid=42; Path=/'], body: html },
  };
}

/** Lovable + Supabase done right: public keys only, all headers, https redirect, source map URL answered by the SPA fallback. */
export function hardenedLovable(): Site {
  const SB = 'https://abcdefghijklmnopqrst.supabase.co';
  const html = `<!doctype html><html lang="en"><head><meta name="generator" content="lovable">
<script type="module" crossorigin src="/assets/index-Hq3Lm9Zs.js"></script></head><body><div id="root"></div></body></html>`;
  const code = `import{createClient as c}from"./vendor.js";
const supabase=c("${SB}","${FAKE.anon}");
const alt=c("${SB}","${'sb_' + 'publishable_' + 'Ab12'.repeat(8)}");
//# sourceMappingURL=index-Hq3Lm9Zs.js.map`;
  return {
    'https://secure.example.com/': {
      headers: FULL_HEADERS,
      setCookies: ['sb-session=x; Path=/; Secure; HttpOnly; SameSite=Lax'],
      body: html,
    },
    'http://secure.example.com/': { redirect: 'https://secure.example.com/' },
    'https://secure.example.com/assets/index-Hq3Lm9Zs.js': { body: code },
    // SPA fallback: unknown path answers with index.html and 200
    'https://secure.example.com/assets/index-Hq3Lm9Zs.js.map': { body: html },
  };
}

/** Start page with 12 same-site scripts: ampel loads 5 (budget notChecked), report loads all. OpenAI key in chunk 3, Anthropic key in chunk 9. */
export function truncatedBigApp(): Site {
  const names = Array.from({ length: 12 }, (_, i) => `chunk-${String(i + 1).padStart(2, '0')}-a1b2c3d4`);
  const html = `<!doctype html><html lang="en"><head>${names.map((n) => `<script src="/assets/${n}.js" defer></script>`).join('')}</head><body><div id="root"></div></body></html>`;
  const site: Site = {
    'https://big.example.com/': { headers: FULL_HEADERS, body: html },
    'http://big.example.com/': { redirect: 'https://big.example.com/' },
  };
  names.forEach((n, i) => {
    const body = i === 2 ? `const k="${FAKE.openai}";` : i === 8 ? `const k="${FAKE.anthropic}";` : `export const c${i + 1}=${i + 1};`;
    site[`https://big.example.com/assets/${n}.js`] = { body };
  });
  return site;
}

