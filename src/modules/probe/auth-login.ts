import { randomBytes } from 'node:crypto';
import { finding } from '../../core/finding.ts';
import type { CheckModule, HttpRequest, HttpResponse, ModuleContext, NotChecked } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';
import { findFirebaseConfig, type FirebaseConfig } from './firebase-config.ts';
import { findSupabaseClient, supabaseHeaders, type SupabaseClientInfo } from './supabase-key.ts';

// Failed logins with a fresh fake address. Only the password login endpoint is called: never
// signup, password reset, magic link or OTP, so no mail is sent and no account is created.

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const isBudget = (e: unknown) => e instanceof Error && e.name === 'BudgetExceededError';

/** Reserved TLD (RFC 2606): no mailbox can exist, no real account is touched. */
export const fakeCredentials = () => ({
  email: `edeltraud-probe-${randomBytes(6).toString('hex')}@example.invalid`,
  password: randomBytes(18).toString('base64url'),
});

const FIREBASE_LOGIN = 'https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword';

interface Login {
  provider: 'supabase' | 'firebase';
  /** Login URL without the key, for the report. */
  url: string;
  request: (email: string, password: string) => HttpRequest;
}

function supabaseLogin(c: SupabaseClientInfo): Login {
  const url = `${c.url}/auth/v1/token?grant_type=password`;
  return {
    provider: 'supabase',
    url,
    request: (email, password) => ({
      url,
      method: 'POST',
      headers: { 'content-type': 'application/json', ...supabaseHeaders(c) },
      body: JSON.stringify({ email, password }),
      maxBytes: 2048,
      followRedirects: false,
    }),
  };
}

function firebaseLogin(cfg: FirebaseConfig, referer: string): Login {
  return {
    provider: 'firebase',
    url: FIREBASE_LOGIN,
    request: (email, password) => ({
      url: `${FIREBASE_LOGIN}?key=${encodeURIComponent(cfg.apiKey)}`,
      method: 'POST',
      // The browser SDK sends the page as referer; keys restricted to the app's domain need it.
      headers: { 'content-type': 'application/json', referer },
      body: JSON.stringify({ email, password, returnSecureToken: true }),
      maxBytes: 2048,
      followRedirects: false,
    }),
  };
}

function sources(ctx: ModuleContext) {
  const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
  const html = (ctx.artifacts.list('page')[0]?.data as PageData | undefined)?.html ?? '';
  return { supabase: findSupabaseClient(bundles, html), firebase: findFirebaseConfig(bundles, html) };
}

/** Firebase error code (e.g. INVALID_LOGIN_CREDENTIALS), never any other part of the body. */
function firebaseError(res: HttpResponse): string {
  try {
    const msg = (JSON.parse(res.body) as { error?: { message?: unknown } }).error?.message;
    return typeof msg === 'string' ? (msg.match(/^[A-Z_]+/)?.[0] ?? '') : '';
  } catch {
    return '';
  }
}

type Outcome = 'denied' | 'limited' | 'other';

function classify(provider: Login['provider'], res: HttpResponse): Outcome {
  if (res.status === 429) return 'limited';
  if (provider === 'supabase') {
    return res.status === 400 && /invalid_credentials|invalid_grant|invalid login credentials/i.test(res.body) ? 'denied' : 'other';
  }
  const code = firebaseError(res);
  if (code === 'TOO_MANY_ATTEMPTS_TRY_LATER') return 'limited';
  return res.status === 400 && /^(INVALID_LOGIN_CREDENTIALS|EMAIL_NOT_FOUND|INVALID_PASSWORD)$/.test(code) ? 'denied' : 'other';
}

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------------------------
// ratelimit.auth: up to maxAttempts failed logins with the same fake address, stop at the first limit.

export const ratelimitAuth: CheckModule<{ maxAttempts: number; pauseMs: number }> = {
  manifest: {
    id: 'ratelimit.auth',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: [],
    params: {
      maxAttempts: { type: 'number', default: 10, min: 1, max: 10 },
      pauseMs: { type: 'number', default: 300, min: 0, max: 2000 },
    },
    budget: { requests: 10 },
  },
  async run(ctx, params) {
    const m = ratelimitAuth.manifest;
    const src = sources(ctx);
    const login = src.supabase ? supabaseLogin(src.supabase) : src.firebase ? firebaseLogin(src.firebase, ctx.target.url) : null;
    if (!login) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no Supabase or Firebase login found in the code' }] };
    const { email, password } = fakeCredentials();
    const notChecked: NotChecked[] = [];
    let attempts = 0;
    let limitedAfter: number | null = null;
    for (let i = 0; i < params.maxAttempts; i++) {
      if (i > 0 && params.pauseMs > 0) await sleep(params.pauseMs);
      let res: HttpResponse;
      try {
        res = await ctx.http!.fetch(login.request(email, password));
      } catch (e) {
        notChecked.push({ module: m.id, reason: isBudget(e) ? 'budget' : 'error', detail: `after ${attempts} attempts: ${errText(e).slice(0, 120)}` });
        break;
      }
      attempts++;
      const o = classify(login.provider, res);
      if (o === 'limited') {
        limitedAfter = attempts - 1;
        break;
      }
      if (o === 'other') {
        notChecked.push({ module: m.id, reason: 'error', detail: `${login.provider} login answered HTTP ${res.status}` });
        break;
      }
    }
    const facts = { 'ratelimit.auth': { provider: login.provider, attempts, limitedAfter } };
    if (notChecked.length || limitedAfter !== null) return { facts, notChecked };
    const f = finding(m, {
      kind: 'no-limit',
      severity: 'medium',
      confidence: 'likely',
      location: { url: login.url },
      evidence: `${login.provider}: ${attempts} failed logins, no HTTP 429`,
      messageKey: login.provider === 'supabase' ? 'ratelimit.auth.supabase' : 'ratelimit.auth.firebase',
      vars: { attempts: String(attempts) },
      discriminator: login.provider,
    });
    return { findings: [f], facts, notChecked };
  },
};

// ---------------------------------------------------------------------------------------------
// auth.enumeration: Firebase only (Supabase answers uniformly). One failed login with a fake address.

export const authEnumeration: CheckModule = {
  manifest: {
    id: 'auth.enumeration',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: [],
    params: {},
    budget: { requests: 1 },
  },
  async run(ctx) {
    const m = authEnumeration.manifest;
    const cfg = sources(ctx).firebase;
    if (!cfg) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no Firebase web config found in the code' }] };
    const login = firebaseLogin(cfg, ctx.target.url);
    const { email, password } = fakeCredentials();
    let res: HttpResponse;
    try {
      res = await ctx.http!.fetch(login.request(email, password));
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: isBudget(e) ? 'budget' : 'error', detail: errText(e).slice(0, 120) }] };
    }
    const code = res.status === 400 ? firebaseError(res) : '';
    if (code !== 'EMAIL_NOT_FOUND' && code !== 'INVALID_LOGIN_CREDENTIALS') {
      return { notChecked: [{ module: m.id, reason: 'error', detail: `firebase login answered HTTP ${res.status}` }] };
    }
    const enumerable = code === 'EMAIL_NOT_FOUND';
    const facts = { 'auth.enumeration': { provider: 'firebase', enumerable } };
    if (!enumerable) return { facts };
    const f = finding(m, {
      kind: 'email-not-found',
      severity: 'medium',
      confidence: 'confirmed',
      location: { url: login.url },
      evidence: `firebase signInWithPassword: HTTP 400 EMAIL_NOT_FOUND`,
      messageKey: 'auth.enumeration',
      discriminator: 'firebase',
    });
    return { findings: [f], facts };
  },
};
