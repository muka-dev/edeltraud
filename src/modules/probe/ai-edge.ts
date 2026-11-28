import { finding } from '../../core/finding.ts';
import type { CheckModule, HttpResponse, ModuleContext, NotChecked } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';
import { allowedOrigin, type EndpointsData } from '../analyze/endpoints.ts';
import { DESTRUCTIVE } from './api.ts';
import { findSupabaseClient, supabaseHeaders } from './supabase-key.ts';

const LLM_NAME = /chat|(?:^|[-_])ai(?:$|[-_])|gpt|llm|generate|completion|assistant|openai|gemini|claude|anthropic|summar|translat|rewrite|prompt|agent/i;
const LLM_CODE = /openai|anthropic|gemini|claude-|gpt-|mistral|llama|groq|deepseek|openrouter|\bmodel\s*:|\bprompt\s*:|\bmessages\s*:/i;
const NEAR = 400;
// The function got past the gateway and tried to read the body.
const PARSE_ERROR = /json|unexpected end|syntaxerror|invalid|body|parse/i;

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const isBudget = (e: unknown) => e instanceof Error && e.name === 'BudgetExceededError';
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

/** Model or provider names within ~400 chars after a reference to the function (where the invoke body sits). */
function codeHintsLlm(name: string, bundles: readonly BundleData[]): boolean {
  const ref = new RegExp(`["'\`/]${escapeRe(name)}["'\`?]`, 'g');
  for (const b of bundles) {
    for (const m of b.code.matchAll(ref)) {
      const i = m.index ?? 0;
      if (LLM_CODE.test(b.code.slice(i, i + NEAR))) return true;
    }
  }
  return false;
}

function candidates(ctx: ModuleContext, bundles: readonly BundleData[], fallbackOrigin: string): { name: string; url: string }[] {
  const list = (ctx.artifacts.list('endpoints')[0]?.data as EndpointsData | undefined)?.list ?? [];
  const seen = new Set<string>();
  const out: { name: string; url: string }[] = [];
  for (const e of list) {
    const name = e.edgeFunction;
    if (!name || DESTRUCTIVE.test(name)) continue;
    const origin = e.origin ?? fallbackOrigin;
    if (!allowedOrigin(origin, ctx.target.host)) continue;
    const url = `${origin}/functions/v1/${name}`;
    if (seen.has(url)) continue;
    if (!LLM_NAME.test(name) && !codeHintsLlm(name, bundles)) continue;
    seen.add(url);
    out.push({ name, url });
  }
  return out;
}

/**
 * Supabase Edge Functions that look like LLM wrappers, called once each like an anonymous visitor's
 * browser would (public key only), with a deliberately broken JSON body '{'. No prompt is ever sent,
 * so no real LLM call is triggered. Documented exception to the GET/HEAD rule for active probes.
 */
export const aiEdgeFunctionOpen: CheckModule<{ maxFunctions: number }> = {
  manifest: {
    id: 'ai.edge-function-open',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'ai',
    requires: ['artifact:endpoints'],
    uses: ['artifact:js-bundle', 'artifact:page'],
    provides: [],
    params: { maxFunctions: { type: 'number', default: 5, min: 1, max: 5 } },
    budget: { requests: 5 },
  },
  async run(ctx, params) {
    const m = aiEdgeFunctionOpen.manifest;
    const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
    const html = (ctx.artifacts.list('page')[0]?.data as PageData | undefined)?.html ?? '';
    const client = findSupabaseClient(bundles, html);
    const all = client ? candidates(ctx, bundles, client.url) : [];
    const todo = all.slice(0, params.maxFunctions);
    const notChecked: NotChecked[] = [];
    const findings = [];
    let checked = 0;
    let open = 0;
    let protectedCount = 0;
    for (let i = 0; i < todo.length; i++) {
      const { name, url } = todo[i]!;
      let res: HttpResponse;
      try {
        // Public key only (what supabase.functions.invoke sends without login), no cookies, no user token.
        res = await ctx.http!.fetch({
          url,
          method: 'POST',
          headers: { 'content-type': 'application/json', ...supabaseHeaders(client!) },
          body: '{',
          maxBytes: 2048,
          followRedirects: false,
        });
      } catch (e) {
        if (isBudget(e)) {
          notChecked.push({ module: m.id, reason: 'budget', detail: `${todo.length - i} functions not checked` });
          break;
        }
        notChecked.push({ module: m.id, reason: 'error', detail: `${name}: ${errText(e).slice(0, 120)}` });
        continue;
      }
      checked++;
      const s = res.status;
      if (s === 401 || s === 403) {
        protectedCount++;
        continue;
      }
      let confidence: 'likely' | 'possible';
      if (s === 400 || s === 415 || s === 422 || (s === 500 && PARSE_ERROR.test(res.body))) confidence = 'likely';
      else if (s === 200) confidence = 'possible';
      else continue; // 404, other errors: nothing to say
      open++;
      findings.push(
        finding(m, {
          kind: 'open',
          severity: 'high',
          confidence,
          location: { url },
          evidence: `${name}: HTTP ${s}`,
          messageKey: 'ai.edge-function-open',
          vars: { name },
          discriminator: name,
        }),
      );
    }
    if (all.length > todo.length) {
      notChecked.push({ module: m.id, reason: 'budget', detail: `${all.length - todo.length} functions beyond maxFunctions not checked` });
    }
    return { findings, facts: { 'ai.edge-function-open': { checked, open, protected: protectedCount } }, notChecked };
  },
};
