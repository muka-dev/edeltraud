import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding } from '../../core/types.ts';
import { lineOf, type BundleData } from '../util.ts';

const LLM_ENDPOINTS: [RegExp, string][] = [
  [/api\.openai\.com\/v1/, 'OpenAI'],
  [/api\.anthropic\.com\/v1/, 'Anthropic'],
  [/generativelanguage\.googleapis\.com/, 'Google Gemini'],
  [/api\.groq\.com/, 'Groq'],
  [/openrouter\.ai\/api/, 'OpenRouter'],
  [/api\.mistral\.ai/, 'Mistral'],
  [/api\.x\.ai\/v1/, 'xAI'],
  [/api\.deepseek\.com/, 'DeepSeek'],
  [/api\.perplexity\.ai/, 'Perplexity'],
  [/api\.elevenlabs\.io/, 'ElevenLabs'],
  [/api\.replicate\.com/, 'Replicate'],
];

/**
 * The browser talks to an LLM provider directly. Then either the key is in the client,
 * or anyone can run up costs. Explicit SDK opt-outs are confirmed findings.
 */
export const aiClientLlmCall: CheckModule = {
  manifest: {
    id: 'ai.client-llm-call',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'ai',
    requires: ['artifact:js-bundle'],
    provides: ['fact:ai.client-llm'],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = aiClientLlmCall.manifest;
    const out: Finding[] = [];
    const providers = new Set<string>();
    for (const a of ctx.artifacts.list('js-bundle')) {
      const b = a.data as BundleData;
      const flag = b.code.search(/dangerouslyAllowBrowser\s*:\s*(?:!0|true)/);
      if (flag >= 0) {
        out.push(finding(m, { kind: 'browser-flag', severity: 'high', confidence: 'confirmed', location: { url: b.url, line: lineOf(b.code, flag) }, messageKey: 'ai.browser-flag' }));
      }
      for (const [re, name] of LLM_ENDPOINTS) {
        const i = b.code.search(re);
        if (i >= 0 && !providers.has(name)) {
          providers.add(name);
          out.push(finding(m, { kind: 'direct-call', severity: 'high', confidence: 'likely', location: { url: b.url, line: lineOf(b.code, i) }, messageKey: 'ai.client-llm', vars: { provider: name }, discriminator: name }));
        }
      }
    }
    return { findings: out, facts: { 'ai.client-llm': [...providers] } };
  },
};
