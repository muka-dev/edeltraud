import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, RenderData } from '../../core/types.ts';
import type { PageData } from '../util.ts';
import type { LegalPagesData } from '../collect/legal.ts';

/** Imprint and privacy policy: linked and reachable. Hints only, no legal assessment. */
export const privacyLegalPages: CheckModule = {
  manifest: {
    id: 'privacy.legal-pages',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'privacy',
    requires: [],
    uses: ['artifact:legal-pages', 'artifact:render', 'artifact:page'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = privacyLegalPages.manifest;
    const art = ctx.artifacts.list('legal-pages')[0];
    if (!art) return {};
    const d = art.data as LegalPagesData;
    const loc = { url: ctx.target.url };
    const conf = d.source === 'render' ? 'likely' : 'possible';
    const out: Finding[] = [];

    if (!d.privacy) {
      out.push(finding(m, { kind: 'no-privacy-link', severity: 'medium', confidence: conf, location: loc, messageKey: 'privacy.no-privacy-link' }));
    }
    if (!d.imprint) {
      const html = (ctx.artifacts.list('render')[0]?.data as RenderData | undefined)?.html || (ctx.artifacts.list('page')[0]?.data as PageData | undefined)?.html || '';
      const lang = html.match(/<html\b[^>]*\blang\s*=\s*["']?([A-Za-z-]+)/i)?.[1]?.toLowerCase() ?? '';
      const host = ctx.target.host.toLowerCase();
      const german = lang.startsWith('de') || /\.(de|at|ch)$/.test(host);
      if (german) {
        out.push(finding(m, { kind: 'no-imprint-link', severity: 'low', confidence: conf, location: loc, messageKey: 'privacy.no-imprint-link' }));
      }
    }
    for (const [kind, link] of [['imprint', d.imprint], ['privacy', d.privacy]] as const) {
      if (link && link.status >= 400) {
        out.push(finding(m, {
          kind: `unreachable-${kind}`,
          severity: 'medium',
          confidence: 'confirmed',
          location: { url: link.href },
          messageKey: 'privacy.legal-unreachable',
          vars: { href: link.href, status: String(link.status) },
        }));
      }
    }
    return { findings: out };
  },
};
