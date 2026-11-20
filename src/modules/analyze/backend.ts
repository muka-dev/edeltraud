import { finding } from '../../core/finding.ts';
import type { CheckModule } from '../../core/types.ts';

/** Supabase found: public config is fine, but access rules decide everything. Points to the deep check. */
export const supabaseConfig: CheckModule = {
  manifest: {
    id: 'supabase.config',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    when: ['fact:stack.supabase'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const url = ctx.facts.get<string>('supabase.url');
    return {
      findings: [
        finding(supabaseConfig.manifest, {
          kind: 'detected',
          severity: 'info',
          confidence: 'confirmed',
          location: { url: url ?? ctx.target.url },
          messageKey: 'supabase.config',
          ...(url ? { vars: { project: new URL(url).hostname } } : {}),
        }),
      ],
      notChecked: [{ module: 'supabase.rls-read', reason: 'ownership', detail: 'row level security needs the deep check' }],
    };
  },
};

export const firebaseConfig: CheckModule = {
  manifest: {
    id: 'firebase.config',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    when: ['fact:stack.firebase'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const project = ctx.facts.get<string>('firebase.projectId');
    return {
      findings: [
        finding(firebaseConfig.manifest, {
          kind: 'detected',
          severity: 'info',
          confidence: 'confirmed',
          location: { url: ctx.target.url },
          messageKey: 'firebase.config',
          ...(project ? { vars: { project } } : {}),
        }),
      ],
      notChecked: [{ module: 'firebase.rules', reason: 'ownership', detail: 'database and storage rules need the deep check' }],
    };
  },
};
