import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding } from '../../core/types.ts';
import type { PageData } from '../util.ts';
import { compareVersions } from './deps.ts';
import { SERVER_DB } from './deps-db.ts';

/** Extracts a PHP version (x.y.z) from `x-powered-by` / `server` header values. */
export function detectPhp(headers: Record<string, string>): string | null {
  for (const key of ['x-powered-by', 'server']) {
    const m = (headers[key] ?? '').match(/\bPHP\/(\d+\.\d+\.\d+)/i);
    if (m) return m[1]!;
  }
  return null;
}

/** Server software versions disclosed in response headers, matched against known PHP advisories. */
export const depsServer: CheckModule = {
  manifest: {
    id: 'deps.server',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    provides: ['fact:server.php'],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = depsServer.manifest;
    try {
      const page = ctx.artifacts.list('page')[0]!.data as PageData;
      const version = detectPhp(page.headers);
      const facts = { 'server.php': version };
      if (!version) return { findings: [], facts };
      const db = SERVER_DB.php;
      const branch = version.split('.').slice(0, 2).join('.');
      const loc = { url: page.finalUrl };
      const out: Finding[] = [];
      const fixedIn = db.fixed[branch];
      const affected = fixedIn ? compareVersions(version, fixedIn) < 0 : compareVersions(branch, db.unfixedUpTo) <= 0;
      if (affected) {
        // Distributions backport fixes and keep the old version number, so the version alone is only a hint.
        out.push(
          finding(m, {
            kind: 'php2shell',
            severity: 'high',
            confidence: 'possible',
            location: loc,
            evidence: `PHP/${version}`,
            messageKey: 'server.php2shell',
            vars: { version, advisories: db.advisories.join(', '), fixed: fixedIn ?? '–' },
            discriminator: version,
          }),
        );
      }
      const updateIn = db.update.fixed[branch];
      if (!affected && updateIn && compareVersions(version, updateIn) < 0) {
        // Critical issues of this round need a non-default configuration: medium, version only a hint.
        out.push(
          finding(m, {
            kind: 'php-update',
            severity: 'medium',
            confidence: 'possible',
            location: loc,
            evidence: `PHP/${version}`,
            messageKey: 'server.php-update',
            vars: { version, advisories: db.update.advisories.join(', '), fixed: updateIn },
            discriminator: version,
          }),
        );
      }
      const eol = db.eol[branch];
      if (eol) {
        out.push(finding(m, { kind: 'php-eol', severity: 'medium', confidence: 'likely', location: loc, evidence: `PHP/${version}`, messageKey: 'server.php-eol', vars: { version }, discriminator: version }));
      } else if (db.eolSoon[branch]) {
        out.push(
          finding(m, { kind: 'php-eol-soon', severity: 'info', confidence: 'likely', location: loc, evidence: `PHP/${version}`, messageKey: 'server.php-eol-soon', vars: { version, eol: db.eolSoon[branch]! }, discriminator: version }),
        );
      }
      return { findings: out, facts };
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: 'error', detail: e instanceof Error ? e.message : String(e) }] };
    }
  },
};
