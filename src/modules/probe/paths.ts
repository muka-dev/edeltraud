import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, HttpResponse, NotChecked } from '../../core/types.ts';
import type { PageData } from '../util.ts';

/** Fixed path that should not exist; its answer shows how the app treats unknown URLs (SPA fallback). */
export const BASELINE_PATH = '/edeltraud-404-baseline';

type Kind = 'env' | 'git' | 'backup' | 'info' | 'admin';
interface Candidate {
  path: string;
  method: 'GET' | 'HEAD';
  kind: Kind;
  /** Bytes of the body that are read. */
  maxBytes: number;
}

const get = (path: string, kind: Kind, maxBytes = 2048): Candidate => ({ path, method: 'GET', kind, maxBytes });
const head = (path: string): Candidate => ({ path, method: 'HEAD', kind: 'backup', maxBytes: 0 });

/** 19 candidates + 1 baseline = 20 requests. Read only: GET with a capped body, or HEAD. */
export const CANDIDATES: readonly Candidate[] = [
  get('/.env', 'env'),
  get('/.env.local', 'env'),
  get('/.env.production', 'env'),
  get('/.git/config', 'git'),
  get('/.git/HEAD', 'git'),
  get('/.DS_Store', 'info'),
  get('/config.json', 'info'),
  head('/backup.zip'),
  head('/db.sql'),
  head('/dump.sql'),
  get('/.svn/entries', 'git'),
  get('/wp-config.php.bak', 'backup'),
  get('/phpinfo.php', 'info'),
  get('/server-status', 'info'),
  get('/.vscode/settings.json', 'info'),
  get('/docker-compose.yml', 'info'),
  get('/firebase.json', 'info'),
  get('/.npmrc', 'env'),
  // /admin needs a bit more of the HTML to see whether a password field exists.
  get('/admin', 'admin', 16384),
];

const ENV_LINE = /^\s*(?:export\s+)?([A-Z][A-Z0-9_]*)\s*=/;
const SECRET_JSON_KEY = /"([A-Za-z0-9_.-]*(?:secret|token|password|passwd|api[_-]?key|private[_-]?key)[A-Za-z0-9_.-]*)"\s*:/gi;

const looksLikeHtml = (body: string) => /^\s*(<!doctype html|<html|<head|<body|<!--)/i.test(body) || /<\/?(html|head|body|script)\b/i.test(body.slice(0, 600));

/** Names of `KEY=value` lines (uppercase keys only). Values are never kept. */
export function envKeyNames(body: string): string[] {
  const keys: string[] = [];
  for (const line of body.split(/\r?\n/)) {
    const m = line.match(ENV_LINE);
    if (m && !keys.includes(m[1]!)) keys.push(m[1]!);
  }
  return keys;
}

interface Hit {
  kind: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  messageKey: string;
  evidence: string;
  vars: Record<string, string>;
}

/** Classifies one response; returns null unless the content clearly matches the file type. */
function classify(c: Candidate, res: HttpResponse): Hit | null {
  if (res.status !== 200) return null;
  const p = c.path;
  const body = res.body;
  const ct = (res.headers['content-type'] ?? '').toLowerCase();

  if (c.method === 'HEAD') {
    const len = Number(res.headers['content-length'] ?? '0');
    if (!(len > 0) || ct.includes('text/html')) return null;
    return { kind: 'backup-exposed', severity: 'high', messageKey: 'paths.backup-exposed', evidence: `HEAD ${p}: 200, ${len} bytes`, vars: { path: p, size: String(len) } };
  }
  if (c.kind === 'admin') {
    if (!ct.includes('html') && !looksLikeHtml(body)) return null;
    if (/type\s*=\s*["']?password/i.test(body) || !/dashboard/i.test(body)) return null;
    return { kind: 'admin-open', severity: 'low', messageKey: 'paths.admin-open', evidence: `${p}: 200, no password field`, vars: { path: p } };
  }
  if (p.startsWith('/.env')) {
    if (looksLikeHtml(body)) return null;
    const keys = envKeyNames(body);
    if (keys.length < 2) return null;
    const shown = keys.slice(0, 12).join(', ') + (keys.length > 12 ? ', …' : '');
    return { kind: 'env-exposed', severity: 'critical', messageKey: 'paths.env-exposed', evidence: shown, vars: { path: p, keys: shown } };
  }
  if (p === '/.npmrc') {
    if (looksLikeHtml(body)) return null;
    if (/_authToken\s*=/.test(body)) {
      return { kind: 'env-exposed', severity: 'critical', messageKey: 'paths.env-exposed', evidence: '_authToken', vars: { path: p, keys: '_authToken' } };
    }
    if (/^\s*(@[\w-]+:)?registry\s*=/m.test(body)) {
      return { kind: 'info-exposed', severity: 'medium', messageKey: 'paths.info-exposed', evidence: `${p}: registry`, vars: { path: p } };
    }
    return null;
  }
  const gitHit = (what: string): Hit => ({ kind: 'git-exposed', severity: 'high', messageKey: 'paths.git-exposed', evidence: `${p}: ${what}`, vars: { path: p } });
  if (p === '/.git/config') return /^\s*\[core\]/m.test(body) && !looksLikeHtml(body) ? gitHit('[core]') : null;
  if (p === '/.git/HEAD') return /^ref:\s*refs\//.test(body.trim()) ? gitHit('ref: refs/') : null;
  if (p === '/.svn/entries') return !looksLikeHtml(body) && /^(\d+\s*\n)(\s*\n)?\s*dir\b/.test(body) ? gitHit('dir') : null;

  const info = (what: string): Hit => ({ kind: 'info-exposed', severity: 'medium', messageKey: 'paths.info-exposed', evidence: `${p}: ${what}`, vars: { path: p } });
  switch (p) {
    case '/phpinfo.php':
      return /phpinfo\(\)|PHP Version/.test(body) ? info('phpinfo') : null;
    case '/server-status':
      return /Apache Server Status/i.test(body) ? info('Apache Server Status') : null;
    case '/.DS_Store':
      return body.includes('Bud1') && !looksLikeHtml(body) ? info('.DS_Store') : null;
    case '/.vscode/settings.json':
      return !looksLikeHtml(body) && /"(?:editor|files|workbench|terminal|python|eslint|prettier|[a-z]+)\.[\w.]+"\s*:/.test(body) && body.trim().startsWith('{') ? info('settings.json') : null;
    case '/docker-compose.yml':
      return !looksLikeHtml(body) && /^services:\s*$/m.test(body) ? info('services:') : null;
    case '/firebase.json':
      return !looksLikeHtml(body) && body.trim().startsWith('{') && /"(hosting|firestore|functions|storage|rewrites)"\s*:/.test(body) ? info('firebase.json') : null;
    case '/config.json': {
      if (looksLikeHtml(body) || !body.trim().startsWith('{')) return null;
      const keys = [...new Set([...body.matchAll(SECRET_JSON_KEY)].map((m) => m[1]!))];
      if (!keys.length) return null;
      return { kind: 'info-exposed', severity: 'medium', messageKey: 'paths.info-exposed', evidence: `${p}: ${keys.slice(0, 8).join(', ')}`, vars: { path: p } };
    }
    case '/wp-config.php.bak':
      return /DB_PASSWORD|DB_NAME|<\?php/.test(body)
        ? { kind: 'backup-exposed', severity: 'high', messageKey: 'paths.backup-exposed', evidence: `${p}: wp-config`, vars: { path: p, size: String(res.headers['content-length'] ?? body.length) } }
        : null;
  }
  return null;
}

/** True if the candidate answer is just the app's catch-all answer. */
function sameAsBaseline(res: HttpResponse, base: HttpResponse | null): boolean {
  if (!base || base.status !== 200 || res.status !== 200) return false;
  return res.body.slice(0, 256) === base.body.slice(0, 256);
}

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const isBudget = (e: unknown) => e instanceof Error && e.name === 'BudgetExceededError';

/** Actively requests well-known sensitive files on the app's origin. Read only; bodies are dropped after classification. */
export const pathsSensitive: CheckModule = {
  manifest: {
    id: 'paths.sensitive',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:page'],
    uses: [],
    provides: [],
    params: {},
    budget: { requests: 20 },
  },
  async run(ctx) {
    const m = pathsSensitive.manifest;
    const http = ctx.http!;
    const origin = new URL((ctx.artifacts.list('page')[0]!.data as PageData).finalUrl).origin;
    const findings: Finding[] = [];
    const notChecked: NotChecked[] = [];

    let baseline: HttpResponse | null = null;
    try {
      baseline = await http.fetch({ url: origin + BASELINE_PATH, maxBytes: 2048, followRedirects: false });
    } catch (e) {
      if (isBudget(e)) return { notChecked: [{ module: m.id, reason: 'budget', detail: errText(e) }] };
      notChecked.push({ module: m.id, reason: 'error', detail: `baseline: ${errText(e)}`.slice(0, 120) });
    }

    let skipped = 0;
    for (let i = 0; i < CANDIDATES.length; i++) {
      const c = CANDIDATES[i]!;
      const url = origin + c.path;
      let res: HttpResponse;
      try {
        res = await http.fetch({ url, method: c.method, maxBytes: c.maxBytes, followRedirects: false });
      } catch (e) {
        if (isBudget(e)) {
          skipped += CANDIDATES.length - i;
          break;
        }
        notChecked.push({ module: m.id, reason: 'error', detail: `${c.path}: ${errText(e)}`.slice(0, 120) });
        continue;
      }
      // HEAD answers carry no body to compare; their content-type check already excludes SPA fallbacks.
      if (c.method === 'GET' && sameAsBaseline(res, baseline)) continue;
      const hit = classify(c, res);
      if (!hit) continue;
      findings.push(
        finding(m, {
          kind: hit.kind,
          severity: hit.severity,
          confidence: 'confirmed',
          location: { url },
          evidence: hit.evidence,
          messageKey: hit.messageKey,
          vars: hit.vars,
          discriminator: c.path,
        }),
      );
    }
    if (skipped > 0) notChecked.push({ module: m.id, reason: 'budget', detail: `${skipped} paths not checked` });
    return { findings, notChecked };
  },
};
