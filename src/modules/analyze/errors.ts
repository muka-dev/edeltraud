import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding, Severity } from '../../core/types.ts';
import type { ErrorPageData } from '../collect/errorpages.ts';
import type { PageData } from '../util.ts';

const DEBUG_PAGES: { framework: string; test: (t: string) => string | undefined }[] = [
  { framework: 'Werkzeug', test: (t) => t.match(/Werkzeug Debugger|__debugger__/)?.[0] },
  { framework: 'Django', test: (t) => t.match(/this error because you have\s*(?:<code>)?\s*DEBUG\s*=\s*True/i)?.[0] },
  {
    framework: 'Laravel',
    test: (t) => t.match(/Whoops! There was an error/)?.[0] ?? (/ignition/i.test(t) ? t.match(/Illuminate[\\/]\\?[A-Z]\w*/)?.[0] : undefined),
  },
  { framework: 'Rails', test: (t) => t.match(/Action Controller: Exception caught/)?.[0] },
  { framework: 'Symfony', test: (t) => t.match(/Symfony Exception|sf-toolbar/)?.[0] },
  { framework: 'ASP.NET', test: (t) => t.match(/Server Error in (?:'|&#39;)\/[^'&]*(?:'|&#39;) Application/)?.[0] },
];

const NODE_STACK = /^[ \t]*at\s+(?:async\s+)?(?:[^()\n]*?\s)?\(?(?:\/|file:\/\/|node:internal|[A-Za-z]:\\)[^\s)]*\)?[ \t]*$/gm;

const STACKTRACES: ((t: string) => string | undefined)[] = [
  (t) => {
    const lines = t.match(NODE_STACK);
    return lines && lines.length >= 2 ? lines[0]!.trim() : undefined;
  },
  (t) => t.match(/Traceback \(most recent call last\)/)?.[0],
  (t) => t.match(/\bat\s+[A-Za-z_$][\w$]*(?:\.[\w$<>]+){2,}\([\w$]+\.java:\d+\)/)?.[0],
  (t) => t.match(/Fatal error:[^\n]{0,300}?on line \d+/i)?.[0],
];

const SQL_ERRORS: RegExp[] = [
  /SQLSTATE\[/,
  /You have an error in your SQL syntax/,
  /\bPG::[A-Z]\w+/,
  /syntax error at or near/,
  /ORA-\d{5}/,
  /SQLITE_ERROR/,
  /PrismaClientKnownRequestError/,
  /relation "[^"]+" does not exist/,
];

const FRAMEWORK_PAGES: { framework: string; re: RegExp; probeOnly?: boolean }[] = [
  { framework: 'Spring Boot', re: /Whitelabel Error Page/ },
  { framework: 'Express', re: /Cannot (?:GET|POST|HEAD) \/(?:api\/)?edeltraud-check-404/, probeOnly: true },
];

const ENTITIES: Record<string, string> = { nbsp: ' ', amp: '&', lt: '<', gt: '>', quot: '"', '#39': "'", '#x27': "'" };

/** Turns an HTML error page into plain text lines, so that stack traces rendered as HTML are matched too. */
function toText(html: string, stripScripts: boolean): string {
  let s = html;
  if (stripScripts) s = s.replace(/<(script|style)\b[\s\S]*?<\/\1>/gi, ' ');
  return s
    .replace(/<br\s*\/?>|<\/(?:p|div|li|tr|pre)>/gi, '\n')
    .replace(/<[^>]*>/g, '')
    .replace(/&(nbsp|amp|lt|gt|quot|#39|#x27);/g, (_, e: string) => ENTITIES[e] ?? ' ');
}

/** Short masked snippet: one line, home directories replaced by '…', at most 80 characters. */
function snippet(s: string): string {
  const t = s
    .replace(/\s+/g, ' ')
    .replace(/(?:\/home\/[^/\s]+|\/Users\/[^/\s]+|[A-Za-z]:\\Users\\[^\\\s]+|\/root)(?=[/\\])/g, '…')
    .trim();
  return t.length > 80 ? t.slice(0, 79) + '…' : t;
}

/** Looks for debug pages, stack traces and SQL errors in the probe error pages and the start page. */
export const errorsVerbose: CheckModule = {
  manifest: {
    id: 'errors.verbose',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: [],
    uses: ['artifact:error-page', 'artifact:page'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const m = errorsVerbose.manifest;
    const targets: { url: string; html: string; probe: boolean }[] = [];
    for (const a of ctx.artifacts.list('error-page')) {
      const d = a.data as ErrorPageData;
      targets.push({ url: d.url, html: d.body, probe: true });
    }
    for (const a of ctx.artifacts.list('page')) {
      const d = a.data as PageData;
      targets.push({ url: d.finalUrl, html: d.html, probe: false });
    }
    const out: Finding[] = [];
    for (const t of targets) {
      const text = toText(t.html, !t.probe);
      const add = (kind: string, severity: Severity, messageKey: string, ev: string, vars?: Record<string, string>) =>
        out.push(
          finding(m, {
            kind,
            severity,
            confidence: 'confirmed',
            location: { url: t.url },
            evidence: snippet(ev),
            messageKey,
            ...(vars ? { vars } : {}),
          }),
        );

      for (const d of DEBUG_PAGES) {
        const hit = d.test(t.html) ?? d.test(text);
        if (hit) {
          add('debug-page', 'high', 'errors.debug-page', hit, { framework: d.framework });
          break;
        }
      }
      for (const test of STACKTRACES) {
        const hit = test(text);
        if (hit) {
          add('stacktrace', 'medium', 'errors.stacktrace', hit);
          break;
        }
      }
      for (const re of SQL_ERRORS) {
        const hit = text.match(re)?.[0];
        if (hit) {
          add('sql', 'medium', 'errors.sql', hit);
          break;
        }
      }
      for (const f of FRAMEWORK_PAGES) {
        if (f.probeOnly && !t.probe) continue;
        const hit = text.match(f.re)?.[0];
        if (hit) {
          add('framework-page', 'low', 'errors.framework-page', hit, { framework: f.framework });
          break;
        }
      }
    }
    return { findings: out };
  },
};
