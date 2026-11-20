#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import { scan } from '../core/scan.ts';
import { isLang } from '../i18n/index.ts';
import { present, renderText } from '../report/present.ts';

const HELP = `EDEL.TRAUD.AI – Trau, schau, wem.

Usage: edeltraud <url> [options]

  --plan <name>     ampel (default), report, deep, watch
  --lang <de|en|pt|pt-BR> language of the output (default de)
  --json            print the presented result as JSON
  --raw             print the full ScanResult as JSON (internal)
  --record <file>   save all HTTP exchanges as a replay fixture
  --verbose         log module errors to stderr
`;

async function main(): Promise<number> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      plan: { type: 'string', default: 'ampel' },
      lang: { type: 'string', default: 'de' },
      json: { type: 'boolean', default: false },
      raw: { type: 'boolean', default: false },
      record: { type: 'string' },
      verbose: { type: 'boolean', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (values.help || positionals.length !== 1) {
    process.stdout.write(HELP);
    return values.help ? 0 : 2;
  }
  const lang = isLang(values.lang) ? values.lang : 'de';
  const out = await scan({
    url: positionals[0]!,
    plan: values.plan!,
    record: Boolean(values.record),
    ...(values.verbose ? { log: { debug() {}, warn: (m: string, e?: unknown) => console.error(m, e) } } : {}),
  });
  if (values.record) {
    const site: Record<string, unknown> = {};
    for (const { req, res } of out.recorded) {
      // Redirect chains are flattened: the first URL points straight at the final one.
      if (res.finalUrl !== req.url) site[req.url] = { redirect: res.finalUrl };
      site[res.finalUrl] = { status: res.status, headers: res.headers, setCookies: res.setCookies, body: res.body };
    }
    writeFileSync(values.record, JSON.stringify(site, null, 2));
  }
  if (values.raw) process.stdout.write(JSON.stringify(out.result, null, 2) + '\n');
  else {
    const p = present(out.result, out.plan, lang);
    process.stdout.write(values.json ? JSON.stringify(p, null, 2) + '\n' : renderText(p) + '\n');
  }
  return { red: 1, yellow: 0, green: 0, unknown: 3 }[out.result.verdict.light];
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(2);
  },
);
