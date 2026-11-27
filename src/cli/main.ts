#!/usr/bin/env node
import { parseArgs } from 'node:util';
import { writeFileSync } from 'node:fs';
import { scan } from '../core/scan.ts';
import { isLang } from '../i18n/index.ts';
import { present, renderText } from '../report/present.ts';

const HELP = `EDEL.TRAUD.AI – Trau, schau, wem.

Usage: edeltraud <url> [options]
       edeltraud ownership <host> [--account <id>]   token and instructions for the deep check
       edeltraud watch add <url> --email <addr> [--lang de]   start a weekly watch (private part)
       edeltraud watch list | watch run                  list subscriptions / run all due ones once
       edeltraud jobs run [--once]                       work on paid jobs (private part)

  --plan <name>     ampel (default), report, deep, watch
  --lang <de|en|pt|pt-BR> language of the output (default de)
  --json            print the presented result as JSON
  --raw             print the full ScanResult as JSON (internal)
  --html <file>     write the report as a self-contained HTML file (private layout)
  --pdf <file>      write the report as PDF (needs Playwright/Chromium)
  --record <file>   save all HTTP exchanges as a replay fixture
  --owner-token <t> verify ownership (DNS TXT or /.well-known file) before active checks
  --account <id>    account the ownership token belongs to (default: cli)
  --verbose         log module errors to stderr

Environment: OWNERSHIP_SECRET (min. 16 characters) for ownership tokens;
jobs: JOBS_DIR, OWNERSHIP_SECRET, PUBLIC_BASE_URL, MAIL_ADMIN, SMTP_URL, MAIL_FROM.
watch: WATCH_DIR, WATCH_SECRET, PUBLIC_BASE_URL, SMTP_URL, MAIL_FROM (MAIL_DRY_RUN=1 writes .eml files).
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
      html: { type: 'string' },
      pdf: { type: 'string' },
      verbose: { type: 'boolean', default: false },
      'owner-token': { type: 'string' },
      email: { type: 'string' },
      once: { type: 'boolean', default: false },
      account: { type: 'string', default: 'cli' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  });
  if (positionals[0] === 'ownership' && positionals.length === 2) {
    const { issueToken } = await import('../ownership/ownership.ts');
    const i = issueToken(ownershipSecret(), positionals[1]!, values.account!);
    process.stdout.write(
      [
        `Token: ${i.token} (valid until ${i.expiresAt})`,
        '',
        'Either a DNS TXT record (the domain record covers all subdomains):',
        ...i.dns.map((d) => `  ${d.name}  TXT  "${d.value}"`),
        '',
        'or a file:',
        `  ${i.file.url}`,
        `  content: ${i.file.content}`,
        '',
      ].join('\n'),
    );
    return 0;
  }
  if (positionals[0] === 'watch') return watchCommand(positionals.slice(1), values);
  if (positionals[0] === 'jobs') return jobsCommand(positionals.slice(1), values);
  if (values.help || positionals.length !== 1) {
    process.stdout.write(HELP);
    return values.help ? 0 : 2;
  }
  const lang = isLang(values.lang) ? values.lang : 'de';
  let ownershipVerified = false;
  if (values['owner-token']) {
    const { verifyOwnership } = await import('../ownership/ownership.ts');
    const { LiveDns } = await import('../fetch/dns.ts');
    const { LiveHttp } = await import('../fetch/http.ts');
    const { normaliseTarget } = await import('../fetch/ssrf.ts');
    const v = await verifyOwnership({
      secret: ownershipSecret(),
      host: normaliseTarget(positionals[0]!).hostname,
      account: values.account!,
      token: values['owner-token'],
      dns: new LiveDns(),
      http: new LiveHttp(),
    });
    process.stderr.write(`ownership verified via ${v.method} (${v.where}), valid until ${v.expiresAt}\n`);
    ownershipVerified = true;
  }
  const out = await scan({
    url: positionals[0]!,
    ownershipVerified,
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
  if (values.html || values.pdf) {
    const html = await renderReportHtml(present(out.result, out.plan, lang));
    if (values.html) writeFileSync(values.html, html);
    if (values.pdf) {
      const { htmlToPdf } = await import('../report/pdf.ts');
      writeFileSync(values.pdf, await htmlToPdf(html));
    }
  }
  if (values.raw) process.stdout.write(JSON.stringify(out.result, null, 2) + '\n');
  else {
    const p = present(out.result, out.plan, lang);
    process.stdout.write(values.json ? JSON.stringify(p, null, 2) + '\n' : renderText(p) + '\n');
  }
  return { red: 1, yellow: 0, green: 0, unknown: 3 }[out.result.verdict.light];
}

/** The watch is private: loaded only when present. */
async function watchCommand(args: string[], values: { email?: string; lang?: string; plan?: string; verbose?: boolean }): Promise<number> {
  const dir = process.env.WATCH_DIR ?? 'data/watch';
  const storeMod: string = '../watch/store.ts';
  const { WatchStore } = await import(storeMod);
  const store = new WatchStore(dir);
  if (args[0] === 'add' && args[1]) {
    const { normaliseTarget } = await import('../fetch/ssrf.ts');
    const email = values.email ?? '';
    if (!/^[^\s@<>]+@[^\s@<>]+\.[a-z]{2,}$/i.test(email)) throw new Error('--email <address> is required');
    const sub = await store.add({
      url: normaliseTarget(args[1]).toString(),
      email,
      lang: isLang(values.lang) ? values.lang : 'de',
      plan: values.plan === 'ampel' ? 'watch' : (values.plan ?? 'watch'),
    });
    process.stdout.write(`watch ${sub.id} for ${sub.url} → ${sub.email}\n`);
    return 0;
  }
  if (args[0] === 'list') {
    for (const s of await store.list()) process.stdout.write(`${s.id}  ${s.active ? 'active ' : 'stopped'}  ${s.lastRunAt ?? 'never'}  ${s.url}  ${s.email}\n`);
    return 0;
  }
  if (args[0] === 'run') {
    const secret = process.env.WATCH_SECRET ?? '';
    if (secret.length < 16) throw new Error('WATCH_SECRET is not set (min. 16 characters)');
    const runnerMod: string = '../watch/runner.ts';
    const smtpMod: string = '../watch/smtp.ts';
    const { runWatch } = await import(runnerMod);
    const { mailerFromEnv } = await import(smtpMod);
    const summary = await runWatch({
      store,
      mailer: mailerFromEnv(),
      secret,
      baseUrl: process.env.PUBLIC_BASE_URL ?? 'https://scan.m-ko.de',
      ...(values.verbose ? { log: { debug() {}, warn: (m: string, e?: unknown) => console.error(m, e) } } : {}),
    });
    process.stdout.write(JSON.stringify(summary) + '\n');
    return summary.errors.length ? 1 : 0;
  }
  process.stdout.write(HELP);
  return 2;
}

/** Paid jobs are private: loaded only when present. */
async function jobsCommand(args: string[], values: { once?: boolean; verbose?: boolean }): Promise<number> {
  if (args[0] !== 'run') {
    process.stdout.write(HELP);
    return 2;
  }
  const queueMod: string = '../jobs/queue.ts';
  const workerMod: string = '../jobs/worker.ts';
  const smtpMod: string = '../watch/smtp.ts';
  const { JobQueue } = await import(queueMod);
  const { runWorker } = await import(workerMod);
  const { mailerFromEnv } = await import(smtpMod);
  const ac = new AbortController();
  for (const sig of ['SIGINT', 'SIGTERM'] as const) process.on(sig, () => ac.abort());
  await runWorker(
    {
      queue: new JobQueue(process.env.JOBS_DIR ?? 'data/jobs'),
      mailer: mailerFromEnv(),
      ownershipSecret: ownershipSecret(),
      baseUrl: process.env.PUBLIC_BASE_URL ?? 'https://scan.m-ko.de',
      ...(process.env.MAIL_ADMIN ? { adminEmail: process.env.MAIL_ADMIN } : {}),
      log: { debug: (m: string) => { if (values.verbose) console.error(m); }, warn: (m: string) => console.error(m) },
    },
    { once: values.once === true, signal: ac.signal },
  );
  return 0;
}

function ownershipSecret(): string {
  const s = process.env.OWNERSHIP_SECRET ?? '';
  if (s.length < 16) throw new Error('OWNERSHIP_SECRET is not set (min. 16 characters); create one with: openssl rand -hex 32');
  return s;
}

/** The HTML layout is private and not part of the open core. */
async function renderReportHtml(p: ReturnType<typeof present>): Promise<string> {
  // A variable path keeps tsc from requiring the file in the open core.
  const mod: string = '../report/private/html.ts';
  try {
    const { renderHtml } = (await import(mod)) as { renderHtml: (p: ReturnType<typeof present>) => string };
    return renderHtml(p);
  } catch (e) {
    if ((e as { code?: string }).code === 'ERR_MODULE_NOT_FOUND') throw new Error('HTML report is not part of the open core');
    throw e;
  }
}

main().then(
  (code) => process.exit(code),
  (e) => {
    console.error(e instanceof Error ? e.message : e);
    process.exit(2);
  },
);
