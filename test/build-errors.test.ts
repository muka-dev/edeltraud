import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { collectErrorpages } from '../src/modules/collect/errorpages.ts';

const plan = parsePlan({
  plan: 't',
  limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.bundles', 'collect.errorpages', 'build.dev-mode', 'errors.verbose'],
  presentation: { showFindings: 'all', fixPrompts: true },
});
const modules = [...MODULES];
const O = 'https://app.example.com';
const P1 = `${O}/edeltraud-check-404`;
const P2 = `${O}/api/edeltraud-check-404`;

async function scan(site: Record<string, { status?: number; body?: string }>) {
  const { result } = await runOn(site, `${O}/`, plan, { modules });
  return result;
}
const ids = (r: { findings: { id: string }[] }) => r.findings.map((f) => f.id).sort();
const page = (body: string) => ({ [`${O}/`]: { body } });

test('build: dev servers', async () => {
  const vite = await scan(page(`<script type="module">import RefreshRuntime from "/@react-refresh"</script><script type="module" src="/@vite/client"></script>`));
  const f = vite.findings.filter((x) => x.id === 'build.dev-mode/dev-server');
  assert.equal(f.length, 1);
  assert.equal(f[0]!.vars?.tool, 'Vite');
  assert.equal(f[0]!.severity, 'high');

  const wp = await scan(page(`<script src="/sockjs-node/info"></script>`));
  assert.equal(wp.findings.find((x) => x.id === 'build.dev-mode/dev-server')?.vars?.tool, 'webpack-dev-server');

  const next = await scan(page(`<script src="/_next/static/development/_buildManifest.js"></script>`));
  assert.equal(next.findings.find((x) => x.id === 'build.dev-mode/dev-server')?.vars?.tool, 'Next.js');

  const nextData = await scan(page(`<script id="__NEXT_DATA__" type="application/json">{"props":{},"dev":true}</script>`));
  assert.equal(nextData.findings.find((x) => x.id === 'build.dev-mode/dev-server')?.vars?.tool, 'Next.js');

  const nextProd = await scan(page(`<script id="__NEXT_DATA__" type="application/json">{"props":{},"buildId":"abc123"}</script>`));
  assert.ok(!nextProd.findings.some((x) => x.id === 'build.dev-mode/dev-server'));
});

test('build: development builds, found in a bundle, one finding per framework', async () => {
  const r = await scan({
    [`${O}/`]: { body: `<script src="/app.js"></script><script src="/b.js"></script>` },
    [`${O}/app.js`]: { body: `console.info("Download the React DevTools for a better development experience: https://reactjs.org/link/react-devtools")` },
    [`${O}/b.js`]: { body: `react-dom.development.js; "You are running Vue in development mode"; Angular is running in development mode.` },
  });
  const dev = r.findings.filter((x) => x.id === 'build.dev-mode/dev-build');
  assert.deepEqual(dev.map((x) => x.vars?.framework).sort(), ['Angular', 'React', 'Vue']);
  assert.equal(dev.find((x) => x.vars?.framework === 'React')?.location.url, `${O}/app.js`);
  assert.equal(dev.find((x) => x.vars?.framework === 'Vue')?.location.url, `${O}/b.js`);
});

test('build: production markers and plain mentions do not match', async () => {
  const r = await scan({
    [`${O}/`]: { body: `<p>We love vite and webpack-dev servers, react development is fun.</p><script src="/app.js"></script>` },
    [`${O}/app.js`]: { body: `throw Error("Minified React error #"+e+"; visit https://reactjs.org/docs/error-decoder.html?invariant="+e); /* react-dom.production.min.js */` },
  });
  assert.ok(!r.findings.some((x) => x.module === 'build.dev-mode'));
});

test('errors: debug pages per framework', async () => {
  const cases: [string, string][] = [
    ['Werkzeug', '<title>Werkzeug Debugger</title><script src="?__debugger__=yes&cmd=resource"></script>'],
    ['Django', `<p>You're seeing this error because you have <code>DEBUG = True</code> in your settings</p>`],
    ['Laravel', '<h1>Whoops! There was an error.</h1>'],
    ['Laravel', 'ignition <span>Illuminate\\Foundation\\Exceptions</span>'],
    ['Rails', '<title>Action Controller: Exception caught</title>'],
    ['Symfony', '<title>Symfony Exception</title>'],
    ['ASP.NET', `<h1>Server Error in '/' Application.</h1>`],
  ];
  for (const [fw, body] of cases) {
    const r = await scan({ ...page('<html>ok</html>'), [P1]: { status: 500, body } });
    const f = r.findings.filter((x) => x.id === 'errors.verbose/debug-page');
    assert.equal(f.length, 1, fw);
    assert.equal(f[0]!.vars?.framework, fw);
    assert.equal(f[0]!.severity, 'high');
    assert.equal(f[0]!.location.url, P1);
  }
});

test('errors: stack traces, masked', async () => {
  const node = `<pre>Error: boom<br> &nbsp; &nbsp;at handler (/home/alice/app/server.js:12:34)<br> &nbsp; &nbsp;at Layer.handle [as handle_request] (/home/alice/app/node_modules/express/lib/router/layer.js:95:5)<br> &nbsp; &nbsp;at next (node:internal/process/task_queues:1:1)</pre>`;
  const r = await scan({ ...page('ok'), [P1]: { status: 500, body: node }, [P2]: { status: 500, body: 'Traceback (most recent call last):\n  File "x.py"' } });
  const st = r.findings.filter((x) => x.id === 'errors.verbose/stacktrace');
  assert.equal(st.length, 2);
  for (const f of st) assert.ok((f.evidence ?? '').length <= 80 && !f.evidence!.includes('alice'), f.evidence ?? '');
  assert.ok(st.find((f) => f.location.url === P1)!.evidence!.includes('…'));

  const one = await scan({ ...page('ok'), [P1]: { body: 'at handler (/home/alice/app/server.js:12:34)' } });
  assert.ok(!one.findings.some((x) => x.id === 'errors.verbose/stacktrace'));

  const java = await scan({ ...page('ok'), [P1]: { status: 500, body: 'java.lang.NullPointerException\n\tat com.acme.Foo.bar(Foo.java:12)' } });
  assert.ok(java.findings.some((x) => x.id === 'errors.verbose/stacktrace'));
  const php = await scan({ ...page('ok'), [P1]: { status: 500, body: '<b>Fatal error</b>: Uncaught Error in /var/www/x.php on line 7' } });
  assert.ok(php.findings.some((x) => x.id === 'errors.verbose/stacktrace'), 'tags are stripped before matching');
  const php2 = await scan({ ...page('ok'), [P1]: { status: 500, body: 'Fatal error: Uncaught Error in /var/www/x.php on line 7' } });
  assert.ok(php2.findings.some((x) => x.id === 'errors.verbose/stacktrace'));
});

test('errors: sql errors and framework pages', async () => {
  for (const body of ['SQLSTATE[42S02]: Base table', 'ORA-00942: table', 'PrismaClientKnownRequestError: x', 'relation "users" does not exist', 'syntax error at or near "FROM"', 'PG::UndefinedTable']) {
    const r = await scan({ ...page('ok'), [P2]: { status: 500, body } });
    assert.ok(r.findings.some((x) => x.id === 'errors.verbose/sql'), body);
  }
  const sp = await scan({ ...page('ok'), [P1]: { status: 404, body: '<h1>Whitelabel Error Page</h1>' } });
  const f = sp.findings.find((x) => x.id === 'errors.verbose/framework-page');
  assert.equal(f?.vars?.framework, 'Spring Boot');
  assert.equal(f?.severity, 'low');
  const ex = await scan({ ...page('ok'), [P1]: { status: 404, body: '<pre>Cannot GET /edeltraud-check-404</pre>' } });
  assert.equal(ex.findings.find((x) => x.id === 'errors.verbose/framework-page')?.vars?.framework, 'Express');
});

test('errors: start page can leak a debug page too', async () => {
  const r = await scan(page('<title>Symfony Exception</title>'));
  const f = r.findings.find((x) => x.id === 'errors.verbose/debug-page');
  assert.equal(f?.location.url, `${O}/`);
});

test('errors: traps produce no findings', async () => {
  const next404 = '<html><body><h1 class="next-error-h1">404</h1><h2>This page could not be found.</h2></body></html>';
  const spa = '<!doctype html><div id="root"></div><script type="module" src="/assets/index.js"></script>';
  const nginx = '<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx</center></body></html>';
  for (const body of [next404, spa, nginx, 'Not found']) {
    const r = await scan({
      [`${O}/`]: { body: '<html><body>hello</body></html>' },
      [P1]: { status: body === spa ? 200 : 404, body },
      [P2]: { status: body === spa ? 200 : 404, body },
    });
    assert.deepEqual(ids(r).filter((i) => i.startsWith('errors.verbose')), []);
  }
  // default replay 404 ('Not found') for both probes
  const r = await scan(page('<html></html>'));
  assert.ok(!r.findings.some((x) => x.module === 'errors.verbose'));
});

test('errors: collector requests the two fixed probes, network errors become notChecked', async () => {
  const { result, http } = await runOn(page('<html></html>'), `${O}/`, plan, { modules });
  assert.ok(http.log.includes(`GET ${P1}`) && http.log.includes(`GET ${P2}`));
  assert.ok(!result.notChecked.some((n) => n.module === 'collect.errorpages'));

  const artifacts = new Map<string, unknown>();
  const ctx: any = {
    target: { url: `${O}/` },
    artifacts: { list: () => [{ type: 'page', key: 'k', data: { finalUrl: `${O}/` } }] },
    http: { fetch: async () => { throw new Error('boom'); } },
  };
  const res = await collectErrorpages.run(ctx, {});
  assert.equal(res.artifacts?.length, 0);
  assert.equal(res.notChecked?.[0]?.reason, 'error');
  void artifacts;
});
