import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runOn } from './helpers.ts';
import { parsePlan } from '../src/core/plan.ts';
import { MODULES } from '../src/modules/index.ts';
import { detectLibraries, compareVersions, matchVulnerabilities } from '../src/modules/analyze/deps.ts';

const det = (code: string) => detectLibraries(code).map((d) => `${d.name}@${d.version}`);

test('compareVersions', () => {
  assert.equal(compareVersions('3.4.1', '3.5.0'), -1);
  assert.equal(compareVersions('4.17.21', '4.17.21'), 0);
  assert.equal(compareVersions('1.10.0', '1.9.9'), 1);
  assert.equal(compareVersions('2', '2.0.0'), 0);
});

test('detect: banners', () => {
  assert.deepEqual(det('/*! jQuery v3.4.1 | (c) JS Foundation */'), ['jquery@3.4.1']);
  assert.deepEqual(det('/*! jQuery JavaScript Library v1.12.4 */'), ['jquery@1.12.4']);
  assert.deepEqual(det('/*! jQuery UI - v1.12.1 - 2016-09-14 */'), ['jquery-ui@1.12.1']);
  assert.deepEqual(det('/*! Bootstrap v3.3.7 (http://getbootstrap.com) */'), ['bootstrap@3.3.7']);
  assert.deepEqual(det('/*! @license DOMPurify 3.0.6 | (c) Cure53 */'), ['dompurify@3.0.6']);
  assert.deepEqual(det('/*! Vue.js v2.6.14 */'), ['vue2@2.6.14']);
  assert.deepEqual(det('/** AngularJS v1.5.8 (c) Google */'), ['angularjs@1.5.8']);
  assert.deepEqual(det('var a={full:"1.6.10",major:1,minor:6}'), ['angularjs@1.6.10']);
});

test('detect: string-constant based', () => {
  assert.deepEqual(det('var VERSION="4.17.15";x();throw new TypeError("Unsupported core-js use. Try https://npms.io")'), ['lodash@4.17.15']);
  assert.deepEqual(det('function f(){throw "moment construction falls back to js Date"} hooks.version="2.24.0";'), ['moment@2.24.0']);
  assert.deepEqual(det('const a="1.5.1",b=1;x=`[Axios v`+"";'), []);
  assert.deepEqual(det('const Ke="1.5.1";function f(){return"[Axios v"+Ke+"] Transitional option"}'), ['axios@1.5.1']);
  assert.deepEqual(det('const x="0.27.2";y("[Axios v0.27.2] Transitional")'), ['axios@0.27.2']);
  assert.deepEqual(det('const z="9.9.9",Ke="1.5.1",q=2;function f(){return"[Axios v"+Ke+"]"}'), ['axios@1.5.1']);
  assert.equal(detectLibraries('const Q="14.1.0";window.next={version:Q,appDir:!0}')[0]?.confidence, 'possible');
  assert.deepEqual(det('window.next={version:"13.4.2-canary.1",x:1}'), ['nextjs@13.4.2']);
});

test('detect: traps', () => {
  assert.deepEqual(det('/*! Bootstrap v5.3.3 */'), ['bootstrap@5.3.3']); // detected, but no advisory
  assert.equal(matchVulnerabilities('bootstrap', '5.3.3'), null);
  assert.deepEqual(det('const v="4.17.15";'), []);
  assert.deepEqual(det('const o={version:"1.2.3"};'), []);
  assert.deepEqual(det('hooks.version="2.24.0"'), []); // no moment marker
  assert.deepEqual(det('/*! BootstrapVue 2.23.1 */ /*! bootstrap-vue v2.1.0 */'), []);
  assert.deepEqual(det('/*! jQuery v3.4.1 */ /*! jQuery v3.4.1 */'), ['jquery@3.4.1']);
  assert.deepEqual(det('const a="1.5.1";"[Axios v"+Zz+"]"'), []); // unresolvable identifier
});

test('database matching', () => {
  assert.equal(matchVulnerabilities('jquery', '3.7.1'), null);
  assert.equal(matchVulnerabilities('jquery', '3.5.0'), null);
  assert.deepEqual(matchVulnerabilities('jquery', '3.4.1'), { severity: 'medium', ids: ['CVE-2020-11022', 'CVE-2020-11023', 'CVE-2019-11358'], fixed: '3.5.0' });
  assert.equal(matchVulnerabilities('bootstrap', '4.3.1'), null);
  assert.equal(matchVulnerabilities('bootstrap', '4.0.0')!.fixed, '4.3.1');
  assert.deepEqual(matchVulnerabilities('bootstrap', '3.3.7')!.ids, ['CVE-2019-8331', 'CVE-2018-14040', 'CVE-2018-14041', 'CVE-2018-14042']);
  const dp = matchVulnerabilities('dompurify', '3.1.0')!;
  assert.equal(dp.severity, 'high');
  assert.deepEqual(dp.ids, ['CVE-2024-45801', 'CVE-2024-47875', 'CVE-2025-26791']);
  assert.equal(dp.fixed, '3.2.4');
  assert.equal(matchVulnerabilities('dompurify', '3.2.4'), null);
  assert.equal(matchVulnerabilities('dompurify', '3.1.5')!.severity, 'medium');
  assert.equal(matchVulnerabilities('axios', '1.6.0'), null);
  assert.equal(matchVulnerabilities('axios', '0.30.0'), null);
  assert.equal(matchVulnerabilities('axios', '1.5.1')!.fixed, '1.6.0');
  assert.equal(matchVulnerabilities('nextjs', '14.2.25')!.fixed, '15.5.28', 'AVIF/SVG RCE reach back to 10.0.0');
  assert.equal(matchVulnerabilities('nextjs', '13.0.0')!.severity, 'critical');
  assert.equal(matchVulnerabilities('nextjs', '15.1.0')!.severity, 'critical');
  assert.equal(matchVulnerabilities('moment', '2.29.4'), null);
  assert.equal(matchVulnerabilities('lodash', '4.17.20')!.severity, 'high');
  assert.deepEqual(matchVulnerabilities('lodash', '4.17.22'), { severity: 'medium', ids: ['CVE-2025-13465'], fixed: '4.17.23' });
  assert.equal(matchVulnerabilities('lodash', '4.17.23'), null);
});

const plan = parsePlan({
  plan: 't',
  limits: { totalMs: 10000, requests: 50, browser: false },
  modules: ['collect.page', 'collect.bundles', 'deps.vulnerable'],
  presentation: { showFindings: 'all', fixPrompts: true },
});

function site(js: string, inline = '') {
  return {
    'https://x.example.com/': {
      headers: { 'content-type': 'text/html' },
      body: `<!doctype html><html><head><script src="/a.js"></script></head><body>${inline}</body></html>`,
    },
    'https://x.example.com/a.js': { headers: { 'content-type': 'text/javascript' }, body: js },
  };
}

const run = async (s: ReturnType<typeof site>) => (await runOn(s as never, 'https://x.example.com/', plan, { modules: [...MODULES] })).result;

test('module: findings for vulnerable, EOL and capped Next.js', async () => {
  const js = [
    '/*! jQuery v3.4.1 */',
    '/*! Bootstrap v5.3.3 */',
    '/*! jQuery UI - v1.13.2 */',
    '/** AngularJS v1.8.2 */',
    '/*! Vue.js v2.7.16 */',
    'const Q="15.1.0";window.next={version:Q};',
  ].join('\n');
  const r = await run(site(js));
  const f = (id: string) => r.findings.find((x) => x.id === `deps.vulnerable/${id}`);
  assert.deepEqual(r.findings.map((x) => x.id).sort(), ['deps.vulnerable/lib-angularjs', 'deps.vulnerable/lib-jquery', 'deps.vulnerable/lib-nextjs', 'deps.vulnerable/lib-vue2']);
  const jq = f('lib-jquery')!;
  assert.equal(jq.messageKey, 'deps.vulnerable');
  assert.equal(jq.evidence, 'jQuery@3.4.1');
  assert.equal(jq.vars!['fixed'], '3.5.0');
  assert.equal(jq.confidence, 'likely');
  assert.equal(f('lib-angularjs')!.messageKey, 'deps.eol');
  assert.equal(f('lib-angularjs')!.vars!['eol'], '2021-12');
  assert.equal(f('lib-angularjs')!.severity, 'medium');
  assert.equal(f('lib-vue2')!.severity, 'low');
  const nx = f('lib-nextjs')!;
  assert.equal(nx.severity, 'high'); // critical rule capped, confidence 'possible'
  assert.equal(nx.confidence, 'possible');
  assert.ok(nx.vars!['advisories']!.includes('CVE-2025-66478'));
  assert.equal(r.complete, true);
});

test('module: inline HTML, dedupe, version change = new fingerprint, clean site', async () => {
  const a = await run(site('', '<script>/*! jQuery v1.12.4 */</script>'));
  assert.equal(a.findings.length, 1);
  const b = await run(site('/*! jQuery v3.4.1 */'));
  assert.notEqual(a.findings[0]!.fingerprint, b.findings[0]!.fingerprint);
  const dup = await run(site('/*! jQuery v3.4.1 */', '<script>/*! jQuery v3.4.1 */</script>'));
  assert.equal(dup.findings.length, 1);
  const clean = await run(site('/*! jQuery v3.7.1 */ const v="4.17.15"; /*! Bootstrap v5.3.3 */ x={version:"1.2.3"}'));
  assert.equal(clean.findings.length, 0);
  assert.equal(clean.complete, true);
});
