// Runs the built-in vulnerable test site through a plan, without network.
//   node scripts/demo.ts [ampel|report] [de|en|pt]
import { runPlan } from '../src/core/processor.ts';
import { loadPlan } from '../src/core/plan.ts';
import { createRegistry } from '../src/modules/index.ts';
import { ReplayHttp } from '../src/fetch/replay.ts';
import { present, renderText } from '../src/report/present.ts';
import { isLang } from '../src/i18n/index.ts';
import { vulnerableSite } from '../test/fixtures/sites.ts';

const plan = loadPlan(process.argv[2] ?? 'ampel');
const lang = isLang(process.argv[3]) ? process.argv[3] : 'de';
const { result } = await runPlan({
  plan,
  target: { url: 'https://vibe.example.com/', host: 'vibe.example.com', ownershipVerified: false },
  registry: createRegistry(),
  http: new ReplayHttp(vulnerableSite()),
});
console.log(renderText(present(result, plan, lang)));
