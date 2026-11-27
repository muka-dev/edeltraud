import { finding } from '../../core/finding.ts';
import type { CheckModule, Finding } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';

interface Source {
  url: string;
  text: string;
  isPage: boolean;
}

// Dev servers announce themselves through client scripts that production builds never contain.
const DEV_SERVER: { tool: string; re: RegExp }[] = [
  { tool: 'Vite', re: /\/@(?:vite\/client|react-refresh)(?![\w-])/ },
  { tool: 'webpack-dev-server', re: /webpack-dev-server\/client|\/sockjs-node(?![\w-])|webpack\/hot\/(?:only-)?dev-server/ },
  { tool: 'Next.js', re: /\/_next\/static\/development\/|\/_next\/webpack-hmr|"buildId"\s*:\s*"development"/ },
];

// Development builds of frameworks. Production React ships 'reactjs.org/docs/error-decoder.html', which must not match.
const DEV_BUILD: { framework: string; re: RegExp }[] = [
  { framework: 'React', re: /react-dom\.development|Download the React DevTools for a better development experience/ },
  { framework: 'Vue', re: /You are running Vue in development mode|You are running a development build of Vue/ },
  { framework: 'Angular', re: /Angular is running in development mode/ },
];

const NEXT_DATA = /<script\b[^>]*\bid\s*=\s*["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i;

function nextDataIsDev(html: string): boolean {
  const raw = html.match(NEXT_DATA)?.[1];
  if (!raw) return false;
  try {
    return (JSON.parse(raw) as { dev?: unknown }).dev === true;
  } catch {
    return false;
  }
}

/** Detects dev servers (HMR clients) and development builds of frameworks served in production. */
export const buildDevMode: CheckModule = {
  manifest: {
    id: 'build.dev-mode',
    version: '0.1.0',
    kind: 'analyzer',
    mode: 'passive',
    category: 'security',
    requires: ['artifact:page'],
    uses: ['artifact:js-bundle'],
    provides: [],
    params: {},
    budget: {},
  },
  run(ctx) {
    const page = ctx.artifacts.list('page')[0]!.data as PageData;
    const sources: Source[] = [{ url: page.finalUrl, text: page.html, isPage: true }];
    for (const a of ctx.artifacts.list('js-bundle')) {
      const b = a.data as BundleData;
      sources.push({ url: b.url, text: b.code, isPage: false });
    }
    const out: Finding[] = [];
    const m = buildDevMode.manifest;

    for (const { tool, re } of DEV_SERVER) {
      for (const s of sources) {
        const hit = s.text.match(re)?.[0];
        const nextDev = tool === 'Next.js' && s.isPage && nextDataIsDev(s.text);
        if (!hit && !nextDev) continue;
        out.push(
          finding(m, {
            kind: 'dev-server',
            severity: 'high',
            confidence: 'confirmed',
            location: { url: s.url },
            evidence: hit ?? '__NEXT_DATA__ "dev":true',
            messageKey: 'build.dev-server',
            vars: { tool },
            discriminator: tool,
          }),
        );
        break;
      }
    }

    for (const { framework, re } of DEV_BUILD) {
      for (const s of sources) {
        const hit = s.text.match(re)?.[0];
        if (!hit) continue;
        out.push(
          finding(m, {
            kind: 'dev-build',
            severity: 'medium',
            confidence: 'confirmed',
            location: { url: s.url },
            evidence: hit.slice(0, 80),
            messageKey: 'build.dev-build',
            vars: { framework },
            discriminator: framework,
          }),
        );
        break;
      }
    }
    return { findings: out };
  },
};
