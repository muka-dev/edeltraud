import type { CheckModule } from '../core/types.ts';
import { collectBundles } from './collect/bundles.ts';
import { collectPage } from './collect/page.ts';
import { collectSourcemaps } from './collect/sourcemaps.ts';
import { collectTls } from './collect/tls.ts';
import { collectRender } from './collect/render.ts';
import { collectLegal } from './collect/legal.ts';
import { privacyLegalPages } from './analyze/legal.ts';
import { opsErrorsConsole } from './analyze/console.ts';
import { mixedContent, sriMissing } from './analyze/content.ts';
import { privacyConsentBeforeTracking, privacyGoogleFonts, privacyThirdParty } from './analyze/privacy.ts';
import { depsServer } from './analyze/server.ts';
import { nextDataLeak } from './analyze/nextdata.ts';
import { aiSystemPromptExposed } from './analyze/prompts.ts';
import { SUPABASE_MODULES } from './probe/supabase.ts';
import { FIREBASE_MODULES } from './probe/firebase.ts';
import { pathsSensitive } from './probe/paths.ts';
import { dnsDangling } from './analyze/dangling.ts';
import { collectWellknown } from './collect/wellknown.ts';
import { WELLKNOWN_ANALYZERS } from './analyze/wellknown.ts';
import { ENDPOINT_MODULES } from './analyze/endpoints.ts';
import { API_MODULES } from './probe/api.ts';
import { collectDns } from './collect/dns.ts';
import { dnsMail } from './analyze/dns.ts';
import { headersCspQuality } from './analyze/csp.ts';
import { depsVulnerable } from './analyze/deps.ts';
import { collectErrorpages } from './collect/errorpages.ts';
import { buildDevMode } from './analyze/build.ts';
import { errorsVerbose } from './analyze/errors.ts';
import { aiClientLlmCall } from './analyze/ai.ts';
import { firebaseConfig, supabaseConfig } from './analyze/backend.ts';
import { cookiesFlags, headersSecurity } from './analyze/headers.ts';
import { secretsFrontend } from './analyze/secrets.ts';
import { sourcemapsExposed } from './analyze/sourcemaps.ts';
import { stackDetect } from './analyze/stack.ts';
import { tlsBasics } from './analyze/tls.ts';

/** All modules, registered at build time. New modules are added here. */
export const MODULES: readonly CheckModule<any>[] = [
  collectPage,
  collectBundles,
  collectSourcemaps,
  collectTls,
  collectRender,
  collectLegal,
  collectWellknown,
  collectDns,
  collectErrorpages,
  stackDetect,
  secretsFrontend,
  headersSecurity,
  cookiesFlags,
  headersCspQuality,
  dnsMail,
  tlsBasics,
  sourcemapsExposed,
  supabaseConfig,
  firebaseConfig,
  aiClientLlmCall,
  depsVulnerable,
  buildDevMode,
  errorsVerbose,
  privacyLegalPages,
  opsErrorsConsole,
  mixedContent,
  sriMissing,
  privacyThirdParty,
  privacyGoogleFonts,
  privacyConsentBeforeTracking,
  depsServer,
  nextDataLeak,
  aiSystemPromptExposed,
  ...SUPABASE_MODULES,
  ...FIREBASE_MODULES,
  pathsSensitive,
  dnsDangling,
  ...WELLKNOWN_ANALYZERS,
  ...ENDPOINT_MODULES,
  ...API_MODULES,
];

export function createRegistry(modules: readonly CheckModule<any>[] = MODULES): Map<string, CheckModule> {
  const reg = new Map<string, CheckModule>();
  for (const m of modules) {
    if (reg.has(m.manifest.id)) throw new Error(`duplicate module id ${m.manifest.id}`);
    reg.set(m.manifest.id, m as CheckModule);
  }
  return reg;
}
