import type { CheckModule } from '../core/types.ts';
import { collectBundles } from './collect/bundles.ts';
import { collectPage } from './collect/page.ts';
import { collectSourcemaps } from './collect/sourcemaps.ts';
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
  stackDetect,
  secretsFrontend,
  headersSecurity,
  cookiesFlags,
  tlsBasics,
  sourcemapsExposed,
  supabaseConfig,
  firebaseConfig,
  aiClientLlmCall,
];

export function createRegistry(modules: readonly CheckModule<any>[] = MODULES): Map<string, CheckModule> {
  const reg = new Map<string, CheckModule>();
  for (const m of modules) {
    if (reg.has(m.manifest.id)) throw new Error(`duplicate module id ${m.manifest.id}`);
    reg.set(m.manifest.id, m as CheckModule);
  }
  return reg;
}
