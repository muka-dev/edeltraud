import type { BundleData } from '../util.ts';

export interface FirebaseConfig {
  apiKey: string;
  projectId: string;
  databaseURL?: string;
  storageBucket?: string;
}

const API_KEY = /["']?apiKey["']?\s*:\s*["'](AIza[A-Za-z0-9_-]{30,50})["']/g;
const PROJECT = /["']?projectId["']?\s*:\s*["']([a-z][a-z0-9-]{3,29})["']/;
const DATABASE = /["']?databaseURL["']?\s*:\s*["'](https:\/\/[a-z0-9-]+(?:-default-rtdb)?(?:\.[a-z0-9-]+)?\.(?:firebaseio\.com|firebasedatabase\.app))\/?["']/;
const BUCKET = /["']?storageBucket["']?\s*:\s*["']([a-z0-9][a-z0-9._-]{2,62}\.(?:appspot\.com|firebasestorage\.app))["']/;

/**
 * Finds the Firebase web config object (public by design) in the app's code and HTML.
 * Only public Google hosts are accepted for databaseURL and storageBucket.
 */
export function findFirebaseConfig(bundles: readonly BundleData[], html = ''): FirebaseConfig | null {
  const texts = [...bundles.map((b) => b.code), html];
  for (const text of texts) {
    for (const m of text.matchAll(API_KEY)) {
      const i = m.index ?? 0;
      const around = text.slice(Math.max(0, i - 600), i + 900);
      const projectId = around.match(PROJECT)?.[1];
      if (!projectId) continue;
      const databaseURL = around.match(DATABASE)?.[1];
      const storageBucket = around.match(BUCKET)?.[1];
      return { apiKey: m[1]!, projectId, ...(databaseURL ? { databaseURL } : {}), ...(storageBucket ? { storageBucket } : {}) };
    }
  }
  return null;
}
