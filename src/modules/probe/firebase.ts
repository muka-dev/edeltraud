import { finding } from '../../core/finding.ts';
import type { CheckModule, HttpResponse, ModuleContext, NotChecked } from '../../core/types.ts';
import type { BundleData, PageData } from '../util.ts';
import { findFirebaseConfig, type FirebaseConfig } from './firebase-config.ts';

function configFrom(ctx: ModuleContext): FirebaseConfig | null {
  const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
  const html = (ctx.artifacts.list('page')[0]?.data as PageData | undefined)?.html ?? '';
  return findFirebaseConfig(bundles, html);
}

const errText = (e: unknown) => (e instanceof Error ? e.message : String(e));
const isBudget = (e: unknown) => e instanceof Error && e.name === 'BudgetExceededError';

function parseJson(res: HttpResponse): unknown {
  try {
    return JSON.parse(res.body);
  } catch {
    return undefined;
  }
}

const NO_CONFIG = (id: string): { notChecked: NotChecked[] } => ({
  notChecked: [{ module: id, reason: 'condition', detail: 'no Firebase web config found in the code' }],
});

// ---------------------------------------------------------------------------------------------
// firebase.rtdb-open: shallow read only. Shallow returns top-level keys with the value `true`, never data.

export const firebaseRtdbOpen: CheckModule = {
  manifest: {
    id: 'firebase.rtdb-open',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: [],
    when: ['fact:stack.firebase'],
    params: {},
    budget: { requests: 2 },
  },
  async run(ctx) {
    const m = firebaseRtdbOpen.manifest;
    const cfg = configFrom(ctx);
    if (!cfg) return NO_CONFIG(m.id);
    if (!cfg.databaseURL) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no Realtime Database URL in the Firebase config' }] };
    const url = `${cfg.databaseURL}/.json?shallow=true`;
    let res: HttpResponse;
    try {
      res = await ctx.http!.fetch({ url, headers: { Accept: 'application/json' }, maxBytes: 100_000 });
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: isBudget(e) ? 'budget' : 'error', detail: errText(e) }] };
    }
    if (res.status !== 200) return {}; // 401 Permission denied, 404/423 missing or locked: protected
    const body = parseJson(res);
    // null = empty database, scalar = nothing to name; only an object with keys proves open read access
    if (!body || typeof body !== 'object' || Array.isArray(body)) return {};
    const keys = Object.keys(body as object);
    if (!keys.length) return {};
    const sample = keys.slice(0, 5).join(', ');
    return {
      findings: [
        finding(m, {
          kind: 'rtdb-open',
          severity: 'critical',
          confidence: 'confirmed',
          location: { url: `${cfg.databaseURL}/` },
          evidence: `shallow read: ${keys.length} Schlüssel auf oberster Ebene (${sample}), keine Werte gelesen`,
          messageKey: 'firebase.rtdb-open',
          vars: { keys: String(keys.length), sample },
        }),
      ],
    };
  },
};

// ---------------------------------------------------------------------------------------------
// firebase.firestore-open: one document per collection at most (pageSize=1), field names only.

const PERSONAL_FIELD = /e-?mail|phone|mobile|(^|_)tel($|_)|(first|last|full|user|display)_?name|^name$|address|street|passw|token|secret|iban|birth|(^|_)dob($|_)|(^|_)ip($|_)|ip_?address|(^|_)ssn($|_)|card_?number/i;
const SENSITIVE_COLLECTION = /user|profile|account|customer|client|order|message|payment|subscription|admin|member|contact|lead|invoice|booking|patient|chat/i;
const COLLECTION_NAME = /^[A-Za-z_][A-Za-z0-9_-]{0,62}$/;

/** Top-level collection names the app's own code uses. */
export function collectionsFromBundles(bundles: readonly BundleData[]): string[] {
  const out = new Set<string>();
  const patterns = [
    /\bcollection\(\s*[A-Za-z_$][\w$.]*\s*,\s*["'`]([^"'`/]+)["'`]/g,
    /\.collection\(\s*["'`]([^"'`/]+)["'`]/g,
    /\bdoc\(\s*[A-Za-z_$][\w$.]*\s*,\s*["'`]([^"'`/]+)["'`]/g,
  ];
  for (const b of bundles) {
    for (const re of patterns) for (const x of b.code.matchAll(re)) if (COLLECTION_NAME.test(x[1]!)) out.add(x[1]!);
  }
  return [...out];
}

export const firebaseFirestoreOpen: CheckModule<{ maxCollections: number }> = {
  manifest: {
    id: 'firebase.firestore-open',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: [],
    when: ['fact:stack.firebase'],
    params: { maxCollections: { type: 'number', default: 10, min: 1, max: 10 } },
    budget: { requests: 12 },
  },
  async run(ctx, params) {
    const m = firebaseFirestoreOpen.manifest;
    const cfg = configFrom(ctx);
    if (!cfg) return NO_CONFIG(m.id);
    const bundles = ctx.artifacts.list('js-bundle').map((a) => a.data as BundleData);
    const all = collectionsFromBundles(bundles).sort(
      (a, b) => Number(SENSITIVE_COLLECTION.test(b)) - Number(SENSITIVE_COLLECTION.test(a)) || a.localeCompare(b),
    );
    if (!all.length) return { notChecked: [{ module: m.id, reason: 'unsupported', detail: 'no collection names found in the code' }] };
    const cap = all.slice(0, params.maxCollections);
    let left = all.length - cap.length;
    const notChecked: NotChecked[] = [];
    const findings = [];

    for (let i = 0; i < cap.length; i++) {
      const collection = cap[i]!;
      const base = `https://firestore.googleapis.com/v1/projects/${cfg.projectId}/databases/(default)/documents/${encodeURIComponent(collection)}`;
      let res: HttpResponse;
      try {
        res = await ctx.http!.fetch({ url: `${base}?pageSize=1&key=${cfg.apiKey}`, method: 'GET', headers: { Accept: 'application/json' }, maxBytes: 200_000 });
      } catch (e) {
        if (isBudget(e)) {
          left += cap.length - i;
          break;
        }
        notChecked.push({ module: m.id, reason: 'error', detail: `${collection}: ${errText(e)}` });
        continue;
      }
      if (res.status !== 200) continue; // 403 PERMISSION_DENIED, 404: protected
      const body = parseJson(res) as { documents?: unknown } | undefined;
      const first = Array.isArray(body?.documents) ? (body!.documents as { fields?: unknown }[])[0] : undefined;
      if (!first) continue; // {} = empty collection or filtered
      // Only field names survive; values are dropped here.
      const fieldNames = first.fields && typeof first.fields === 'object' ? Object.keys(first.fields as object) : [];
      const fields = fieldNames.slice(0, 8).join(', ');
      const personal = fieldNames.some((f) => PERSONAL_FIELD.test(f));
      findings.push(
        finding(m, {
          kind: 'firestore-open',
          severity: personal ? 'critical' : 'high',
          confidence: 'confirmed',
          location: { url: base },
          evidence: `${collection}: 1 Dokument lesbar, Felder ${fields || '(keine)'}`,
          messageKey: 'firebase.firestore-open',
          vars: { collection, fields },
          discriminator: collection,
        }),
      );
    }
    if (left > 0) notChecked.push({ module: m.id, reason: 'budget', detail: `${left} collections not checked` });
    return { findings, notChecked };
  },
};

// ---------------------------------------------------------------------------------------------
// firebase.storage-open: lists at most one object name's existence, the name itself is not stored.

export const firebaseStorageOpen: CheckModule = {
  manifest: {
    id: 'firebase.storage-open',
    version: '0.1.0',
    kind: 'probe',
    mode: 'active',
    category: 'security',
    requires: ['artifact:js-bundle'],
    uses: ['artifact:page'],
    provides: [],
    when: ['fact:stack.firebase'],
    params: {},
    budget: { requests: 1 },
  },
  async run(ctx) {
    const m = firebaseStorageOpen.manifest;
    const cfg = configFrom(ctx);
    if (!cfg) return NO_CONFIG(m.id);
    if (!cfg.storageBucket) return { notChecked: [{ module: m.id, reason: 'condition', detail: 'no storage bucket in the Firebase config' }] };
    const bucket = cfg.storageBucket;
    const url = `https://firebasestorage.googleapis.com/v0/b/${bucket}/o?maxResults=1`;
    let res: HttpResponse;
    try {
      res = await ctx.http!.fetch({ url, headers: { Accept: 'application/json' }, maxBytes: 50_000 });
    } catch (e) {
      return { notChecked: [{ module: m.id, reason: isBudget(e) ? 'budget' : 'error', detail: errText(e) }] };
    }
    if (res.status !== 200) return {}; // 403: protected
    const body = parseJson(res) as { items?: unknown } | undefined;
    if (!Array.isArray(body?.items) || !body!.items.length) return {};
    return {
      findings: [
        finding(m, {
          kind: 'storage-listable',
          severity: 'high',
          confidence: 'confirmed',
          location: { url },
          evidence: `Bucket ${bucket}: Dateiliste ohne Anmeldung lesbar, 1 Eintrag geprüft`,
          messageKey: 'firebase.storage-listable',
          vars: { bucket },
        }),
      ],
    };
  },
};

export const FIREBASE_MODULES: CheckModule<any>[] = [firebaseRtdbOpen, firebaseFirestoreOpen, firebaseStorageOpen];
