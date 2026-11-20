import { createHash } from 'node:crypto';
import type { Category, Confidence, Finding, Location, ModuleManifest, Severity } from './types.ts';

/** Masks a secret so that it can be shown and stored: 'sk-ant-api03-abc…3f9a'. */
export function mask(secret: string, keepStart = 6, keepEnd = 4): string {
  const s = String(secret);
  if (s.length <= keepStart + keepEnd + 3) return s.slice(0, Math.min(3, s.length)) + '…';
  return s.slice(0, keepStart) + '…' + s.slice(-keepEnd);
}

export function sha256(text: string): string {
  return createHash('sha256').update(text).digest('hex');
}

/** Normalises a location so that cache-busting hashes in bundle names do not create new fingerprints. */
export function normaliseLocation(loc: Location): string {
  const url = (loc.url ?? loc.file ?? '')
    .replace(/[?#].*$/, '')
    .replace(/([-.])[A-Za-z0-9_]{8,}(\.(?:m?js|css|map))$/, '$1#$2');
  return [url, loc.selector ?? ''].join('|');
}

export interface FindingInput {
  kind: string;
  severity: Severity;
  confidence?: Confidence;
  category?: Category;
  location: Location;
  evidence?: string;
  messageKey: string;
  vars?: Record<string, string>;
  /** Extra discriminator for the fingerprint, e.g. the masked secret. */
  discriminator?: string;
}

/** Builds a finding for a module, with a stable fingerprint. */
export function finding(m: ModuleManifest, f: FindingInput): Finding {
  const id = `${m.id}/${f.kind}`;
  const out: Finding = {
    id,
    module: m.id,
    moduleVersion: m.version,
    severity: f.severity,
    confidence: f.confidence ?? 'likely',
    category: f.category ?? m.category,
    location: f.location,
    messageKey: f.messageKey,
    fingerprint: sha256([id, normaliseLocation(f.location), f.discriminator ?? ''].join('\n')).slice(0, 24),
  };
  if (f.evidence !== undefined) out.evidence = f.evidence;
  if (f.vars) out.vars = f.vars;
  return out;
}
