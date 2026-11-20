// Shared types for EDEL.TRAUD.AI. See docs/spec/architektur.md.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export const SEVERITIES: readonly Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

export type Confidence = 'confirmed' | 'likely' | 'possible';
export type Category = 'security' | 'privacy' | 'accessibility' | 'operations' | 'ai' | 'quality';
export type ModuleKind = 'collector' | 'analyzer' | 'probe';
export type ModuleMode = 'passive' | 'active';
export type Lang = 'de' | 'en' | 'pt' | 'pt-BR';

/** Minimal parameter schema: enough to validate plans without a JSON-Schema library. */
export type ParamSpec =
  | { type: 'number'; default: number; min?: number; max?: number }
  | { type: 'boolean'; default: boolean }
  | { type: 'string'; default: string; enum?: readonly string[] };
export type ParamSchema = Record<string, ParamSpec>;
export type Params = Record<string, number | boolean | string>;

export interface Budget {
  /** HTTP requests this module may make. */
  requests?: number;
  /** Wall time this module may take. */
  ms?: number;
  /** Needs a headless browser. */
  browser?: boolean;
}

export interface ModuleManifest {
  /** Stable id, never renamed, e.g. 'secrets.frontend'. */
  id: string;
  version: string;
  kind: ModuleKind;
  mode: ModuleMode;
  category: Category;
  /** Keys of facts or artifact types this module needs, e.g. 'artifact:js-bundle'. */
  requires: readonly string[];
  /** Optional inputs: ordered after their providers, but not required to run. */
  uses?: readonly string[];
  /** Keys this module may produce. Used to build the dependency graph. */
  provides: readonly string[];
  /** Run only if all these facts are truthy once known, e.g. 'fact:stack.supabase'. */
  when?: readonly string[];
  params: ParamSchema;
  budget: Budget;
}

export interface Location {
  url?: string;
  file?: string;
  line?: number;
  selector?: string;
}

export interface Finding {
  /** '<module>/<kind>', e.g. 'secrets.frontend/openai-key'. */
  id: string;
  module: string;
  moduleVersion: string;
  severity: Severity;
  confidence: Confidence;
  category: Category;
  location: Location;
  /** Always masked. Never the raw secret or record. */
  evidence?: string;
  /** Key into the i18n catalogs: '<key>.title', '<key>.explain', '<key>.fix', '<key>.prompt'. */
  messageKey: string;
  vars?: Record<string, string>;
  /** Stable across runs: used by watch (new findings) and re-checks (fixed findings). */
  fingerprint: string;
}

export type NotCheckedReason = 'ownership' | 'budget' | 'condition' | 'error' | 'unsupported' | 'dependency';

export interface NotChecked {
  module: string;
  reason: NotCheckedReason;
  detail?: string;
}

export interface Artifact {
  /** Artifact type, e.g. 'page', 'js-bundle', 'tls', 'sourcemap-head'. */
  type: string;
  /** Unique within the type, usually the URL. */
  key: string;
  data: unknown;
}

export interface ModuleResult {
  findings?: Finding[];
  facts?: Record<string, unknown>;
  artifacts?: Artifact[];
  notChecked?: NotChecked[];
}

export interface Target {
  /** Normalised origin + path, e.g. 'https://app.example.com/'. */
  url: string;
  host: string;
  /** Ownership verified (DNS TXT or .well-known file). Required for active modules. */
  ownershipVerified: boolean;
}

export interface Logger {
  debug(msg: string, extra?: unknown): void;
  warn(msg: string, extra?: unknown): void;
}

export interface HttpRequest {
  url: string;
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
  /** Max bytes of body to read. */
  maxBytes?: number;
  /** Follow redirects (default true, max 5). */
  followRedirects?: boolean;
}

export interface HttpResponse {
  url: string;
  /** Final URL after redirects. */
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  /** Raw 'set-cookie' header lines. */
  setCookies: string[];
  body: string;
  truncated: boolean;
  redirects: string[];
}

export interface Http {
  fetch(req: HttpRequest): Promise<HttpResponse>;
}

export interface ArtifactReader {
  get(type: string, key: string): Artifact | undefined;
  list(type: string): Artifact[];
}

export interface FactReader {
  get<T = unknown>(key: string): T | undefined;
  has(key: string): boolean;
}

export interface ModuleContext {
  target: Target;
  artifacts: ArtifactReader;
  facts: FactReader;
  /** Only for collectors and probes. */
  http?: Http;
  log: Logger;
  signal: AbortSignal;
}

export interface CheckModule<P extends Params = Params> {
  manifest: ModuleManifest;
  run(ctx: ModuleContext, params: P): Promise<ModuleResult> | ModuleResult;
}

export interface PlanStep {
  module: string;
  params: Params;
}

export interface Plan {
  plan: string;
  version: number;
  limits: { totalMs: number; requests: number; browser: boolean };
  modules: PlanStep[];
  presentation: { showFindings: number | 'all'; fixPrompts: boolean };
}

/** 'unknown': the scan was incomplete and found nothing. Never shown as green. */
export type Light = 'red' | 'yellow' | 'green' | 'unknown';

export interface Verdict {
  light: Light;
  rule: string;
  counts: Record<Severity, number>;
}

export interface ScanResult {
  tool: { name: 'edeltraud'; version: string };
  plan: { name: string; version: number };
  target: Target;
  startedAt: string;
  durationMs: number;
  /** False if a module failed or was skipped for a missing input or budget. */
  complete: boolean;
  verdict: Verdict;
  findings: Finding[];
  notChecked: NotChecked[];
  facts: Record<string, unknown>;
  modules: { id: string; version: string; status: 'ok' | 'skipped' | 'error'; ms: number }[];
  requests: number;
}
