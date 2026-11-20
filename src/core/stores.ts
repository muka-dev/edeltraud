import type { Artifact, ArtifactReader, FactReader } from './types.ts';

export class ArtifactStore implements ArtifactReader {
  private byType = new Map<string, Map<string, Artifact>>();

  add(a: Artifact): void {
    let m = this.byType.get(a.type);
    if (!m) this.byType.set(a.type, (m = new Map()));
    m.set(a.key, a);
  }
  get(type: string, key: string): Artifact | undefined {
    return this.byType.get(type)?.get(key);
  }
  list(type: string): Artifact[] {
    return [...(this.byType.get(type)?.values() ?? [])];
  }
  types(): string[] {
    return [...this.byType.keys()].filter((t) => (this.byType.get(t)?.size ?? 0) > 0);
  }
  /** Serialisable snapshot, used for replay fixtures. */
  toJSON(): Artifact[] {
    return [...this.byType.values()].flatMap((m) => [...m.values()]);
  }
}

export class FactStore implements FactReader {
  private facts = new Map<string, unknown>();

  set(key: string, value: unknown): void {
    this.facts.set(key.startsWith('fact:') ? key : `fact:${key}`, value);
  }
  get<T = unknown>(key: string): T | undefined {
    return this.facts.get(key.startsWith('fact:') ? key : `fact:${key}`) as T | undefined;
  }
  has(key: string): boolean {
    return this.facts.has(key.startsWith('fact:') ? key : `fact:${key}`);
  }
  toJSON(): Record<string, unknown> {
    return Object.fromEntries([...this.facts].map(([k, v]) => [k.slice(5), v]));
  }
}
