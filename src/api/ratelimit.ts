/** Fixed-window counter per key. In memory: one API process per server is enough for now. */
export class RateLimiter {
  private hits = new Map<string, { count: number; reset: number }>();
  private limit: number;
  private windowMs: number;
  private now: () => number;

  constructor(limit: number, windowMs: number, now: () => number = Date.now) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.now = now;
  }

  /** Returns seconds to wait, or 0 if allowed (and counts the hit). */
  take(key: string): number {
    const t = this.now();
    let e = this.hits.get(key);
    if (!e || e.reset <= t) {
      e = { count: 0, reset: t + this.windowMs };
      this.hits.set(key, e);
    }
    if (e.count >= this.limit) return Math.ceil((e.reset - t) / 1000);
    e.count++;
    if (this.hits.size > 50_000) this.sweep(t);
    return 0;
  }

  private sweep(t: number): void {
    for (const [k, e] of this.hits) if (e.reset <= t) this.hits.delete(k);
  }
}

/** Short-lived result cache, so repeated scans of one target do not hit it again. */
export class TtlCache<T> {
  private items = new Map<string, { value: T; until: number }>();
  private ttlMs: number;
  private now: () => number;

  constructor(ttlMs: number, now: () => number = Date.now) {
    this.ttlMs = ttlMs;
    this.now = now;
  }
  get(key: string): T | undefined {
    const e = this.items.get(key);
    if (!e) return undefined;
    if (e.until <= this.now()) {
      this.items.delete(key);
      return undefined;
    }
    return e.value;
  }
  set(key: string, value: T): void {
    this.items.set(key, { value, until: this.now() + this.ttlMs });
  }
}
