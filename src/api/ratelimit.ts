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

  /** Seconds to wait if the key is at its limit, else 0. Does not count. */
  peek(key: string): number {
    const t = this.now();
    const e = this.hits.get(key);
    if (!e || e.reset <= t || e.count < this.limit) return 0;
    return Math.ceil((e.reset - t) / 1000);
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

/**
 * Key for per-client limits. IPv6 clients usually own a whole /64, so counting single
 * addresses would make the limit trivial to dodge; IPv4-mapped addresses count as IPv4.
 */
export function clientKey(ip: string): string {
  const v4 = ip.match(/^(?:::ffff:)?(\d{1,3}(?:\.\d{1,3}){3})$/i);
  if (v4) return v4[1]!;
  if (!ip.includes(':')) return ip;
  const [head, tail = ''] = ip.toLowerCase().split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = [...left, ...Array(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right];
  return groups.slice(0, 4).map((g) => g.replace(/^0+(?=.)/, '')).join(':') + '::/64';
}

/** Several windows for one key, e.g. 3 per minute, 10 per hour, 30 per day. All must allow. */
export class TieredLimiter {
  private tiers: RateLimiter[];
  constructor(tiers: { limit: number; windowMs: number }[], now: () => number = Date.now) {
    this.tiers = tiers.map((t) => new RateLimiter(t.limit, t.windowMs, now));
  }
  /** Seconds until the key may try again; 0 means allowed (and counted in every tier). */
  check(key: string): number {
    for (const t of this.tiers) {
      const wait = t.peek(key);
      if (wait) return wait;
    }
    for (const t of this.tiers) t.take(key);
    return 0;
  }
}
