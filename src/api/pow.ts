import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

/**
 * Proof of work for the free check: before each scan the browser solves a small puzzle
 * (about 65,000 hashes at difficulty 16, well under two seconds). For a person this is
 * invisible; for a script that wants thousands of scans it adds up. No third party,
 * no cookie, no tracking.
 */
export interface Challenge {
  algorithm: 'SHA-256';
  salt: string;
  difficulty: number;
  expires: number;
  signature: string;
}

export interface Solution {
  salt: string;
  nonce: string | number;
  expires: number;
  signature: string;
}

export type PowError = 'pow_required' | 'pow_invalid' | 'pow_expired' | 'pow_used';

export function leadingZeroBits(buf: Uint8Array): number {
  let n = 0;
  for (const byte of buf) {
    if (byte === 0) {
      n += 8;
      continue;
    }
    return n + Math.clz32(byte) - 24;
  }
  return n;
}

export class ProofOfWork {
  private secret: Buffer;
  private difficulty: number;
  private ttlMs: number;
  private now: () => number;
  /** Solved challenges until they expire: each challenge buys exactly one scan. */
  private used = new Map<string, number>();

  constructor(opts: { secret?: string; difficulty?: number; ttlMs?: number; now?: () => number } = {}) {
    this.secret = opts.secret ? Buffer.from(opts.secret) : randomBytes(32);
    this.difficulty = opts.difficulty ?? 16;
    this.ttlMs = opts.ttlMs ?? 5 * 60_000;
    this.now = opts.now ?? Date.now;
  }

  issue(): Challenge {
    const salt = randomBytes(16).toString('hex');
    const expires = this.now() + this.ttlMs;
    return { algorithm: 'SHA-256', salt, difficulty: this.difficulty, expires, signature: this.sign(salt, this.difficulty, expires) };
  }

  /** Returns null if the solution is valid (and marks it used), else the reason. */
  verify(s: unknown): PowError | null {
    if (!s || typeof s !== 'object') return 'pow_required';
    const { salt, nonce, expires, signature } = s as Partial<Solution>;
    if (typeof salt !== 'string' || !/^[0-9a-f]{32}$/.test(salt)) return 'pow_invalid';
    if (typeof expires !== 'number' || typeof signature !== 'string' || !/^[0-9a-f]{64}$/.test(signature)) return 'pow_invalid';
    const n = String(nonce ?? '');
    if (!/^\d{1,12}$/.test(n)) return 'pow_invalid';
    const expected = Buffer.from(this.sign(salt, this.difficulty, expires), 'hex');
    if (!timingSafeEqual(expected, Buffer.from(signature, 'hex'))) return 'pow_invalid';
    const t = this.now();
    if (expires <= t) return 'pow_expired';
    this.sweep(t);
    if (this.used.has(salt)) return 'pow_used';
    const hash = createHash('sha256').update(`${salt}:${n}`).digest();
    if (leadingZeroBits(hash) < this.difficulty) return 'pow_invalid';
    this.used.set(salt, expires);
    return null;
  }

  private sign(salt: string, difficulty: number, expires: number): string {
    return createHmac('sha256', this.secret).update(`${salt}.${difficulty}.${expires}`).digest('hex');
  }

  private sweep(t: number): void {
    if (this.used.size < 1000) return;
    for (const [k, exp] of this.used) if (exp <= t) this.used.delete(k);
  }
}

/** Reference solver (tests, CLI clients). The page uses the same rule in web/assets/pow.js. */
export function solve(c: Pick<Challenge, 'salt' | 'difficulty'>, maxTries = 50_000_000): number {
  for (let nonce = 0; nonce < maxTries; nonce++) {
    if (leadingZeroBits(createHash('sha256').update(`${c.salt}:${nonce}`).digest()) >= c.difficulty) return nonce;
  }
  throw new Error('no solution found');
}
