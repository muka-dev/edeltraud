// Proof-of-work helpers. Shared by the Web Worker and the tests (ES module, no DOM).

/** Number of leading zero bits in a byte array. */
export function leadingZeroBits(bytes) {
  let bits = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b === 0) { bits += 8; continue; }
    bits += Math.clz32(b) - 24;
    break;
  }
  return bits;
}

/**
 * Find nonce >= 0 such that SHA-256(`${salt}:${nonce}`) has >= difficulty leading zero bits.
 * options: { subtle, batch = 2000, onProgress(tries) }
 */
export async function solve(salt, difficulty, options = {}) {
  const subtle = options.subtle || globalThis.crypto.subtle;
  const batch = options.batch || 2000;
  const enc = new TextEncoder();
  let base = 0;
  for (;;) {
    const jobs = new Array(batch);
    for (let i = 0; i < batch; i++) {
      jobs[i] = subtle.digest('SHA-256', enc.encode(`${salt}:${base + i}`));
    }
    const digests = await Promise.all(jobs);
    for (let i = 0; i < batch; i++) {
      if (leadingZeroBits(new Uint8Array(digests[i])) >= difficulty) return base + i;
    }
    base += batch;
    if (options.onProgress) options.onProgress(base);
  }
}
