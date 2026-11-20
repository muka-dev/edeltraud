import { isIP } from 'node:net';

// Blocks private, reserved and metadata addresses. Applied to the target, after every
// DNS resolution and after every redirect.

const V4_BLOCKED: [string, number][] = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16],
  ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
  ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4], ['240.0.0.0', 4],
];

function v4ToInt(ip: string): number {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

function inV4Range(ip: string, base: string, bits: number): boolean {
  const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
  return (v4ToInt(ip) & mask) === (v4ToInt(base) & mask);
}

function expandV6(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/^\[|\]$/g, '').replace(/%.*$/, '');
  // Embedded IPv4 (e.g. ::ffff:10.0.0.1)
  const v4 = s.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) {
    const n = v4ToInt(v4[1]!);
    s = s.slice(0, -v4[1]!.length) + ((n >>> 16).toString(16) + ':' + (n & 0xffff).toString(16));
  }
  const [head, tail] = s.split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined ? (tail ? tail.split(':') : []) : [];
  const fill = s.includes('::') ? 8 - h.length - t.length : 0;
  const parts = [...h, ...Array(fill).fill('0'), ...t];
  if (parts.length !== 8) return null;
  return parts.map((p) => parseInt(p || '0', 16));
}

/** True if the address must not be contacted. Unknown formats are blocked. */
export function isBlockedIp(ip: string): boolean {
  const kind = isIP(ip.replace(/^\[|\]$/g, ''));
  if (kind === 4) return V4_BLOCKED.some(([b, n]) => inV4Range(ip, b, n));
  if (kind === 6) {
    const w = expandV6(ip);
    if (!w) return true;
    if (w.every((x) => x === 0)) return true; // ::
    if (w.slice(0, 7).every((x) => x === 0) && w[7] === 1) return true; // ::1
    // IPv4-mapped / -compatible / NAT64: check the embedded IPv4
    const isMapped = w.slice(0, 5).every((x) => x === 0) && (w[5] === 0xffff || w[5] === 0);
    const isNat64 = w[0] === 0x64 && w[1] === 0xff9b;
    if (isMapped || isNat64) {
      const v4 = `${w[6]! >> 8}.${w[6]! & 255}.${w[7]! >> 8}.${w[7]! & 255}`;
      return isBlockedIp(v4);
    }
    const first = w[0]!;
    if ((first & 0xfe00) === 0xfc00) return true; // fc00::/7 unique local
    if ((first & 0xffc0) === 0xfe80) return true; // fe80::/10 link local
    if ((first & 0xff00) === 0xff00) return true; // multicast
    if (first === 0x2001 && w[1] === 0x0db8) return true; // documentation
    return false;
  }
  return true;
}

const BLOCKED_HOSTS = /^(localhost|.*\.localhost|.*\.local|.*\.internal|metadata\.google\.internal|.*\.home\.arpa)$/i;

export class BlockedTargetError extends Error {
  override name = 'BlockedTargetError';
}

/** Validates a URL before any request: scheme, port, host name, literal IPs. */
export function assertAllowedUrl(raw: string): URL {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new BlockedTargetError('invalid URL');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new BlockedTargetError('only http and https');
  if (u.username || u.password) throw new BlockedTargetError('credentials in URL');
  if (u.port && !['80', '443', '8080', '8443'].includes(u.port)) throw new BlockedTargetError('port not allowed');
  const host = u.hostname.replace(/^\[|\]$/g, '');
  if (BLOCKED_HOSTS.test(host)) throw new BlockedTargetError('internal host name');
  if (isIP(host)) {
    if (isBlockedIp(host)) throw new BlockedTargetError('private or reserved address');
  } else if (!host.includes('.')) {
    throw new BlockedTargetError('host name without domain');
  }
  return u;
}

/** Normalises user input into a target URL ('example.com' → 'https://example.com/'). */
export function normaliseTarget(input: string): URL {
  const s = input.trim();
  const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(s) ? s : `https://${s}`;
  const u = assertAllowedUrl(withScheme);
  u.hash = '';
  return u;
}
