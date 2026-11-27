import { createHmac, timingSafeEqual } from 'node:crypto';
import type { Dns, Http } from '../core/types.ts';
import { registrableDomain } from '../modules/collect/dns.ts';

/**
 * Proof of ownership for active checks (deep check).
 *
 * The operator gets a token bound to the host and the account and places it either
 *   - as DNS TXT record `edeltraud-verify=<token>` on the host, on `_edeltraud.<host>`
 *     or on the registrable domain (the domain record covers all its subdomains), or
 *   - as file `https://<host>/.well-known/edeltraud-<token>.txt` containing the token
 *     (covers exactly this host).
 *
 * Tokens are stateless (HMAC), can be placed within 14 days, and a successful check is
 * valid for 30 days. Nothing is stored here; the caller keeps the Verification.
 */

export const TOKEN_TTL_MS = 14 * 24 * 60 * 60_000;
export const VERIFICATION_TTL_MS = 30 * 24 * 60 * 60_000;

export interface Verification {
  host: string;
  account: string;
  method: 'dns' | 'file';
  /** Where the token was found. */
  where: string;
  /** Host names covered: the exact host, or with DNS on the registrable domain all its subdomains. */
  scope: 'host' | 'domain';
  verifiedAt: string;
  expiresAt: string;
}

export interface Instructions {
  token: string;
  dns: { name: string; type: 'TXT'; value: string }[];
  file: { url: string; content: string };
  expiresAt: string;
}

export class OwnershipError extends Error {
  override name = 'OwnershipError';
}

function normHost(host: string): string {
  const h = host.trim().toLowerCase().replace(/\.$/, '');
  if (!/^[a-z0-9.-]+$/.test(h) || !h.includes('.')) throw new OwnershipError(`invalid host ${host}`);
  return h;
}

function mac(secret: string, host: string, account: string, issued: number): string {
  return createHmac('sha256', secret).update(`edeltraud-ownership\n${host}\n${account}\n${issued}`).digest('base64url').slice(0, 22);
}

/** Token format: <issued, base36>.<hmac> — no secret inside, safe to publish in DNS. */
export function issueToken(secret: string, host: string, account: string, now = Date.now()): Instructions {
  if (secret.length < 16) throw new OwnershipError('ownership secret missing or too short');
  const h = normHost(host);
  const token = `${now.toString(36)}.${mac(secret, h, account, now)}`;
  const value = `edeltraud-verify=${token}`;
  const domain = registrableDomain(h);
  return {
    token,
    dns: [
      { name: `_edeltraud.${h}`, type: 'TXT', value },
      ...(domain !== h ? [{ name: domain, type: 'TXT' as const, value }] : []),
    ],
    file: { url: `https://${h}/.well-known/edeltraud-${token}.txt`, content: token },
    expiresAt: new Date(now + TOKEN_TTL_MS).toISOString(),
  };
}

/** Checks that a token belongs to host + account and is not too old. */
export function checkToken(secret: string, host: string, account: string, token: string, now = Date.now()): void {
  const m = /^([0-9a-z]{6,12})\.([A-Za-z0-9_-]{22})$/.exec(token);
  if (!m) throw new OwnershipError('malformed token');
  const issued = parseInt(m[1]!, 36);
  const expected = Buffer.from(mac(secret, normHost(host), account, issued));
  const got = Buffer.from(m[2]!);
  if (expected.length !== got.length || !timingSafeEqual(expected, got)) throw new OwnershipError('token does not belong to this host or account');
  if (issued > now + 60_000 || now - issued > TOKEN_TTL_MS) throw new OwnershipError('token expired, request a new one');
}

/**
 * Looks for the token in DNS first, then as a file. Only GET on the target, no redirects
 * to other hosts are accepted for the file.
 */
export async function verifyOwnership(opts: {
  secret: string;
  host: string;
  account: string;
  token: string;
  dns?: Dns;
  http?: Http;
  now?: number;
}): Promise<Verification> {
  const now = opts.now ?? Date.now();
  const host = normHost(opts.host);
  checkToken(opts.secret, host, opts.account, opts.token, now);
  const value = `edeltraud-verify=${opts.token}`;
  const done = (method: Verification['method'], where: string, scope: Verification['scope']): Verification => ({
    host,
    account: opts.account,
    method,
    where,
    scope,
    verifiedAt: new Date(now).toISOString(),
    expiresAt: new Date(now + VERIFICATION_TTL_MS).toISOString(),
  });

  if (opts.dns) {
    const domain = registrableDomain(host);
    const names: [string, Verification['scope']][] = [
      [`_edeltraud.${host}`, 'host'],
      [host, 'host'],
      ...(domain !== host ? ([[domain, 'domain']] as [string, Verification['scope']][]) : []),
    ];
    if (domain === host) names[1]![1] = 'domain';
    for (const [name, scope] of names) {
      const txt = await opts.dns.resolve(name, 'TXT').catch(() => [] as string[]);
      if (txt.some((t) => t.trim() === value)) return done('dns', name, scope);
    }
  }
  if (opts.http) {
    const url = `https://${host}/.well-known/edeltraud-${opts.token}.txt`;
    try {
      const res = await opts.http.fetch({ url, maxBytes: 1024 });
      const sameHost = new URL(res.finalUrl).hostname === host;
      if (res.status === 200 && sameHost && res.body.trim() === opts.token) return done('file', url, 'host');
    } catch {
      /* not reachable: fall through */
    }
  }
  throw new OwnershipError('token not found in DNS or under /.well-known/');
}

/** True if a verification covers this host right now. */
export function covers(v: Verification, host: string, now = Date.now()): boolean {
  if (Date.parse(v.expiresAt) <= now) return false;
  const h = normHost(host);
  return v.scope === 'domain' ? h === v.host || h.endsWith(`.${registrableDomain(v.host)}`) || h === registrableDomain(v.host) : h === v.host;
}
