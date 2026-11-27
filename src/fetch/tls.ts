import tls from 'node:tls';
import type { LookupFunction } from 'node:net';
import type { TlsInfo, TlsInspector } from '../core/types.ts';
import { safeLookup } from './http.ts';

const TIMEOUT_MS = 8_000;

export interface LiveTlsOptions {
  /** Injectable for tests; defaults to the SSRF-safe lookup. */
  lookup?: LookupFunction;
  timeoutMs?: number;
}

type Handshake =
  | { ok: true; socket: tls.TLSSocket }
  | { ok: false; kind: 'alert' | 'network'; error: Error };

/** Alert / protocol errors mean the server refused; everything else is inconclusive. */
function isAlert(e: NodeJS.ErrnoException): boolean {
  const code = String(e.code ?? '');
  return /^ERR_SSL_|^ERR_TLS_|ERR_SSL/.test(code) || /alert|handshake failure|protocol version|no protocols available|wrong version|unsupported protocol/i.test(e.message);
}

/** Real TLS handshakes. Certificate trust is reported, never enforced (rejectUnauthorized: false). */
export class LiveTls implements TlsInspector {
  private lookup: LookupFunction;
  private timeoutMs: number;
  constructor(opts: LiveTlsOptions = {}) {
    this.lookup = opts.lookup ?? safeLookup;
    this.timeoutMs = opts.timeoutMs ?? TIMEOUT_MS;
  }

  private handshake(host: string, port: number, extra: tls.ConnectionOptions = {}): Promise<Handshake> {
    return new Promise((resolve) => {
      let settled = false;
      const done = (r: Handshake) => {
        if (settled) return;
        settled = true;
        if (!r.ok) socket.destroy();
        resolve(r);
      };
      const socket = tls.connect({
        host,
        port,
        servername: host,
        lookup: this.lookup,
        rejectUnauthorized: false,
        timeout: this.timeoutMs,
        ...extra,
      });
      socket.once('secureConnect', () => done({ ok: true, socket }));
      socket.once('timeout', () => done({ ok: false, kind: 'network', error: Object.assign(new Error('TLS handshake timeout'), { code: 'ETIMEDOUT' }) }));
      socket.once('error', (e: NodeJS.ErrnoException) => done({ ok: false, kind: isAlert(e) ? 'alert' : 'network', error: e }));
      socket.once('close', () => done({ ok: false, kind: 'network', error: new Error('connection closed') }));
    });
  }

  private async legacy(host: string, port: number, version: 'TLSv1' | 'TLSv1.1'): Promise<boolean | null> {
    const r = await this.handshake(host, port, { minVersion: version, maxVersion: version, ciphers: 'DEFAULT:@SECLEVEL=0' });
    if (r.ok) {
      r.socket.destroy();
      return true;
    }
    return r.kind === 'alert' ? false : null;
  }

  async inspect(host: string, opts: { port?: number; legacyProtocols?: boolean } = {}): Promise<TlsInfo> {
    const port = opts.port ?? 443;
    const r = await this.handshake(host, port);
    if (!r.ok) throw r.error;
    const socket = r.socket;
    let info: TlsInfo;
    try {
      const cert = socket.getPeerCertificate();
      const has = cert && Object.keys(cert).length > 0;
      const iso = (s?: string) => {
        const t = s ? Date.parse(s) : NaN;
        return Number.isNaN(t) ? null : new Date(t).toISOString();
      };
      const name = (o?: { O?: string | string[]; CN?: string | string[] }) => {
        const v = o?.O ?? o?.CN;
        return (Array.isArray(v) ? v[0] : v) ?? null;
      };
      const subjCn = cert?.subject?.CN;
      const altNames = has && cert.subjectaltname
        ? cert.subjectaltname.split(',').map((s) => s.trim()).filter((s) => s.startsWith('DNS:')).map((s) => s.slice(4))
        : [];
      info = {
        host,
        port,
        checkedAt: new Date().toISOString(),
        protocol: socket.getProtocol() ?? null,
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
        validFrom: has ? iso(cert.valid_from) : null,
        validTo: has ? iso(cert.valid_to) : null,
        issuer: has ? name(cert.issuer) : null,
        subject: has ? (Array.isArray(subjCn) ? subjCn[0] ?? null : subjCn ?? null) : null,
        altNames,
        legacy: { 'TLSv1': null, 'TLSv1.1': null },
      };
    } finally {
      socket.destroy();
    }
    if (opts.legacyProtocols ?? true) {
      info.legacy = { 'TLSv1': await this.legacy(host, port, 'TLSv1'), 'TLSv1.1': await this.legacy(host, port, 'TLSv1.1') };
    }
    return info;
  }
}
