import type { TlsInfo, TlsInspector } from '../core/types.ts';

/** Fixture TLS: host → handshake result. Unknown hosts fail like a closed port. */
export class ReplayTls implements TlsInspector {
  private hosts: Record<string, Partial<TlsInfo>>;
  constructor(hosts: Record<string, Partial<TlsInfo>>) {
    this.hosts = hosts;
  }
  async inspect(host: string, opts: { port?: number; legacyProtocols?: boolean } = {}): Promise<TlsInfo> {
    const h = this.hosts[host];
    if (!h) throw Object.assign(new Error(`connect ECONNREFUSED ${host}:${opts.port ?? 443}`), { code: 'ECONNREFUSED' });
    return {
      host,
      port: opts.port ?? 443,
      checkedAt: '2026-11-20T12:00:00.000Z',
      protocol: 'TLSv1.3',
      authorized: true,
      authorizationError: null,
      validFrom: null,
      validTo: null,
      issuer: null,
      subject: host,
      altNames: [host],
      ...h,
      legacy: opts.legacyProtocols === false ? { 'TLSv1': null, 'TLSv1.1': null } : { 'TLSv1': false, 'TLSv1.1': false, ...h.legacy },
    };
  }
}
