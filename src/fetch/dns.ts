import { Resolver } from 'node:dns/promises';
import type { Dns, DnsRecordType } from '../core/types.ts';

const EMPTY = new Set(['ENODATA', 'ENOTFOUND', 'NXDOMAIN', 'ENONAME']);

/** Real DNS through the system resolver, with a short timeout. Names only, no connection to the target. */
export class LiveDns implements Dns {
  private r: Resolver;
  constructor(opts: { timeoutMs?: number; tries?: number } = {}) {
    this.r = new Resolver({ timeout: opts.timeoutMs ?? 3000, tries: opts.tries ?? 2 });
  }

  async resolve(name: string, type: DnsRecordType): Promise<string[]> {
    try {
      switch (type) {
        case 'A': return await this.r.resolve4(name);
        case 'AAAA': return await this.r.resolve6(name);
        case 'CNAME': return await this.r.resolveCname(name);
        case 'MX': return (await this.r.resolveMx(name)).map((m) => `${m.priority} ${m.exchange || '.'}`);
        case 'TXT': return (await this.r.resolveTxt(name)).map((chunks) => chunks.join(''));
        case 'CAA':
          return (await this.r.resolveCaa(name)).map((c) => {
            const tag = Object.keys(c).find((k) => k !== 'critical') ?? 'unknown';
            return `${c.critical} ${tag} "${String((c as unknown as Record<string, unknown>)[tag] ?? '')}"`;
          });
      }
    } catch (e) {
      if (EMPTY.has((e as NodeJS.ErrnoException).code ?? '')) return [];
      throw e;
    }
  }
}

/** Fixture DNS: 'name TYPE' → answers. Missing entries answer with no data. A value of 'SERVFAIL' throws. */
export class ReplayDns implements Dns {
  readonly log: string[] = [];
  private zone: Record<string, string[] | 'SERVFAIL'>;
  constructor(zone: Record<string, string[] | 'SERVFAIL'>) {
    this.zone = zone;
  }
  async resolve(name: string, type: DnsRecordType): Promise<string[]> {
    const key = `${name.toLowerCase().replace(/\.$/, '')} ${type}`;
    this.log.push(key);
    const v = this.zone[key];
    if (v === 'SERVFAIL') throw Object.assign(new Error(`queryServfail ${key}`), { code: 'ESERVFAIL' });
    return v ?? [];
  }
}
