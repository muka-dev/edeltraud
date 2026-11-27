import type { CheckModule } from '../../core/types.ts';

/** Inspects the TLS handshake of the target host: certificate validity, protocol, legacy protocol support. */
export const collectTls: CheckModule<{ legacyProtocols: boolean }> = {
  manifest: {
    id: 'collect.tls',
    version: '0.1.0',
    kind: 'collector',
    mode: 'passive',
    category: 'security',
    requires: [],
    provides: ['artifact:tls'],
    params: { legacyProtocols: { type: 'boolean', default: true } },
    budget: { ms: 20_000 },
  },
  async run(ctx, params) {
    const id = collectTls.manifest.id;
    if (!ctx.target.url.startsWith('https://')) return { notChecked: [{ module: id, reason: 'condition' }] };
    if (!ctx.tls) return { notChecked: [{ module: id, reason: 'unsupported' }] };
    try {
      const u = new URL(ctx.target.url);
      const port = u.port ? Number(u.port) : 443;
      const data = await ctx.tls.inspect(ctx.target.host, { port, legacyProtocols: params.legacyProtocols });
      return { artifacts: [{ type: 'tls', key: ctx.target.host, data }] };
    } catch (e) {
      const msg = e instanceof Error ? `${(e as NodeJS.ErrnoException).code ?? ''} ${e.message}`.trim() : String(e);
      return { notChecked: [{ module: id, reason: 'error', detail: msg.slice(0, 200) }] };
    }
  },
};
