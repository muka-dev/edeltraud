import type { Browser, RenderData } from '../core/types.ts';

/** Fixture browser: URL → what the page loaded. Unknown URLs fail like an unreachable site. */
export class ReplayBrowser implements Browser {
  private pages: Record<string, Partial<RenderData>>;
  constructor(pages: Record<string, Partial<RenderData>>) {
    this.pages = pages;
  }
  async render(url: string): Promise<RenderData> {
    const p = this.pages[url];
    if (!p) throw new Error(`net::ERR_CONNECTION_REFUSED at ${url}`);
    return {
      url,
      finalUrl: url,
      status: 200,
      html: '',
      title: '',
      requests: [],
      cookies: [],
      storage: { local: [], session: [] },
      console: [],
      pageErrors: [],
      links: [],
      blocked: [],
      limitReached: false,
      ...p,
    };
  }
}
