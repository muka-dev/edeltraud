import { loadPlaywright } from '../fetch/browser.ts';

/**
 * Prints a self-contained HTML document to PDF with headless Chromium.
 * The page gets no network at all: every request is aborted, so a report can never
 * load something from the scanned site while it is printed.
 */
export async function htmlToPdf(html: string, opts: { executablePath?: string } = {}): Promise<Buffer> {
  const { chromium } = loadPlaywright();
  const executablePath = opts.executablePath ?? process.env.EDELTRAUD_CHROMIUM;
  const browser = await chromium.launch({
    ...(executablePath ? { executablePath } : {}),
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  try {
    const context = await browser.newContext({ javaScriptEnabled: false, offline: true });
    const page = await context.newPage();
    await page.route('**/*', (route: any) => route.abort('blockedbyclient'));
    await page.setContent(html, { waitUntil: 'load', timeout: 30_000 });
    await page.emulateMedia({ media: 'print' });
    const pdf: Uint8Array = await page.pdf({
      format: 'A4',
      printBackground: true,
      preferCSSPageSize: true,
      margin: { top: '16mm', bottom: '16mm', left: '16mm', right: '16mm' },
    });
    return Buffer.from(pdf);
  } finally {
    await browser.close().catch(() => {});
  }
}
