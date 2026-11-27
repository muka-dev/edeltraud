// Renders web/og.png (1200x627, the size LinkedIn and others use for link previews).
//   node scripts/og/render.cjs      (needs Playwright with Chromium)
const path = require('node:path');
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const page = await browser.newPage({ viewport: { width: 1200, height: 627 }, deviceScaleFactor: 1 });
  await page.goto('file://' + path.join(__dirname, 'og.html'));
  await page.evaluate(() => document.fonts.ready);
  await page.screenshot({ path: path.join(__dirname, '../../web/og.png'), type: 'png' });
  await browser.close();
  console.log('written web/og.png');
})();
