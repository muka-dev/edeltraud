import { test } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { htmlToPdf } from '../src/report/pdf.ts';

test('htmlToPdf: A4 PDF, no network while printing (skipped without Chromium)', async (t) => {
  let hits = 0;
  const server = http.createServer((_req, res) => {
    hits++;
    res.end('x');
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  const port = (server.address() as { port: number }).port;
  try {
    const html = `<!doctype html><html lang="de"><head><meta charset="utf-8">
<link rel="stylesheet" href="http://127.0.0.1:${port}/x.css"></head>
<body><h1>Bericht</h1><img src="http://127.0.0.1:${port}/pixel.png"><script>fetch('http://127.0.0.1:${port}/js')</script></body></html>`;
    let pdf: Buffer;
    try {
      pdf = await htmlToPdf(html);
    } catch (e) {
      if (/Playwright is not installed|Executable doesn't exist|launch/i.test(String(e))) return t.skip(String(e).slice(0, 80));
      throw e;
    }
    assert.equal(pdf.subarray(0, 5).toString(), '%PDF-');
    assert.ok(pdf.length > 1000);
    assert.equal(hits, 0, 'printing must not load anything');
  } finally {
    server.close();
  }
});
