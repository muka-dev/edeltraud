// Module worker: new Worker('assets/pow-worker.js', { type: 'module' })
import { solve } from './pow.js';

self.onmessage = async (event) => {
  const { salt, difficulty } = event.data || {};
  try {
    const nonce = await solve(String(salt), Number(difficulty), {
      batch: 2000,
      onProgress: (tries) => self.postMessage({ progress: tries }),
    });
    self.postMessage({ nonce });
  } catch (err) {
    self.postMessage({ error: String((err && err.message) || err) });
  }
};
