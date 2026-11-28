// EDEL.TRAUD.AI Ampel. All result data is untrusted: it is only ever written with
// textContent / createElement, never as markup.
import { solve } from './pow.js';

const root = document.documentElement;
const $ = (id) => document.getElementById(id);

const T = {
  de: {
    working: 'Edeltraud schaut nach',
    solving: 'Edeltraud schaut nach: kleine Rechenaufgabe gegen automatische Massenanfragen',
    scanning: 'Edeltraud schaut nach: Die App wird passiv angesehen. Das kann bis zu einer Minute dauern',
    empty: 'Bitte eine Adresse eintragen, zum Beispiel example.com.',
    result: 'Ergebnis',
    cached: 'Ergebnis von vor wenigen Minuten.',
    severityNone: 'Keine Befunde in den sichtbaren Prüfungen.',
    fix: 'Behebung',
    evidence: 'Fundstelle',
    notChecked: 'Nicht geprüft',
    light: { red: 'Rot', yellow: 'Gelb', green: 'Grün', unknown: 'Unklar' },
    ctaReport: 'Vollständiger Bericht mit Schritten zur Behebung und fertigen Prompts',
    ctaReportBtn: 'Bericht kaufen · 49 €',
    ctaWatchBtn: 'WatchDog · 19 €/Monat',
    ctaDeepBtn: 'Tiefenprüfung kaufen · 149 €',
    ctaWatchYBtn: 'WatchDog · 190 €/Jahr',
    orderHint: 'Zuerst die Adresse der App prüfen. Danach geht es direkt zur Bestellung.',
    ctaFallbackBtn: 'Bericht anfragen',
    buying: 'Bezahlseite wird vorbereitet …',
    buyError: 'Die Bezahlseite ließ sich gerade nicht öffnen. Bitte später erneut versuchen.',
    ctaHuman: 'Für alles hinter der Anmeldung braucht es einen Menschen.',
    ctaHumanBtn: 'Produktionscheck ansehen',
    target: 'Adresse',
    err: {
      invalid_url: 'Diese Adresse lässt sich nicht prüfen (intern oder ungültig).',
      blocked_target: 'Diese Adresse lässt sich nicht prüfen (intern oder ungültig).',
      pow: 'Die Rechenaufgabe war ungültig oder abgelaufen. Bitte noch einmal auf Prüfen drücken.',
      generic: 'Die Anfrage konnte nicht verarbeitet werden. Bitte noch einmal versuchen.',
      network: 'Keine Verbindung zum Prüfdienst. Bitte die Verbindung kontrollieren und später noch einmal versuchen.',
      server: 'Der Prüfdienst meldet gerade einen Fehler. Bitte später noch einmal versuchen.',
      busy: (w) => `Gerade laufen zu viele Prüfungen. Nächster Versuch in etwa ${w} möglich.`,
      ip: (w) => `Von dieser Verbindung wurden zu viele Prüfungen gestartet. Nächster Versuch in etwa ${w} möglich.`,
      target: (w) => `Diese Adresse wurde gerade erst geprüft. Nächster Versuch in etwa ${w} möglich.`,
      global: (w) => `Gerade sind sehr viele Prüfungen unterwegs. Nächster Versuch in etwa ${w} möglich.`,
    },
    min: (n) => (n === 1 ? '1 Minute' : `${n} Minuten`),
    sec: (n) => (n === 1 ? '1 Sekunde' : `${n} Sekunden`),
  },
  en: {
    working: 'Edeltraud is looking',
    solving: 'Edeltraud is looking: solving a small puzzle against automated mass requests',
    scanning: 'Edeltraud is looking: the app is being viewed passively. This can take up to a minute',
    empty: 'Please enter an address, for example example.com.',
    result: 'Result',
    cached: 'Result from a few minutes ago.',
    severityNone: 'No findings in the visible checks.',
    fix: 'Fix',
    evidence: 'Evidence',
    notChecked: 'Not checked',
    light: { red: 'Red', yellow: 'Yellow', green: 'Green', unknown: 'Unclear' },
    ctaReport: 'Full report with steps to fix and ready-made prompts',
    ctaReportBtn: 'Buy report · €49',
    ctaWatchBtn: 'WatchDog · €19/month',
    ctaDeepBtn: 'Buy deep check · €149',
    ctaWatchYBtn: 'WatchDog · €190/year',
    orderHint: 'First check the address of the app. The order follows right after.',
    ctaFallbackBtn: 'Request report',
    buying: 'Preparing the payment page …',
    buyError: 'The payment page could not be opened right now. Please try again later.',
    ctaHuman: 'Everything behind the login needs a human.',
    ctaHumanBtn: 'See the production check',
    target: 'Address',
    err: {
      invalid_url: 'This address cannot be checked (internal or invalid).',
      blocked_target: 'This address cannot be checked (internal or invalid).',
      pow: 'The puzzle was invalid or expired. Please press Check again.',
      generic: 'The request could not be processed. Please try again.',
      network: 'No connection to the check service. Please check the connection and try again later.',
      server: 'The check service reports an error right now. Please try again later.',
      busy: (w) => `Too many checks are running right now. Next try possible in about ${w}.`,
      ip: (w) => `Too many checks were started from this connection. Next try possible in about ${w}.`,
      target: (w) => `This address was just checked. Next try possible in about ${w}.`,
      global: (w) => `A lot of checks are running right now. Next try possible in about ${w}.`,
    },
    min: (n) => (n === 1 ? '1 minute' : `${n} minutes`),
    sec: (n) => (n === 1 ? '1 second' : `${n} seconds`),
  },
  pt: {
    working: 'A Edeltraud está a verificar',
    solving: 'A Edeltraud está a verificar: pequeno desafio contra pedidos automáticos em massa',
    scanning: 'A Edeltraud está a verificar: a app é observada de forma passiva. Pode demorar até um minuto',
    empty: 'Indique um endereço, por exemplo example.com.',
    result: 'Resultado',
    cached: 'Resultado de há poucos minutos.',
    severityNone: 'Sem resultados nas verificações visíveis.',
    fix: 'Correção',
    evidence: 'Indício',
    notChecked: 'Não verificado',
    light: { red: 'Vermelho', yellow: 'Amarelo', green: 'Verde', unknown: 'Incerto' },
    ctaReport: 'Relatório completo com passos de correção e prompts prontos',
    ctaReportBtn: 'Comprar relatório · 49 €',
    ctaWatchBtn: 'WatchDog · 19 €/mês',
    ctaDeepBtn: 'Comprar verificação aprofundada · 149 €',
    ctaWatchYBtn: 'WatchDog · 190 €/ano',
    orderHint: 'Primeiro verifique o endereço da app. A encomenda segue logo a seguir.',
    ctaFallbackBtn: 'Pedir relatório',
    buying: 'A preparar a página de pagamento …',
    buyError: 'Não foi possível abrir a página de pagamento. Tente novamente mais tarde.',
    ctaHuman: 'Tudo o que está atrás do login precisa de uma pessoa.',
    ctaHumanBtn: 'Ver a verificação de produção',
    target: 'Endereço',
    err: {
      invalid_url: 'Este endereço não pode ser verificado (interno ou inválido).',
      blocked_target: 'Este endereço não pode ser verificado (interno ou inválido).',
      pow: 'O desafio era inválido ou expirou. Prima Verificar novamente.',
      generic: 'Não foi possível processar o pedido. Tente novamente.',
      network: 'Sem ligação ao serviço de verificação. Verifique a ligação e tente mais tarde.',
      server: 'O serviço de verificação indica um erro neste momento. Tente mais tarde.',
      busy: (w) => `Há demasiadas verificações em curso. Nova tentativa possível dentro de cerca de ${w}.`,
      ip: (w) => `Foram iniciadas demasiadas verificações desta ligação. Nova tentativa possível dentro de cerca de ${w}.`,
      target: (w) => `Este endereço acabou de ser verificado. Nova tentativa possível dentro de cerca de ${w}.`,
      global: (w) => `Há muitas verificações em curso. Nova tentativa possível dentro de cerca de ${w}.`,
    },
    min: (n) => (n === 1 ? '1 minuto' : `${n} minutos`),
    sec: (n) => (n === 1 ? '1 segundo' : `${n} segundos`),
  },
};

const form = $('scan-form');
const input = $('url');
const button = $('go');
const statusBox = $('status');
const statusText = $('status-text');
const statusBar = $('status-bar');
const errorBox = $('error');
const resultBox = $('result');
const resultBody = $('result-body');

/** Product chosen on m-ko.de/check/ (?order=…): offered first after the free check. */
const ORDER = (() => {
  const o = new URLSearchParams(window.location.search).get('order');
  return ['report', 'deep', 'watchdog', 'watchdog-y'].includes(o) ? o : null;
})();

function lang() {
  const l = root.getAttribute('data-lang');
  return T[l] ? l : 'en';
}
function t() { return T[lang()]; }

/** Language sent to the API: pt-BR only when pt is shown and the browser is Brazilian. */
export function apiLang() {
  const l = lang();
  if (l === 'pt' && /^pt-br$/i.test(navigator.language || '')) return 'pt-BR';
  return l;
}

function el(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.className = className;
  return node;
}

function clear(node) { node.textContent = ''; }

function waitText(seconds) {
  const s = Math.max(1, Math.ceil(Number(seconds) || 60));
  return s < 90 ? t().sec(s) : t().min(Math.ceil(s / 60));
}

function showStatus(text, progress) {
  errorBox.hidden = true;
  statusBox.hidden = false;
  clear(statusText);
  statusText.append(document.createTextNode(text));
  statusText.append(el('span', '', 'status__dots'));
  if (progress === undefined) {
    statusBar.hidden = true;
  } else {
    statusBar.hidden = false;
    statusBar.value = Math.max(0, Math.min(100, Math.round(progress * 100)));
  }
}

function showError(text) {
  statusBox.hidden = true;
  errorBox.hidden = false;
  errorBox.textContent = text;
}

class ApiError extends Error {
  constructor(message) { super(message); this.name = 'ApiError'; }
}

async function readJson(res) {
  try { return await res.json(); } catch { return {}; }
}

async function getChallenge() {
  let res;
  try { res = await fetch('/v1/challenge', { headers: { accept: 'application/json' }, cache: 'no-store' }); }
  catch { throw new ApiError(t().err.network); }
  if (res.status === 404) return null; // server does not require proof of work
  if (!res.ok) throw await errorFrom(res);
  const c = await readJson(res);
  if (!c || typeof c.salt !== 'string' || !Number.isFinite(c.difficulty)) throw new ApiError(t().err.generic);
  return c;
}

async function errorFrom(res) {
  const body = await readJson(res);
  const e = t().err;
  if (res.status === 429) {
    const scope = ['ip', 'target', 'global'].includes(body.scope) ? body.scope : 'global';
    return new ApiError(e[scope](waitText(body.retryAfter ?? res.headers.get('Retry-After'))));
  }
  if (res.status === 503) return new ApiError(e.busy(waitText(body.retryAfter ?? res.headers.get('Retry-After'))));
  if (res.status === 400) {
    if (body.error === 'blocked_target' || body.error === 'invalid_url') return new ApiError(e.blocked_target);
    if (typeof body.error === 'string' && body.error.startsWith('pow_')) return new ApiError(e.pow);
    return new ApiError(e.generic);
  }
  return new ApiError(res.status >= 500 ? e.server : e.generic);
}

function solveInWorker(challenge, onProgress) {
  const expected = Math.pow(2, challenge.difficulty);
  return new Promise((resolve, reject) => {
    let worker;
    try { worker = new Worker('assets/pow-worker.js', { type: 'module' }); }
    catch (err) { reject(err); return; }
    worker.onmessage = (ev) => {
      const d = ev.data || {};
      if (typeof d.nonce === 'number') { worker.terminate(); resolve(d.nonce); }
      else if (typeof d.progress === 'number') onProgress(Math.min(0.99, d.progress / expected));
      else if (d.error) { worker.terminate(); reject(new Error(d.error)); }
    };
    worker.onerror = (ev) => { worker.terminate(); reject(new Error(ev.message || 'worker')); };
    worker.postMessage({ salt: challenge.salt, difficulty: challenge.difficulty });
  });
}

async function solveChallenge(challenge, onProgress) {
  try {
    return await solveInWorker(challenge, onProgress);
  } catch {
    // No module-worker support: same algorithm on the main thread.
    const expected = Math.pow(2, challenge.difficulty);
    return solve(challenge.salt, challenge.difficulty, { onProgress: (n) => onProgress(Math.min(0.99, n / expected)) });
  }
}

async function postScan(url, challenge, nonce) {
  const body = { url, lang: apiLang() };
  if (challenge) body.pow = { salt: challenge.salt, nonce, expires: challenge.expires, signature: challenge.signature };
  let res;
  try {
    res = await fetch('/v1/scan', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
    });
  } catch { throw new ApiError(t().err.network); }
  if (!res.ok) throw await errorFrom(res);
  const data = await readJson(res);
  if (!data || typeof data !== 'object' || !data.light) throw new ApiError(t().err.generic);
  return data;
}

// ---------- buying ----------

/** Starts a Paddle checkout for the checked address. Without payment on the server: link to m-ko.de. */
function buyButton(text, target, product, className) {
  const b = el('button', text, className);
  b.type = 'button';
  b.addEventListener('click', () => buy(b, str(target), product));
  return b;
}

async function buy(button, url, product) {
  button.disabled = true;
  showStatus(t().buying);
  try {
    const challenge = await getChallenge();
    let nonce;
    if (challenge) nonce = await solveChallenge(challenge, () => {});
    const body = { url, product, lang: apiLang() };
    if (challenge) body.pow = { salt: challenge.salt, nonce, expires: challenge.expires, signature: challenge.signature };
    const res = await fetch('/v1/checkout', {
      method: 'POST',
      headers: { 'content-type': 'application/json', accept: 'application/json' },
      body: JSON.stringify(body),
    });
    if (res.status === 404) {
      window.location.href = 'https://m-ko.de/check/#report';
      return;
    }
    if (!res.ok) throw await errorFrom(res);
    const data = await readJson(res);
    const next = data && typeof data.checkoutUrl === 'string' ? data.checkoutUrl : '';
    // Only our own payment page: never follow a URL to somewhere else.
    if (!next.startsWith(window.location.origin + '/pay?')) throw new ApiError(t().buyError);
    window.location.href = next;
  } catch (e) {
    showError(e instanceof ApiError ? e.message : t().buyError);
    button.disabled = false;
  }
}

// ---------- rendering (textContent only) ----------

function str(v) { return typeof v === 'string' ? v : ''; }

function renderFinding(f) {
  const sev = ['critical', 'high', 'medium', 'low', 'info'].includes(f.severity) ? f.severity : 'info';
  const li = el('li', null, `finding finding--${sev}`);
  li.append(el('span', str(f.severityLabel) || sev, 'finding__sev'));
  li.append(el('h3', str(f.title)));
  if (str(f.explain)) li.append(el('p', f.explain));
  if (str(f.evidence)) {
    const ev = el('p', null, 'finding__evidence');
    ev.append(el('span', t().evidence + ': ', 'visually-hidden'));
    ev.append(el('code', f.evidence));
    li.append(ev);
  }
  if (str(f.fix)) {
    const fix = el('p', null, 'finding__fix');
    fix.append(el('strong', t().fix));
    fix.append(document.createTextNode(f.fix));
    li.append(fix);
  }
  return li;
}

function ctaLink(text, href, className) {
  const a = el('a', text, className);
  a.href = href;
  return a;
}

export function renderResult(p) {
  const tx = t();
  const light = ['red', 'yellow', 'green', 'unknown'].includes(p.light) ? p.light : 'unknown';
  clear(resultBody);
  resultBox.setAttribute('aria-label', tx.result);

  const verdict = el('div', null, 'verdict');
  const lamp = el('div', null, `light light--${light}`);
  lamp.setAttribute('aria-hidden', 'true');
  for (let i = 0; i < 3; i++) lamp.append(el('span', '', 'light__lamp'));
  const head = el('div');
  head.append(el('span', tx.light[light], 'verdict__label'));
  const h2 = el('h2', str(p.headline) || tx.light[light]);
  h2.id = 'result-heading';
  h2.tabIndex = -1;
  head.append(h2);
  verdict.append(lamp, head);
  resultBody.append(verdict);

  if (str(p.target)) resultBody.append(el('p', `${tx.target}: ${p.target}`, 'verdict__target'));
  if (p.cached) resultBody.append(el('p', tx.cached, 'note-cached'));

  const findings = Array.isArray(p.findings) ? p.findings.slice(0, 3) : [];
  if (findings.length) {
    const ul = el('ul', null, 'findings');
    for (const f of findings) ul.append(renderFinding(f || {}));
    resultBody.append(ul);
  }
  if (str(p.lockedText)) resultBody.append(el('p', p.lockedText, 'locked'));

  const nc = Array.isArray(p.notChecked) ? p.notChecked : [];
  if (nc.length) {
    const d = el('details', null, 'notchecked');
    d.append(el('summary', `${tx.notChecked} (${nc.length})`));
    const ul = el('ul');
    for (const n of nc) ul.append(el('li', `${str(n && n.module)}: ${str(n && n.reason)}`));
    d.append(ul);
    resultBody.append(d);
  }

  if (str(p.always)) resultBody.append(el('p', p.always, 'always'));
  if (str(p.disclaimer)) resultBody.append(el('p', p.disclaimer, 'disclaimer'));

  const ctas = el('div', null, 'ctas');
  const c1 = el('div', null, 'cta');
  const label = { report: tx.ctaReportBtn, deep: tx.ctaDeepBtn, watchdog: tx.ctaWatchBtn, 'watchdog-y': tx.ctaWatchYBtn };
  const offer = ORDER && ORDER !== 'report' && ORDER !== 'watchdog' ? ['report', ORDER, 'watchdog'] : ['report', 'watchdog'];
  if (ORDER) offer.sort((a, b) => (b === ORDER) - (a === ORDER));
  c1.append(el('p', tx.ctaReport), ...offer.map((k, i) => buyButton(label[k], p.target, k, i === 0 ? 'btn' : 'btn btn--ghost')));
  const c2 = el('div', null, 'cta');
  c2.append(el('p', tx.ctaHuman), ctaLink(tx.ctaHumanBtn, 'https://m-ko.de/check/', 'btn btn--ghost'));
  ctas.append(c1, c2);
  resultBody.append(ctas);

  resultBox.hidden = false;
  h2.focus({ preventScroll: true });
  resultBox.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
}

// ---------- flow ----------

let running = false;

async function run(url) {
  running = true;
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  resultBox.hidden = true;
  try {
    showStatus(t().working);
    const challenge = await getChallenge();
    let nonce = 0;
    if (challenge) {
      showStatus(t().solving, 0);
      nonce = await solveChallenge(challenge, (f) => { statusBar.value = Math.round(f * 100); });
    }
    showStatus(t().scanning);
    const presented = await postScan(url, challenge, nonce);
    statusBox.hidden = true;
    renderResult(presented);
  } catch (err) {
    showError(err instanceof ApiError ? err.message : t().err.generic);
  } finally {
    running = false;
    button.disabled = false;
    button.removeAttribute('aria-busy');
  }
}

form.addEventListener('submit', (ev) => {
  ev.preventDefault();
  if (running) return;
  const url = input.value.trim();
  if (!url) { showError(t().empty); input.focus(); return; }
  run(url);
});

if (ORDER) {
  // One span per language, switched by the page's lang CSS like the static text.
  const hint = el('p', null, 'consent order-hint');
  for (const l of ['de', 'en', 'pt']) {
    const s = el('span', T[l].orderHint);
    s.setAttribute('lang', l);
    hint.append(s);
  }
  form.after(hint);
}
