// Opens the Paddle checkout for the transaction in ?_ptxn=… (default payment link page).
// Paddle.js opens the checkout by itself once initialised; this file only passes the public settings.
(async function () {
  const status = document.getElementById('pay-status');
  const fail = (msg) => { if (status) status.textContent = msg; };
  const lang = document.documentElement.getAttribute('lang') || 'de';
  const msg = {
    de: 'Das Bezahlfenster ließ sich nicht öffnen. Bitte später erneut versuchen oder an post@m-ko.de schreiben.',
    en: 'The checkout could not be opened. Please try again later or write to post@m-ko.de.',
    pt: 'Não foi possível abrir o pagamento. Tente mais tarde ou escreva para post@m-ko.de.',
  }[lang] || '';
  try {
    if (!/^txn_[a-z0-9]+$/.test(new URLSearchParams(location.search).get('_ptxn') || '')) return fail(msg);
    const res = await fetch('/v1/pay/config', { headers: { accept: 'application/json' }, cache: 'no-store' });
    const cfg = res.ok ? await res.json() : null;
    if (!cfg || typeof cfg.clientToken !== 'string' || !window.Paddle) return fail(msg);
    if (cfg.environment === 'sandbox') window.Paddle.Environment.set('sandbox');
    window.Paddle.Initialize({
      token: cfg.clientToken,
      checkout: { settings: { displayMode: 'overlay', locale: lang === 'pt' ? 'pt' : lang, successUrl: location.origin + '/danke.html' } },
    });
  } catch {
    fail(msg);
  }
})();
