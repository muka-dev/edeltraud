// Language pick (saved choice, else browser language) and switcher. No inline script, no cookies.
(function () {
  var supported = ['de', 'en', 'pt'];
  var root = document.documentElement;
  function apply(lang) {
    root.setAttribute('data-lang', lang);
    root.setAttribute('lang', lang);
    var t = root.getAttribute('data-title-' + lang);
    if (t) document.title = t;
    var buttons = document.querySelectorAll('[data-set-lang]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].setAttribute('aria-pressed', buttons[i].getAttribute('data-set-lang') === lang ? 'true' : 'false');
    }
  }
  var lang = null;
  try { lang = localStorage.getItem('lang'); } catch (e) {}
  if (supported.indexOf(lang) === -1) {
    lang = (navigator.language || 'en').slice(0, 2).toLowerCase();
    if (supported.indexOf(lang) === -1) lang = 'en';
  }
  root.classList.add('js');
  apply(lang);
  document.addEventListener('DOMContentLoaded', function () {
    apply(root.getAttribute('data-lang'));
    var buttons = document.querySelectorAll('[data-set-lang]');
    for (var i = 0; i < buttons.length; i++) {
      buttons[i].addEventListener('click', function (ev) {
        var l = ev.currentTarget.getAttribute('data-set-lang');
        try { localStorage.setItem('lang', l); } catch (e) {}
        apply(l);
        document.dispatchEvent(new CustomEvent('langchange', { detail: l }));
      });
    }
  });
})();
