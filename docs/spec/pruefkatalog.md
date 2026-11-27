# Prüfkatalog

Stand: 20.11.2026 · Status: Entwurf

Spalten: **A** = Ampel (kostenlos), **B** = Bericht, **T** = Tiefenprüfung
(Nachweis der Inhaberschaft), **W** = WatchDog. **Modus** passiv/aktiv,
**Art** Sammler (C), Analyse (A), Probe (P). **Welle** = geplante Reihenfolge
der Entwicklung (1 = erste Version).

**Umgesetzt im Gerüst (Welle 1):** `collect.page`, `collect.bundles`,
`collect.sourcemaps`, `stack.detect`, `secrets.frontend`, `headers.security`,
`cookies.flags`, `tls.basics`, `sourcemaps.exposed`, `supabase.config`,
`firebase.config`, `ai.client-llm-call`. `secrets.frontend` erkennt
zusätzlich OpenRouter, Groq, xAI, Replicate, Hugging Face, SendGrid, Resend,
Slack, neue Supabase-Secret-Keys und Gemini-Schlüssel (Google-Key in der
Nähe eines Gemini-Aufrufs).

**Umgesetzt in Welle 2, Teil "Rest" (20.11.2026):** `collect.tls`
(Ablaufdatum relativ zur Laufzeit, TLS 1.0/1.1; in der Ampel ohne alte
Protokolle), `collect.dns` + `dns.mail`, `collect.errorpages` +
`errors.verbose`, `build.dev-mode`, `deps.vulnerable` (eigene kleine
Datenbank in `src/modules/analyze/deps-db.ts`, Stand 20.11.2026, nicht
vollständig), `headers.csp-quality`. Die Ablaufwarnung steckt in
`tls.basics` (Version 0.2.0).

**Umgesetzt in Welle 2, Teil "Browser" (20.11.2026):** `collect.render`
(Headless-Chromium, keine Klicks), `privacy.third-party` (mit
`privacy.third-country`), `privacy.google-fonts`,
`privacy.consent-before-tracking` (inkl. Google Consent Mode "denied"),
`collect.legal` + `privacy.legal-pages`, `ops.errors-console`,
`mixed.content`, `sri.missing`. Zusätzlich vorgezogen bzw. neu:
`deps.server` (PHP2Shell CVE-2026-109618/109619, PHP end of life),
`next.data-leak`, `ai.system-prompt-exposed`, Next.js-Fixes vom
August 2026 in `deps.vulnerable`. Drittanbieter-Liste:
`src/modules/analyze/thirdparty-db.ts`.

**Umgesetzt in Welle 3, Teil Supabase (20.11.2026):** Nachweis der
Inhaberschaft (`src/ownership/`), `supabase.auth-settings` (passiv),
`supabase.rls-read`, `supabase.rpc-exposed`, `supabase.storage-public`
(aktiv, nur mit Nachweis).

**Umgesetzt in Welle 3/4 (21.11.2026):** `collect.wellknown`,
`wellknown.securitytxt`, `wellknown.robots-hints`, `stack.generator`,
`endpoints.discovered`, `auth.client-only`, `dns.dangling` (passiv);
`api.unauth`, `cors.policy`, `paths.sensitive`, `firebase.rtdb-open`,
`firebase.firestore-open`, `firebase.storage-open` (aktiv, nur mit
Nachweis). Bei allen aktiven Proben gilt: nur GET/HEAD, höchstens ein
Datensatz, im Ergebnis nur Namen und Anzahlen, nie Werte.

Alle Befunde sind Auffälligkeiten, keine Aussage über die Sicherheit oder
Rechtskonformität der App. Datenschutz- und Barrierefreiheits-Module geben
**Hinweise**, keine rechtliche Bewertung.

## Sammler

| ID | Inhalt | Art | A | B | T | W | Welle |
|---|---|---|---|---|---|---|---|
| `collect.page` | Startseite per HTTP, Header, Cookies, HTML | C | ✓ | ✓ | ✓ | ✓ | 1 |
| `collect.bundles` | Eingebundene JS/CSS, Ampel max. 5, sonst inkl. Lazy-Chunks | C | ✓ | ✓ | ✓ | ✓ | 1 |
| `collect.tls` | Zertifikat, Protokolle, Weiterleitung http→https | C | ✓ | ✓ | ✓ | ✓ | 1 |
| `collect.render` | Seite im Headless-Browser, alle Netzwerkanfragen, Cookies, DOM, Konsole | C | – | ✓ | ✓ | ✓ | 2 |
| `collect.crawl` | Bis zu N interne Seiten (Sitemap, Links, Routen aus dem Bundle) | C | – | ✓ | ✓ | ✓ | 2 |
| `collect.dns` | A/AAAA, CNAME, MX, SPF, DMARC, CAA; erkennt Plattform-Domains (vercel.app, lovable.app …) | C | – | ✓ | ✓ | ✓ | 2 |
| `collect.errorpages` | Zwei feste, nicht vorhandene Pfade (`/edeltraud-check-404`, `/api/edeltraud-check-404`) per GET | C | – | ✓ | ✓ | ✓ | 2 |
| `collect.wellknown` | robots.txt, sitemap.xml, security.txt, manifest | C | – | ✓ | ✓ | ✓ | 2 |
| `collect.sourcemaps` | Inhalte ausgelieferter `*.map` | C | – | ✓ | ✓ | ✓ | 2 |

## Stack-Erkennung

| ID | Inhalt | Art | A | B | T | W | Welle |
|---|---|---|---|---|---|---|---|
| `stack.detect` | Supabase, Firebase, Next.js, Vite, React, Lovable, Bolt, v0, Vercel, Netlify, Clerk, Stripe, OpenAI/Anthropic-SDK; setzt Fakten für `when` | A | ✓ | ✓ | ✓ | ✓ | 1 |

## Sicherheit, passiv

| ID | Inhalt | Schwere typ. | A | B | T | W | Welle |
|---|---|---|---|---|---|---|---|
| `secrets.frontend` | Geheime Schlüssel in Bundles/HTML (OpenAI, Anthropic, Stripe `sk_live_`, Supabase `service_role`, AWS, Google, GitHub, private Schlüssel). `anon`-Key und Firebase-Config nur als Info | kritisch | ✓ | ✓ | ✓ | ✓ | 1 |
| `secrets.sourcemaps` | Dasselbe in Source-Map-Inhalten und `.env`-Resten | kritisch | – | ✓ | ✓ | ✓ | 2 |
| `sourcemaps.exposed` | Source Maps öffentlich abrufbar | mittel | ✓ | ✓ | ✓ | ✓ | 1 |
| `headers.security` | CSP, HSTS, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Frame-Schutz | niedrig–mittel | ✓ | ✓ | ✓ | ✓ | 1 |
| `headers.csp-quality` | CSP-Qualität: `unsafe-inline`, `*`, fehlende `object-src`, Report-Only | niedrig–mittel | – | ✓ | ✓ | ✓ | 2 |
| `cookies.flags` | Secure, HttpOnly, SameSite, Lebensdauer von Sitzungs-Cookies | mittel | – | ✓ | ✓ | ✓ | 2 |
| `tls.basics` | Zertifikat gültig, Ablauf bald, http→https, HSTS-Preload | mittel | ✓ | ✓ | ✓ | ✓ | 1 |
| `deps.vulnerable` | Bibliotheken mit bekannten Lücken, soweit Version erkennbar | hoch–mittel | – | ✓ | ✓ | ✓ | 2 |
| `deps.server` | Server-Software aus Headern: PHP2Shell (CVE-2026-109618/109619), PHP end of life; nur "möglich", weil Distributionen Fixes zurückportieren | hoch | ✓ | ✓ | ✓ | ✓ | 2 |
| `build.dev-mode` | Entwicklungs-Build in Produktion, Debug-Ausgaben, Vite-Dev-Server, React-DevTools-Hinweise | mittel | – | ✓ | ✓ | ✓ | 2 |
| `next.data-leak` | Schlüssel, Verbindungs-URLs, E-Mail-Listen, Passwort-Hashes, interne Hosts in `__NEXT_DATA__` und RSC-Flight-Daten | kritisch–niedrig | ✓ | ✓ | ✓ | ✓ | 2 |
| `errors.verbose` | Stacktraces, Framework-Fehlerseiten, SQL-Fehler auf 404/500 | mittel | – | ✓ | ✓ | ✓ | 2 |
| `sri.missing` | Fremde Skripte ohne Subresource Integrity | niedrig | – | ✓ | ✓ | ✓ | 2 |
| `mixed.content` | http-Ressourcen auf https-Seiten | mittel | – | ✓ | ✓ | ✓ | 2 |
| `dns.mail` | SPF, DMARC fehlen oder zu lax (wichtig, wenn die App Mails versendet) | mittel | – | ✓ | ✓ | ✓ | 2 |
| `dns.dangling` | CNAME auf nicht mehr existierende Dienste (Übernahme-Gefahr) | hoch | – | ✓ | ✓ | ✓ | 3 |
| `wellknown.securitytxt` | security.txt fehlt | info | – | ✓ | ✓ | ✓ | 2 |
| `endpoints.discovered` | API-Endpunkte aus Bundles und Anfragen, Grundlage für Proben | – (Fakt) | – | ✓ | ✓ | ✓ | 2 |

## KI-spezifisch

| ID | Inhalt | Schwere typ. | A | B | T | W | Welle |
|---|---|---|---|---|---|---|---|
| `ai.client-llm-call` | Browser ruft LLM-API direkt auf (Kosten-Missbrauch, Schlüssel) | kritisch–hoch | ✓ | ✓ | ✓ | ✓ | 1 |
| `ai.system-prompt-exposed` | System-Prompts und Geschäftslogik im Bundle | niedrig–mittel | – | ✓ | ✓ | ✓ | 2 |
| `ai.edge-function-open` | Supabase Edge Functions / API-Routen mit LLM-Aufruf ohne Anmeldung erreichbar | hoch | – | – | ✓ | ✓ | 4 |
| `ai.cost-guard` | Rate-Limit an LLM-Endpunkten (sehr wenige Anfragen) | hoch | – | – | ✓ | – | 4 |
| `ai.prompt-injection-surface` | Freitext wird ungefiltert an LLM gereicht, Ausgabe als HTML gerendert | mittel | – | – | ✓ | – | 5 |

## Supabase und Firebase

| ID | Inhalt | Modus | Schwere typ. | A | B | T | W | Welle |
|---|---|---|---|---|---|---|---|---|
| `supabase.config` | Projekt-URL und `anon`-Key gefunden, Hinweis auf Tiefenprüfung | passiv | info | ✓ | ✓ | ✓ | ✓ | 1 |
| `supabase.auth-settings` | Öffentliche Auth-Einstellungen: Registrierung offen, E-Mail-Bestätigung aus, Anbieter | passiv | mittel | – | ✓ | ✓ | ✓ | 2 |
| `supabase.rls-read` | Tabellen aus dem OpenAPI-Schema mit `anon`-Key lesen, max. 1 Zeile | aktiv | kritisch | – | – | ✓ | ✓ | 3 |
| `supabase.rpc-exposed` | Öffentlich aufrufbare RPC-Funktionen (nur auflisten, nicht ausführen) | aktiv | hoch | – | – | ✓ | ✓ | 3 |
| `supabase.storage-public` | Öffentliche Buckets, Auflistung möglich | aktiv | hoch | – | – | ✓ | ✓ | 3 |
| `firebase.config` | Firebase-Web-Config gefunden, Hinweis | passiv | info | ✓ | ✓ | ✓ | ✓ | 1 |
| `firebase.rtdb-open` | Realtime Database `/.json` lesbar | aktiv | kritisch | – | – | ✓ | ✓ | 3 |
| `firebase.firestore-open` | Collections ohne Anmeldung lesbar (Namen aus dem Bundle) | aktiv | kritisch | – | – | ✓ | ✓ | 3 |
| `firebase.storage-open` | Storage-Bucket auflistbar | aktiv | hoch | – | – | ✓ | ✓ | 3 |

## Aktive Prüfungen allgemein

| ID | Inhalt | Schwere typ. | A | B | T | W | Welle |
|---|---|---|---|---|---|---|---|
| `paths.sensitive` | `/.env`, `/.git/config`, Backups, `/admin`, Debug-Routen | kritisch–mittel | – | – | ✓ | ✓ | 3 |
| `api.unauth` | Gefundene API-Endpunkte ohne Anmeldung (nur GET) | hoch | – | – | ✓ | ✓ | 3 |
| `cors.policy` | `Access-Control-Allow-Origin` gespiegelt oder `*` mit Credentials | hoch | – | – | ✓ | ✓ | 3 |
| `ratelimit.auth` | Anmeldung und Passwort-Reset: Begrenzung vorhanden (≤ 10 Anfragen) | mittel | – | – | ✓ | – | 4 |
| `auth.enumeration` | Unterschiedliche Antworten für bekannte und unbekannte Konten | niedrig | – | – | ✓ | – | 4 |

## Hinter der Anmeldung (mit zwei Testkonten, Tiefenprüfung Plus)

| ID | Inhalt | Schwere typ. | Welle |
|---|---|---|---|
| `authz.cross-tenant` | Konto A liest oder ändert Daten von Konto B (nur lesen, nur eigene Testdaten) | kritisch | 5 |
| `authz.role-escalation` | Normales Konto erreicht Admin-Funktionen | kritisch | 5 |
| `authz.rls-authenticated` | Supabase-Tabellen mit Token von Konto A, Zeilen von B sichtbar? | kritisch | 5 |
| `session.handling` | Abmelden beendet Sitzung, Token-Lebensdauer, Token in localStorage | mittel | 5 |

## Datenschutz (Hinweise)

| ID | Inhalt | A | B | T | W | Welle |
|---|---|---|---|---|---|---|
| `privacy.third-party` | Liste aller Drittanbieter mit Sitzland (Analyse, Chat, Fonts, CDNs) | ✓ (Anzahl) | ✓ | ✓ | ✓ | 2 |
| `privacy.consent-before-tracking` | Tracker/Cookies vor jeder Einwilligung geladen | – | ✓ | ✓ | ✓ | 2 |
| `privacy.google-fonts` | Schriften direkt von Google geladen | – | ✓ | ✓ | ✓ | 2 |
| `privacy.legal-pages` | Impressum und Datenschutzerklärung verlinkt und erreichbar | ✓ | ✓ | ✓ | ✓ | 2 |
| `privacy.third-country` | Erkannte Dienste mit Firmensitz außerhalb EU/EWR/CH | ✓ | ✓ | ✓ | ✓ | 2 |
| `privacy.forms` | Formulare mit personenbezogenen Feldern, Ziel der Übermittlung | – | ✓ | ✓ | ✓ | 3 |
| `privacy.llm-data-flow` | Eingaben gehen an LLM-Anbieter außerhalb der EU | – | ✓ | ✓ | ✓ | 3 |

## Barrierefreiheit (Hinweise, BFSG-Bezug)

| ID | Inhalt | B | T | W | Welle |
|---|---|---|---|---|---|
| `a11y.axe` | Automatische Prüfung mit axe-core im gerenderten DOM | ✓ | ✓ | ✓ | 3 |
| `a11y.basics` | `lang`, Alternativtexte, Formular-Labels, Kontrast, Fokus sichtbar | ✓ | ✓ | ✓ | 3 |
| `a11y.statement` | Erklärung zur Barrierefreiheit vorhanden | ✓ | ✓ | ✓ | 3 |

## Betrieb und Qualität

| ID | Inhalt | B | T | W | Welle |
|---|---|---|---|---|---|
| `perf.weight` | Seitengewicht, Bundle-Größe, Anzahl Anfragen, Bilder ohne Komprimierung | ✓ | ✓ | ✓ | 3 |
| `perf.vitals` | LCP, CLS, TBT im Labor (Browser) | ✓ | ✓ | ✓ | 3 |
| `ops.errors-console` | Fehler in der Browser-Konsole beim Laden | ✓ | ✓ | ✓ | 2 |
| `ops.404` | Saubere 404-Seite, keine Soft-404 für API-Routen | ✓ | ✓ | ✓ | 3 |
| `seo.basics` | Titel, Beschreibung, OG-Tags, Sitemap, `noindex` auf Produktion | ✓ | ✓ | ✓ | 3 |

## Umfang je Stufe (Ziel nach Welle 3)

| | Ampel | Bericht | Tiefenprüfung | WatchDog |
|---|---|---|---|---|
| Module | ca. 10 | ca. 40 | ca. 55 | wie Bericht, aktiv monatlich |
| Dauer | < 15 s | 1–2 min | 2–5 min | im Hintergrund |
| Anfragen | ≤ 30 | ≤ 400 | ≤ 800 | ≤ 400 |
| Browser | nein | ja | ja | ja |
| Befunde sichtbar | 3 + Anzahl | alle | alle | nur neue/behobene |
| Fix-Prompts | – | ✓ | ✓ | ✓ |

## Später: zweiter Eingang (Repository)

Upload eines Repositorys oder ZIP, statische Analyse im Browser nach dem
Vorbild von `js/scanner-core.js` (m-ko.de). Gleiche Befund-Struktur, eigene
Sammler (`collect.repo`). Findet, was von außen nicht sichtbar ist:
fehlende Rechteprüfung auf dem Server, Secrets in `.env` im Repository,
Webhooks ohne Signaturprüfung, RLS-Richtlinien in Migrationen. Eignet sich
als eigene Stufe oder Teil der Tiefenprüfung.
