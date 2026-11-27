# EDEL.TRAUD.AI

*Trau, schau, wem.* Edeltraud findet typische Fehler in Apps, die mit
Lovable, Cursor, Claude Code, Bolt, v0 und ähnlichen Werkzeugen gebaut
wurden. Eigenständige Komponente (CLI, Bibliothek, HTTP-API), die unter
`scan.m-ko.de` eingebunden wird.

Ein Ergebnis ohne Befunde heißt nur: Diese Prüfungen haben nichts gefunden.
Es ist kein Zertifikat und keine Garantie.

## Schnellstart

Voraussetzung: Node.js ≥ 22.18 (führt TypeScript direkt aus, kein Build-Schritt).

```bash
npm install
npm run check          # Typprüfung + Tests
npm run demo           # Ampel auf der eingebauten Test-App, ohne Netz
npm run demo report en # vollständiger Bericht auf Englisch
npm run scan -- https://example.com --plan ampel --lang de
npm run api            # HTTP-API auf :8787
npm run export:core -- ../edeltraud   # offenen Kern (AGPL) ohne private Teile exportieren
```

CLI-Exit-Codes: 0 grün/gelb, 1 rot, 2 Bedienfehler, 3 unvollständig (Ampel grau).

API (liefert unter `scan.m-ko.de` auch die Ampel-Seite aus `web/`):

```
GET  /v1/challenge                                        → Rechenaufgabe (Proof of Work)
POST /v1/scan   { "url": "example.com", "lang": "de", "pow": {…} }  → Ampel-Ergebnis (de, en, pt, pt-BR)
GET  /health
GET  /                                                    → Ampel-Seite
```

Schutz vor Missbrauch der kostenlosen Ampel:

- **Proof of Work:** Vor jedem Scan löst der Browser eine kleine Rechenaufgabe
  (Stufe 16 ≈ 65.000 Hashes, unter 2 s). Jede Aufgabe gilt für genau einen
  Scan. Kein Dienst eines Dritten, kein Cookie, kein Tracking.
- **Grenzen pro Client:** 3/Minute, 10/Stunde, 30/Tag; IPv6 zählt pro /64.
- **Grenze pro Ziel:** 20/Stunde je registrierbarer Domain (Subdomains zählen
  zusammen). Ergebnisse aus dem Cache (10 Minuten) zählen nicht.
- **Gesamt:** 300 Scans/Stunde, höchstens 4 gleichzeitig (sonst 503 mit
  `Retry-After`; dabei wird kein Kontingent verbraucht).
- **Opt-out:** Domains, deren Betreiber keine Scans wollen, in `BLOCKED_DOMAINS`.
- Die Zähler liegen im Speicher eines Prozesses. Bei mehreren Instanzen
  gehören sie in einen gemeinsamen Speicher (z. B. Redis).

Umgebungsvariablen der API: `PORT`, `ALLOWED_ORIGINS` (kommagetrennt),
`TRUST_PROXY=1` hinter eigenem Reverse Proxy (sonst zählt die Proxy-IP),
`POW_SECRET` (fester Schlüssel, damit Aufgaben einen Neustart überstehen),
`POW_DIFFICULTY` (Standard 16), `BLOCKED_DOMAINS` (kommagetrennt).

## Aufbau

```
src/core/      Prüfprozessor, Pläne, Abhängigkeitsgraph, Ampel-Regel, Typen
src/modules/   collect/ (Netz), analyze/ (reine Funktionen), probe/ (aktiv, ab Welle 3)
src/fetch/     HTTP mit SSRF-Schutz und Budget, Replay für Tests
src/i18n/      Texte de/en/pt/pt-BR; prompts/ = Fix-Prompts (privat, nicht im offenen Kern)
src/report/    Darstellung (Ampel, Sperren, Text)
src/cli/       Kommandozeile
src/api/       HTTP-API mit Rate-Limit und Cache
plans/         ampel, report, deep, watch (YAML)
test/          node:test, Fixtures ohne echte Schlüssel
```

Ein neues Prüfmodul: Datei unter `src/modules/…`, Eintrag in
`src/modules/index.ts`, Texte in allen drei Katalogen, Fixture-Test.
Die Tests prüfen, dass jeder `messageKey` in allen Sprachen existiert und
die Formulierungsregeln eingehalten sind.

## Lizenz

AGPL-3.0-only. Die fertigen Fix-Prompts, der gestaltete Bericht, Bezahlung und Wache sind
nicht Teil des offenen Kerns. Ohne die Prompt-Kataloge zeigt der Bericht die Schritte zur Behebung ohne Prompt.
Der gehostete Dienst mit allen Teilen entsteht unter https://scan.m-ko.de.
