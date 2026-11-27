# Architektur: Prüfmodule und Prüfprozessor

Stand: 20.11.2026 · Status: Entwurf, Grundlage für das Gerüst

## 1. Ziele

- Jede Prüfung ist ein **eigenes Modul**, das sich einzeln entwickeln,
  testen, versionieren und verbessern lässt.
- Ein **Prüfprozessor** arbeitet einen **Prüfplan** ab: eine Liste von
  Modulen mit Parametern. Ampel, Bericht, Tiefenprüfung und WatchDog sind nur
  verschiedene Pläne.
- **Kostenlos schnell, bezahlt breit und tief**, mit denselben Bausteinen.
- Der Kern läuft ohne Netz gegen feste Testdaten und ist deterministisch.
- EDEL.TRAUD.AI ist eine **eigenständige Komponente**: CLI, Bibliothek und
  HTTP-Dienst. Die Webseite (`scan.m-ko.de` oder `m-ko.de/scan`) ist nur ein
  Client.

## 2. Der wichtigste Schnitt: Sammeln und Bewerten trennen

Prüfungen bestehen aus zwei Arten von Modulen:

| Art | Aufgabe | Netz | Kosten | Beispiel |
|---|---|---|---|---|
| **Sammler** (`collector`) | Holt Rohdaten und legt sie als **Artefakte** ab | ja, nur über die Fetch-Schicht | teuer (Zeit, Anfragen, Browser) | Startseite laden, JS-Bundles laden, Seite im Browser rendern, DNS abfragen |
| **Analyse** (`analyzer`) | Liest Artefakte und Fakten, erzeugt **Befunde** und neue **Fakten** | nein, reine Funktion | billig | Schlüssel im Bundle suchen, Header bewerten, Stack erkennen |
| **Probe** (`probe`) | Gezielte aktive Anfrage nach Nachweis der Inhaberschaft | ja, streng begrenzt | mittel | Supabase-Tabelle mit `anon`-Key lesen |

Vorteile:

- Analysen sind reine Funktionen und mit Fixtures testbar, ohne Netz.
- Mehrere Analysen teilen sich einen Sammler. Ein Bundle wird einmal
  geladen und zehnmal untersucht.
- Die Ampel unterscheidet sich vom Bericht vor allem durch **weniger und
  billigere Sammler**. Analysen sind so günstig, dass die Ampel mehr davon
  laufen lassen kann, als sie anzeigt (für die Zählung gesperrter Befunde).
- Aufgezeichnete Artefakte erlauben ein exaktes Wiederholen eines Scans
  (Fehlersuche, Regressionstests, Nachprüfung im Vergleich).

## 3. Modul-Schnittstelle

```ts
interface ModuleManifest {
  id: string;                 // 'secrets.frontend', stabil, nie umbenennen
  version: string;            // semver; Teil jedes Befunds
  kind: 'collector' | 'analyzer' | 'probe';
  mode: 'passive' | 'active'; // active => Nachweis der Inhaberschaft nötig
  category: Category;         // security | privacy | accessibility | operations | ai | quality
  requires: string[];         // Fakten oder Artefakt-Typen, z. B. ['artifact:js-bundle']
  provides: string[];         // z. B. ['fact:stack.supabase', 'artifact:js-bundle']
  when?: string[];            // läuft nur, wenn diese Fakten wahr sind, z. B. ['fact:stack.supabase']
  params: JSONSchema;         // erlaubte Parameter mit Standardwerten
  budget: { requests?: number; ms?: number; browser?: boolean };
}

interface CheckModule<P = unknown> {
  manifest: ModuleManifest;
  run(ctx: ModuleContext, params: P): Promise<ModuleResult>;
}

interface ModuleContext {
  target: Target;                  // normalisierte URL, Inhaberschaft ja/nein
  artifacts: ArtifactStore;        // nur lesen (Analysen) bzw. schreiben (Sammler)
  facts: FactStore;                // gemeinsame Tafel ("blackboard")
  http?: SafeHttp;                 // nur für collector/probe, mit Budget
  browser?: SafeBrowser;           // nur, wenn budget.browser
  log: Logger;
  signal: AbortSignal;             // Zeitlimit des Plans
}

interface ModuleResult {
  findings: Finding[];
  facts?: Record<string, unknown>;
  artifacts?: Artifact[];
  notChecked?: NotChecked[];       // was dieses Modul ausdrücklich nicht prüfen konnte
}
```

Regeln für Module:

- Ein Modul greift nie direkt aufs Netz, nur über `ctx.http` oder
  `ctx.browser`. Analysen bekommen beides gar nicht erst.
- Ein Modul wirft keine Ausnahme nach außen. Fehler werden zu
  `notChecked` mit Grund. Der Plan läuft weiter.
- Eine Analyse ist deterministisch: gleiche Artefakte, gleiche Befunde.
- Jedes Modul bringt Fixtures (positiv und negativ) und Tests mit.

## 4. Befund-Format

Abweichend von der Übergabe englische Bezeichner im Code, damit ein offener
Kern international lesbar ist. Texte kommen aus Sprachkatalogen.

```ts
interface Finding {
  id: string;                  // 'secrets.frontend/openai-key'
  module: string; moduleVersion: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'likely' | 'possible';
  category: Category;
  location: { url?: string; file?: string; line?: number; selector?: string };
  evidence: string;            // immer maskiert: 'sk-ant-…3f9a'
  messageKey: string;          // 'secrets.openai.title' → DE/EN/PT-Katalog
  vars?: Record<string, string>;
  fix: { stepsKey: string; promptKey?: string };  // Fix-Prompt nur im Bericht
  fingerprint: string;         // stabil über Läufe, für WatchDog und Nachprüfung
}
```

`fingerprint` (Hash aus Modul, Befund-Art und normalisierter Fundstelle)
erlaubt dem WatchDog, nur **neue** Befunde zu melden, und der Nachprüfung,
behobene Befunde abzuhaken.

## 5. Prüfplan und Prüfprozessor

### Prüfplan

```yaml
plan: report
version: 3
limits: { totalMs: 120000, requests: 400, browser: true }
modules:
  - collect.page
  - collect.bundles: { maxBundles: 60, followLazyChunks: true }
  - collect.render:  { waitMs: 4000, captureRequests: true }
  - collect.dns
  - stack.detect
  - secrets.frontend: { includeSourceMaps: true }
  - headers.security
  - privacy.consent-before-tracking
  # ...
presentation:
  showFindings: all
  fixPrompts: true
```

```yaml
plan: ampel
limits: { totalMs: 15000, requests: 30, browser: false }
modules:
  - collect.page
  - collect.bundles: { maxBundles: 5, followLazyChunks: false }
  - stack.detect
  - secrets.frontend
  - headers.security
  - sourcemaps.exposed: { headOnly: true }
  - tls.basics
presentation:
  showFindings: 3          # nach Schwere, Rest nur als Anzahl
  fixPrompts: false
```

Pläne liegen als Daten im Repository (`plans/*.yaml`), werden versioniert
und im Ergebnis vermerkt. Neue Kombinationen (z. B. "nur Datenschutz",
"Agentur-Paket") brauchen keinen Code.

### Ablauf im Prozessor

1. **Validieren:** Plan gegen Schema, Parameter gegen das `params`-Schema
   jedes Moduls. Aktive Module ohne Nachweis der Inhaberschaft werden
   entfernt und als `notChecked: ownership` vermerkt.
2. **Auflösen:** Aus `requires`/`provides` einen gerichteten azyklischen
   Graphen bauen. Fehlende Sammler werden automatisch ergänzt, wenn der Plan
   es erlaubt. Zyklen sind ein Fehler im Plan.
3. **Ausführen:** Stufenweise. Was keine offenen Abhängigkeiten hat, läuft
   parallel (Sammler mit begrenzter Parallelität pro Ziel-Host, Analysen
   frei). `when`-Bedingungen werden erst geprüft, wenn ihre Fakten
   feststehen. So laufen Supabase-Module nur, wenn `stack.detect` Supabase
   gefunden hat.
4. **Budget:** Gesamtzeit, Anfragen und Browser-Sekunden werden zentral
   gezählt. Ist das Budget erschöpft, werden restliche Module als
   `notChecked: budget` vermerkt, nicht stillschweigend weggelassen.
5. **Zusammenführen:** Befunde deduplizieren (gleicher `fingerprint`),
   Schwere und Gesamtampel berechnen, Liste "Nicht geprüft" erzeugen.
6. **Ausgabe:** Ein `ScanResult`-JSON. Alles Weitere (Ampel-Ansicht,
   HTML, PDF, Mail des WatchDog) entsteht daraus in `report/`.

Die Ampel ist eine eigene, kleine Regel auf den Befunden: rot ab einem
kritischen oder zwei hohen Befunden, gelb ab einem hohen oder drei mittleren,
sonst grün. Die Regel ist versioniert und steht im Ergebnis.

### Meine Einschätzung zum Prüfprozessor

Ja, aber bewusst klein halten. Ein Abhängigkeitsgraph mit Fakten-Tafel und
Budget reicht. Keine allgemeine Workflow-Engine, keine Plugin-Ladung zur
Laufzeit, keine Warteschlange im Kern. Module werden zur Build-Zeit
registriert (`modules/index.ts`). Das hält den Kern testbar und lässt sich
später trotzdem in einen Job-Worker packen.

## 6. Verzeichnisstruktur

```
src/
  core/        Prozessor, Plan-Schema, Graph, Budget, Ampel-Regel, Typen
  modules/
    collect/   page, bundles, render, dns, tls, wellknown
    analyze/   secrets, headers, stack, privacy, a11y, ai, deps, ...
    probe/     supabase, firebase, paths, cors, ratelimit, auth
  fetch/       SafeHttp, SafeBrowser (Playwright), SSRF-Schutz, Aufzeichnung
  i18n/        de.json, en.json, pt.json (Titel, Erklärung, Schritte, Fix-Prompts)
  report/      ampel, html, pdf, diff (WatchDog, Nachprüfung)
  cli/         edeltraud <url> --plan ampel --json
  api/         HTTP-Dienst: Scan starten, Status, Ergebnis, Inhaberschaft
plans/         ampel.yaml, report.yaml, deep.yaml, watch.yaml
fixtures/      aufgezeichnete Seiten, Bundles, Header je Modul
docs/
```

## 7. Sicherheit des Scanners selbst

- **SSRF-Schutz** in `SafeHttp` und `SafeBrowser`: private und reservierte
  IP-Bereiche, `localhost`, Link-Local und Metadaten-Endpunkte sperren,
  nach jeder DNS-Auflösung und jeder Weiterleitung erneut prüfen. Im
  Browser per Request-Interception.
- **Grenzen:** Zeitlimit und Größenlimit pro Antwort, höchstens N parallele
  Anfragen pro Host, eigener User-Agent mit Info-URL.
- **Inhaberschaft:** DNS-TXT `edeltraud-verify=<token>` oder Datei
  `/.well-known/edeltraud-<token>.txt`. Gilt 30 Tage, an Konto und Domain
  gebunden. Ohne Nachweis gibt es keine `active`-Module.
- **Proben** lesen höchstens eine Zeile, schreiben nie, legen nichts an.
  Rate-Limit-Tests senden wenige Anfragen mit Pausen.
- **Geheimnisse** werden schon im Sammler maskiert, bevor sie gespeichert
  werden. Artefakte mit Rohinhalt werden nach dem Lauf gelöscht oder nur
  verschlüsselt und kurz aufbewahrt (Frist festlegen).
- **Missbrauch:** Rate-Limit pro IP, pro Konto und pro Ziel-Domain, damit
  niemand die Ampel als kostenlosen Massenscanner benutzt.

## 8. Laufzeit und Hosting

- **Ampel:** reiner Fetch, kein Browser, unter 15 s. Läuft auch in einer
  Funktion, die nur bei Bedarf startet.
- **Bericht und Tiefenprüfung:** Headless-Browser, 1 bis 3 Minuten. Braucht
  einen Container mit Chromium und eine kleine Warteschlange.
- **Empfehlung:** ein kleiner Server (z. B. Hetzner Cloud) mit Docker, einer
  API und einem Worker. Einfach, günstig, in der EU, passt zum bestehenden
  Hetzner-Konto. Cloudflare Workers eignen sich nicht für den
  Browser-Teil.
- Die Webseite auf m-ko.de spricht die API per HTTPS an; so bleibt das
  bestehende statische Hosting unverändert.

## 9. Teststrategie

- **Pro Modul:** Fixtures mit erwarteten Befunden (positiv) und ohne
  Befunde (negativ, z. B. Supabase-`anon`-Key darf kein Schlüssel-Befund
  sein).
- **Plan-Tests:** aufgezeichnete Scans werden im Replay-Modus abgespielt;
  Ergebnis wird mit einem gespeicherten Snapshot verglichen.
- **Testziele:** eigene absichtlich fehlerhafte Beispiel-Apps (Lovable,
  Supabase, Firebase) unter eigener Domain, nie fremde Seiten.
- **Werkzeuge:** TypeScript, `node:test`, wie in m-ko.de.

## 10. Stand der Umsetzung (Gerüst, 20.11.2026)

Umgesetzt wie oben beschrieben, mit diesen Präzisierungen:

- **`uses`** im Manifest: optionale Eingaben. Ein Modul läuft nach ihren
  Lieferanten, braucht sie aber nicht (z. B. `stack.detect` nutzt Bundles,
  wenn vorhanden). `requires` bleibt hart: fehlt die Eingabe, wird das Modul
  als `dependency` übersprungen.
- **Ampel grau (`unknown`):** Fällt ein Modul aus oder fehlt eine harte
  Eingabe, ist der Lauf unvollständig. Ohne Befunde zeigt die Ampel dann
  grau statt grün. Eine nicht erreichbare oder mit 4xx/5xx antwortende
  Startseite führt immer zu grau.
- **Parameter-Schema:** statt JSON-Schema ein kleines eigenes Format
  (`number|boolean|string`, Grenzen, Aufzählung). Reicht für Pläne und spart
  eine Abhängigkeit.
- **Zertifikat:** wird über den Abruf der Startseite geprüft (Node lehnt
  ungültige Zertifikate ab). Ablaufdatum und Protokolle folgen mit
  `collect.tls` in Welle 2.
- **Source Maps:** Es zählt nur eine Antwort, die wirklich wie eine Source
  Map aussieht. SPA-Hosts liefern für jeden Pfad `index.html` mit Status 200;
  das wäre sonst ein Fehlalarm.
- **Sperren:** Die Ampel zeigt 3 Befunde (Hinweise rücken nach hinten), der
  Rest wird schon auf dem Server auf Anzahlen reduziert. Details gesperrter
  Befunde verlassen den Server nicht.
- **Netz:** `LiveHttp` auf `node:https` mit eigener DNS-Auflösung, die
  gesperrte Adressen auch nach Weiterleitungen ablehnt. Hinter einem
  HTTP-Proxy (`NODE_USE_ENV_PROXY=1`) wird zusätzlich vorab aufgelöst.
- **Aufzeichnen:** `--record <datei>` speichert alle Antworten eines Laufs
  als Replay-Fixture.

### Welle 2, Teil "Rest" (20.11.2026)

- **DNS und TLS im Kontext:** Sammler und Proben bekommen neben `ctx.http`
  auch `ctx.dns` (`Dns`, live `LiveDns` über `node:dns/promises`) und
  `ctx.tls` (`TlsInspector`, live `LiveTls` mit `safeLookup`, also mit
  demselben SSRF-Schutz). Analysen bekommen beides nicht.
- **Replay:** `ReplayDns` (Schlüssel `'name TYPE'`) und `ReplayTls`
  (Host → Handshake). Ein Lauf mit aufgezeichnetem HTTP nutzt nie Live-DNS
  oder -TLS. Fehlen DNS/TLS, melden die Sammler `unsupported`; das macht den
  Lauf nicht unvollständig.
- **Deterministische Ablaufwarnung:** `collect.tls` speichert `checkedAt`,
  `tls.basics` rechnet die Restlaufzeit daraus. Schwelle: min(14 Tage,
  20 % der Laufzeit), damit kurzlebige Zertifikate (6 oder 45 Tage) nicht
  alarmieren.
- **Fehlerseiten:** `collect.errorpages` fragt feste Pfade ab, damit
  Aufzeichnungen stabil bleiben. Das ist ein normaler GET auf eine fehlende
  Seite, also passiv.
- **Analysen mit optionalen Sammlern** (`dns.mail`, `deps.vulnerable`,
  `errors.verbose`) deklarieren ihre Eingaben über `uses`, nicht
  `requires`. Fehlt die Eingabe, bleiben sie still; den Grund meldet der
  Sammler.

### Welle 2, Teil "Browser" (20.11.2026)

- **`ctx.browser`** gibt es nur für Module mit `budget.browser` in Plänen
  mit `limits.browser: true`. `LiveBrowser` lädt Playwright erst bei Bedarf
  (`playwright-core` oder `playwright`, `EDELTRAUD_PLAYWRIGHT`), API-Image
  und CI brauchen es nicht.
- **Ein Lauf, keine Interaktion:** frischer Browser je Scan, kein Klick,
  keine Eingabe. Alles im Artefakt `render` geschah also vor einer
  möglichen Einwilligung. Vom Storage werden nur Schlüssel gespeichert.
- **SSRF im Browser:** Jede Anfrage läuft durch `page.route` und wird nach
  DNS-Auflösung geprüft. Restrisiko DNS-Rebinding (Chromium löst selbst
  auf): Der Worker (`Dockerfile.worker`) läuft in einem Netz ohne Zugang zu
  internen Diensten und Metadaten-Endpunkten.
- **Ampel ohne Browser:** Module, die auch in der Ampel laufen
  (`privacy.third-party`, `privacy.legal-pages`), arbeiten auf dem
  statischen HTML. Bei einer leeren SPA-Hülle melden sie "nicht
  unterstützt" statt zu raten.
