# Betrieb auf dem Server (scan.m-ko.de)

## 0. Erstinstallation (einmalig)

Docker mit Compose-Plugin und git müssen installiert sein. Das Repository ist
privat; der Server bekommt dafür einen eigenen Lese-Schlüssel (Deploy key):

```bash
sudo ssh-keygen -t ed25519 -N '' -f /root/.ssh/edeltraud_deploy -C scan.m-ko.de
```

```bash
sudo cat /root/.ssh/edeltraud_deploy.pub
```

Den ausgegebenen Schlüssel auf GitHub unter *muka-dev/ai-check > Settings >
Deploy keys* eintragen (nur Lesen, kein Schreibzugriff). Dann klonen:

```bash
sudo GIT_SSH_COMMAND='ssh -i /root/.ssh/edeltraud_deploy' git clone git@github.com:muka-dev/ai-check.git /opt/edeltraud/ai-check
```

```bash
sudo git -C /opt/edeltraud/ai-check config core.sshCommand 'ssh -i /root/.ssh/edeltraud_deploy'
```

Datenverzeichnis für WatchDog und Aufträge (der Container läuft als Benutzer 1000):

```bash
sudo mkdir -p /opt/edeltraud/data && sudo chown 1000:1000 /opt/edeltraud/data
```

Danach Abschnitt 1 (Geheimnisse) und 3 (Proxy) erledigen.

## Deploy (jedes Update)

Deployt wird immer `main`, nachdem der PR gemerged und die CI grün ist:

```bash
sudo /opt/edeltraud/ai-check/deploy/update.sh
```

Das Skript holt den Stand, baut die Images, startet die API (und den
Auftrags-Worker, sobald Paddle eingerichtet ist) neu und prüft `/health`.
Scheitert der Build, läuft die alte Version weiter. Scheitert die Prüfung,
nennt es den Befehl zum Zurückrollen, z. B.:

```bash
sudo /opt/edeltraud/ai-check/deploy/update.sh 1a2b3c4
```

Das Compose-Projekt heißt fest `edeltraud`, die Container also `edeltraud-api-1`,
`edeltraud-jobs-1` usw. (bis Ende November 2026 hießen sie nach dem Ordner
`deploy-api-1`). Beim ersten Lauf nach der Umstellung entfernt `update.sh` die alten
`deploy-*`-Container, die API ist dabei wenige Sekunden weg.

Logs ansehen:

```bash
sudo docker compose -f /opt/edeltraud/ai-check/deploy/compose.yaml logs --tail 100 api
```

DNS und TLS-Zertifikat für `scan.m-ko.de` stehen. Der TLS-Proxy auf dem Server
leitet an die API auf `127.0.0.1:8787` weiter.

## 1. Geheimnisse anlegen (einmalig)

```bash
sudo mkdir -p /opt/edeltraud
sudo cp deploy/api.env.example /opt/edeltraud/api.env
sudo chmod 600 /opt/edeltraud/api.env
```

Dann in `/opt/edeltraud/api.env` eintragen:

- `POW_SECRET`: Ergebnis von `openssl rand -hex 32`
- `OWNERSHIP_SECRET`: ein zweites, anderes Ergebnis von `openssl rand -hex 32`

Die Datei gehört nicht ins Repository. Wozu `POW_SECRET` dient: Die API
signiert damit die Rechenaufgaben der Ampel. Ohne festen Wert erzeugt jeder
Start einen neuen Schlüssel; dann sind Aufgaben, die kurz vor einem Neustart
ausgegeben wurden, ungültig (der Besucher klickt einfach erneut). Mit festem
Wert überstehen sie Neustarts. Ein Wechsel des Werts ist jederzeit möglich.

## 2. Starten

```bash
cd /opt/edeltraud/ai-check
docker compose -f deploy/compose.yaml up -d --build
curl -s http://127.0.0.1:8787/health
```

`/health` antwortet 200 `{"ok":true}`. Mit `JOBS_DIR` meldet es zusätzlich
einen hängenden Auftrags-Worker: 503 `{"ok":false,"jobs":"stalled",…}`, sobald
ein fälliger Auftrag länger als 2 h wartet (`HEALTH_MAX_QUEUE_AGE_MS`). Von
außen überwachen, z. B. im bestehenden GitHub-Actions-Lauf:
`curl -fsS https://scan.m-ko.de/health` (schlägt bei 503 fehl).

## 3. Proxy

Wichtig für die Grenzen pro Besucher: Der Proxy muss die Adresse des Besuchers
in `X-Forwarded-For` **anhängen** oder setzen. Die API nimmt den letzten Eintrag.

Caddy direkt auf dem Server (Paket, systemd), das Netz einmalig anlegen (`sudo docker network create proxy`):

```
scan.m-ko.de {
  reverse_proxy 127.0.0.1:8787
}
```

Caddy in einem eigenen Docker-Container: Dort ist `127.0.0.1` der
Caddy-Container selbst (Folge: 502). `compose.yaml` hängt die API deshalb fest
unter dem Namen `edeltraud-api` in das Docker-Netz von Caddy (Standard: `proxy`).
Das bleibt auch bei `docker compose up` ohne `update.sh` erhalten. Heißt das Netz
anders, in `/opt/edeltraud/api.env` `PROXY_NETWORK=<Netz>` eintragen und bei
Befehlen von Hand `PROXY_NETWORK=<Netz>` voranstellen:

```
scan.m-ko.de {
  reverse_proxy edeltraud-api:8787
}
```

Das Netz von Caddy findet sich mit:

```bash
sudo docker inspect <caddy-container> -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}} {{end}}'
```

nginx:

```
location / {
  proxy_pass http://127.0.0.1:8787;
  proxy_set_header Host $host;
  proxy_set_header X-Forwarded-For $remote_addr;
}
```

Sicherheits-Header (CSP usw.) setzt die API selbst; der Proxy soll sie nicht
überschreiben.

## 4. Prüfen

- `https://scan.m-ko.de/` zeigt die Ampel.
- Eine eigene App prüfen, z. B. `m-ko.de`.
- Der Netzwerk-Tab des Browsers zeigt nur Anfragen an `scan.m-ko.de`.

## 5. WatchDog (wöchentlich)

Einmalig:

```bash
sudo mkdir -p /opt/edeltraud/data && sudo chown 1000:1000 /opt/edeltraud/data
```

In `/opt/edeltraud/api.env` zusätzlich `WATCH_SECRET` (wieder
`openssl rand -hex 32`), `SMTP_URL` und `MAIL_FROM` eintragen.

Einen WatchDog anlegen (bis zur Bezahlung von Hand):

```bash
docker compose -f deploy/compose.yaml run --rm watch watch add https://app.example.com --email kunde@example.com --lang de
```

Täglich laufen lassen; fällig ist jeder WatchDog 7 Tage nach ihrem letzten Lauf
(z. B. per cron um 6:17 Uhr):

```
17 6 * * * cd /opt/edeltraud/ai-check && docker compose -f deploy/compose.yaml run --rm watch >> /var/log/edeltraud-watch.log 2>&1
```

Mails gehen nur bei Änderungen raus: neue Befunde, höhere Schwere, behobene
Befunde (nur nach vollständigem Lauf). Die erste Mail bestätigt, dass der
WatchDog läuft. Jede Mail enthält einen Abmeldelink (auch Ein-Klick-Abmeldung
im Mailprogramm).

## 6. Bezahlung mit Paddle (zuerst Sandbox)

1. In Paddle (Sandbox) unter *Checkout > Checkout settings* den **Default payment
   link** auf `https://scan.m-ko.de/pay` setzen und die Domain freigeben lassen.
2. Unter *Developer tools > Authentication* einen **Client-side token** anlegen und
   als `PADDLE_CLIENT_TOKEN` eintragen (der Token ist öffentlich gedacht).
3. Katalog und Webhook anlegen, die Ausgabe in `/opt/edeltraud/api.env` übernehmen:

```bash
docker compose -f deploy/compose.yaml run --rm --entrypoint node api scripts/paddle-setup.ts --dry-run
```

```bash
docker compose -f deploy/compose.yaml run --rm --entrypoint node api scripts/paddle-setup.ts --webhook
```

   Das Webhook-Secret wird nur einmal angezeigt.
4. API neu starten und den Worker für Aufträge starten:

```bash
docker compose -f deploy/compose.yaml up -d --build api
```

```bash
docker compose -f deploy/compose.yaml --profile jobs up -d jobs
```

5. Testkauf in der Sandbox mit einer Testkarte von Paddle, dann prüfen: Mail mit
   Bericht kommt an, `docker compose -f deploy/compose.yaml logs jobs` ohne Fehler.
6. Erst nach Freigabe durch Paddle `PADDLE_ENV=production` mit Live-Schlüsseln.

## 7. Worker-Image

Folgt mit der Bezahlung (Schritt 6). Das Image `Dockerfile.worker` läuft in
einem eigenen Docker-Netz ohne Zugang zu internen Diensten.
