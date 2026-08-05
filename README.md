# Aether Assessment Console (ReconSecur)

Lokale Weboberflaeche fuer autorisierte, nicht-destruktive Web-Sicherheitsbewertungen. Der aktive Node.js-Dienst prueft Scope, DNS, HTTP-Header und TLS-Metadaten und erzeugt evidenzbasierte Findings mit Empfehlungen.

## Voraussetzungen

- Node.js 20+
- npm 10+
- Schriftliche Autorisierung fuer jedes eingegebene Target

## Installation und Start

Windows PowerShell:

```powershell
npm install
npm start
```

Linux:

```bash
npm install
npm start
```

Danach ist die UI unter http://127.0.0.1:4173 erreichbar.

## Befehle

- `npm start`: startet API und Web-UI
- `npm run dev`: startet den Node-Watch-Modus
- `npm test`: prueft Target-Validierung und Finding-Erzeugung
- `npm run ui:smoke`: prueft Desktop und Mobile mit Playwright; der Server muss laufen
- `npm run mcp:start`: startet Playwright MCP
- `npm run mcp:headless`: startet Playwright MCP headless
- `npm run mcp:help`: zeigt MCP-Optionen

Playwright Chromium fuer den UI-Test installieren:

```powershell
npx playwright install chromium
```

## Architektur

- `server.js`: lokale API, statische Auslieferung und passive Analyse
- `public/`: aktive Weboberflaeche
- `test/`: fokussierte Node-Tests
- `scripts/ui-smoke.js`: responsive Browser-Validierung
- `legacy/secureos-v4/`: unveraenderter importierter SecureOS-v4-Prototyp

Der importierte FastAPI-Prototyp enthaelt wertvolle Phasen-, Consent- und Analysekonzepte, ist aber nicht die aktive Runtime. Insbesondere Platzhalter-Consent und direkte Tool-Ausfuehrung duerfen nicht ungeprueft produktiv aktiviert werden.

## Sicherheitsgrenzen

- Nur HTTP(S)-Targets ohne eingebettete Zugangsdaten
- Explizite Autorisierungsbestaetigung pro Lauf
- Passive Web-Checks mit festen Timeouts
- Loopback- und private Netzadressen standardmaessig blockiert
- Keine frei konfigurierbaren Shell-Befehle
- Findings basieren ausschliesslich auf beobachteter Evidenz
- Ein serverseitiges Engagement bindet jede Analyse und Tool-Session an exakt eine Target-Origin und laeuft nach maximal acht Stunden ab
- Kunden starten mit Phase 1; Phase 2 bis 4 werden einzeln und in Reihenfolge bestaetigt. Master-Engagements erhalten alle vier Phasen.
- Pro Engagement sind maximal 20 Tool-Starts pro Minute erlaubt; alle Engagement-, Analyse- und Tool-Ereignisse werden append-only nach `artifacts/audit.jsonl` geschrieben

Kali-Tools werden ausschliesslich ueber den allowlist-basierten Adapter aktiviert. Der Browser erstellt ein Engagement nach expliziter Bestaetigung; jede nachfolgende Analyse, Phasenfreigabe und Tool-Session muss sowohl dessen serverseitige ID als auch den zugehoerigen Login-Session-Token vorlegen.

Fuer ausdruecklich autorisierte interne Labore kann der Betreiber private Targets lokal freigeben:

```powershell
$env:AETHER_ALLOW_PRIVATE="true"
npm start
```

Die Engagement-Laufzeit kann lokal zwischen einer Minute und 24 Stunden konfiguriert werden (Standard: 8 Stunden):

```powershell
$env:AETHER_ENGAGEMENT_TTL_MS="28800000"
npm start
```

### Admin-Freigabecode (Pflicht fuer jedes Engagement)

Nur der Admin kann ein Engagement freigeben. Dazu wird `AETHER_ADMIN_TOKEN` gesetzt; ohne dieses Token ist die
Freigabe-Route deaktiviert (503). Der Admin praegt manuell einen 20-stelligen, einmal verwendbaren Code fuer genau
ein Ziel (scope-gebunden, TTL 15 Minuten Standard); der Nutzer traegt Ziel + Code + Autorisierungshaeckchen im
Consent-Modal ein, um `POST /api/engagements` auszuloesen.

```powershell
$env:AETHER_ADMIN_TOKEN="ein-geheimes-admin-token"
npm start
```

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:4173/api/admin/approvals `
  -Headers @{ Authorization = "Bearer ein-geheimes-admin-token" } `
  -ContentType "application/json" `
  -Body (@{ target = "https://example.com" } | ConvertTo-Json)
```

Die Antwort enthaelt den 20-stelligen `code`, der einmalig fuer das angegebene Ziel eingeloest werden kann. Die
Freigabecode-TTL laesst sich per `AETHER_APPROVAL_TTL_MS` (1 Minute bis 24 Stunden, Standard 15 Minuten) anpassen.

### Login-System (Kunden-Codes + Master-Codes)

Vor jedem Engagement muss sich der Nutzer einloggen (`POST /api/login`, `{ "code": "..." }`):

- **Kunden**: admin-gepraegter, wiederverwendbarer 15-stelliger Code (`POST /api/admin/logins`, Admin-Token noetig,
  TTL per `AETHER_CUSTOMER_CODE_TTL_MS`, Standard 30 Tage). Kunden brauchen weiterhin zusaetzlich pro Ziel den
  20-stelligen Admin-Freigabecode aus `/api/admin/approvals`.
- **Master (Team)**: mindestens 3 feste Codes ueber `AETHER_MASTER_CODES` (kommagetrennt, beliebig erweiterbar).
  Master-Logins ueberspringen den Freigabecode, erhalten sofort alle Phasen freigeschaltet und duerfen auch
  private/lokale Ziele fuer interne Lab-Tests ansteuern (Bypass gilt nur fuer Tool-Sessions/Recon, nicht fuer die
  passive Analyse).

```powershell
$env:AETHER_MASTER_CODES="master-code-eins,master-code-zwei,master-code-drei,master-code-vier"
npm start
```

```powershell
Invoke-RestMethod -Method Post -Uri http://127.0.0.1:4173/api/admin/logins `
  -Headers @{ Authorization = "Bearer ein-geheimes-admin-token" }
```

Die Antwort enthaelt den 15-stelligen Kunden-Login-Code. `POST /api/login` liefert ein Session-Token (`sessionToken`),
das beim Erstellen des Engagements und bei jeder zugehoerigen Analyse, Phasenfreigabe oder Tool-Session mitgeschickt werden muss; die Session-TTL laesst sich per
`AETHER_SESSION_TTL_MS` (Standard 12 Stunden) anpassen.
