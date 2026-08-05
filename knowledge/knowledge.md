# Knowledge — Das Projekt Aether

Diese Datei beschreibt das Projekt selbst (Architektur, Komponenten, Konventionen).
Grundwissen, das den Kontext traegt. Append-only, Format `- [YYYY-MM-DD] <Kurztext>`.

## Zweck

Aether ist eine consent-gesteuerte, defensive AppSec-/Pentest-Konsole fuer autorisierte
Web-Sicherheitsbewertungen. Node.js ohne externes Framework (core http/fs/dns/tls/net).
Bindet auf 127.0.0.1:4173. Passive Web-Analyse plus allowlist-gated Kali-Tool-Adapter.

## Architektur

- `server.js` — HTTP-Server, statische Auslieferung aus `public/`, JSON-APIs:
  `/api/assessments` (passive Analyse), `/api/tools` (Inventar), `/api/tool-sessions`
  (Einzel-Tool + SSE-Livestream), `/api/recon-runs` (alle Phase-1-Tools parallel).
- `API/toolAdapter.js` — einzige Wahrheitsquelle: deklaratives `PROFILES`-Schema treibt
  `ALLOWLIST`, `TOOL_CATALOG` (Client-Rendering) und `buildToolCommand` (Argumentbau).
  Tool-Erkennung Windows-PATH + WSL2/Kali. Ausfuehrung via `spawn`, `shell:false`.
- `public/` — Vanilla-JS-SPA (SecureOS-v4-Design). `app.js` Logik, `index.html`, `styles.css`.
- `test/server.test.js` — Node-Test-Suite. `scripts/ui-smoke.js` — UI-Smoke (Playwright).
- `legacy/secureos-v4/` — unveraenderte Referenz, nur gezielt gepruefte Teile portieren.

## Sicherheitsmodell

- Nur Allowlist-Tools, keine Shell-Interpolation von Nutzereingaben.
- Client sendet nur typisierte `options`; Server validiert gegen Schema und baut das
  Argument-Array. Injection-Metazeichen werden zu literalen Einzelargumenten.
- Kein web-exponierter Freitext-/Elevation-Shell-Endpoint (RCE-Verbot).
- Ziel-Validierung blockt CRLF/Null; requireTarget begrenzt Laenge.

## Konventionen

- Phasenmodell: 1 Information Gathering (15 staerkste Info-Sammler, laeuft zuerst),
  2 Content Discovery, 3 TLS/SSL, 4 Vuln & Injection.
- Wortlisten als feste Kali-Enum (kein Freitext-Pfad). sqlmap risk 1..3.
- Einzige h1 = "Dashboard" (fuer ui:smoke). Knowledge append-only, nur Master schreibt.

## Befehle

- Start `npm start` · Tests `npm test` · UI-Smoke `npm run ui:smoke` · Hilfe `npm run mcp:help`
