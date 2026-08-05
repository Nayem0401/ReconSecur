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
  (Einzel-Tool + SSE-Livestream), `/api/recon-runs` (alle Phase-1-Tools parallel),
  `/api/admin/approvals` (Admin-only, praegt Freigabecodes), `/api/engagements` (verlangt Code).
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
- Engagement-Erstellung verlangt einen Admin-geprägten, scope-gebundenen, einmal
  verwendbaren 20-Zeichen-Freigabecode (`AETHER_ADMIN_TOKEN`-Gate an `/api/admin/approvals`,
  TTL via `AETHER_APPROVAL_TTL_MS`) zusaetzlich zum Autorisierungshaeckchen.
- Login-Pflicht vor jedem Engagement (`POST /api/login`): Kunden = admin-gepraegter,
  wiederverwendbarer 15-stelliger Code (`/api/admin/logins`); Team/Master = genau 3 feste
  Codes (`AETHER_MASTER_CODES`). Master-Login unlockt sofort alle Phasen, ueberspringt den
  Freigabecode und darf bei Tool-Sessions/Recon private/lokale Ziele ansteuern (reines
  internes Lab-Testing); die passive Analyse bleibt vom Private-Target-Bypass ausgenommen.
- Account-Login (API/accountStore.js): persistente Accounts mit E-Mail + Passwort; Passwoerter
  nur als scrypt-Hash+Salt in `artifacts/accounts.json` (gitignored). Rolle `superadmin` teilt
  sich die Master-Rechte (isPrivilegedRole). Pro Account wird die Engagement-Historie gespeichert
  (`GET /api/account/history`). Super-Admin-Seed via `AETHER_SUPERADMIN_EMAIL`/`_PASSWORD`;
  weitere Accounts ueber admin-authentifiziertes `POST /api/admin/accounts`.

## Konventionen

- Phasenmodell: 1 Information Gathering (staerkste Info-Sammler, laeuft zuerst),
  2 Content Discovery, 3 TLS/SSL, 4 Vuln & Injection, 5 Automatic Recon & Dorking.
  Max-Phase wird dynamisch aus `toolAdapter.PHASES` abgeleitet (nicht hartcodiert).
- Wortlisten als feste Kali-Enum (kein Freitext-Pfad). sqlmap risk 1..3.
- Einzige h1 = "Dashboard" (fuer ui:smoke). Knowledge append-only, nur Master schreibt.

## Befehle

- Start `npm start` · Tests `npm test` · UI-Smoke `npm run ui:smoke` · Hilfe `npm run mcp:help`

- [2026-08-05] Engagement-Gate: POST /api/engagements erzeugt eine in-memory Engagement-ID mit Origin-Scope, Phase 1 und konfigurierbarer 8h-TTL. Assessments/Tool-Sessions/Recon akzeptieren nur diese ID, Scope und freigegebene Phase; Audit nach artifacts/audit.jsonl, 20 Tool-Starts/Minute/Engagement.
- [2026-08-05] Engagement-Folgeaktionen pruefen zusaetzlich den urspruenglichen Login-Session-Token. Eine erratene oder weitergegebene Engagement-ID allein berechtigt weder zu Analyse, Tool-Start noch Phasenfreigabe.
