# Changelog

Durchgefuehrte Code-Aenderungen. Append-only. Format: `- [YYYY-MM-DD] <Aenderung> | Datei: <pfad>`.

- [2026-08-05] Git-Repo initialisiert, Remote origin=github.com/Nayem0401/ReconSecur, Rebase-Merge (.gitignore, README) + Push main.
- [2026-08-05] Tool-Adapter: erkennt Windows- + WSL2/Kali-Tools (Allowlist 37), Endpoint GET /api/tools. | Datei: API/toolAdapter.js, server.js
- [2026-08-05] Adapter Discovery erweitert: listet ALLE Executables (Kali ~6155, Windows ~736) via ls/PATH-Scan; Allowlist nur noch Execution-Gate (execReady). | Datei: API/toolAdapter.js
- [2026-08-05] Web-UI auf SecureOS-v4-Design neu aufgebaut (Sidebar, Phasen-Stepper, Terminal, Findings-Tabelle, Tools-Ansicht), verdrahtet mit echtem Backend (/api/assessments, /api/tools). | Datei: public/index.html, public/app.js, public/styles.css
- [2026-08-05] Tool-Katalog (Kategorie+Flag-Doku) + typisierte Ausfuehrungsprofile + startTool()-Streaming. | Datei: API/toolAdapter.js
- [2026-08-05] Live-Tool-Sessions via SSE: POST/GET/DELETE /api/tool-sessions, Session-Registry, Limits. | Datei: server.js
- [2026-08-05] Tools-Seite: Kategorie-Filter, aufklappbarer Katalog mit Flag-Erklaerungen, typisiertes Startformular mit Kommando-Vorschau, Live-Session-Terminal. | Datei: public/index.html, public/app.js, public/styles.css
- [2026-08-05] Tests ergaenzt: Katalog-Schema, sqlmap risk 1..3, Injection-Safety, Session-Auth-Gate. | Datei: test/server.test.js
- [2026-08-05] Adapter auf deklaratives PROFILES-Schema umgestellt (26 Web-Red-Team-Tools, Emoji-Kategorien, typisierte Flags+positional, WORDLISTS-Enum); generischer buildToolCommand ersetzt if-Kette; PROFILES exportiert. | Datei: API/toolAdapter.js
- [2026-08-05] Server bildet Tool-Ziel nach profile.target.kind (host/url/domain/hostport). | Datei: server.js
- [2026-08-05] Tools-Seite: Katalog nach Emoji-Kategorien gruppiert, jedes Tool startbar, Flags generisch aus Schema (Checkbox/Select/Number/Text) mit Erklaerung, generische Kommando-Vorschau; OS-Chip-Ansicht entfernt. | Datei: public/index.html, public/app.js, public/styles.css
- [2026-08-05] Tests auf Schema-Builder angepasst (order-unabhaengig, Emoji-Kategorie, jedes Tool ausfuehrbar). | Datei: test/server.test.js
- [2026-08-05] Phasen-Metadaten (PHASES/PHASE_BY_TOOL) + dnsenum-Profil; dig um E-Mail-Security-Scope (SPF/DMARC/DKIM, role prefix) + TXT-Default erweitert; buildToolCommand ueberspringt role prefix; PHASES exportiert. | Datei: API/toolAdapter.js
- [2026-08-05] Server wendet validierten Scope-Praefix auf Host an (dig _dmarc./default._domainkey.). | Datei: server.js
- [2026-08-05] Tools-Seite: Phasen-Tabs (Phase 1 default), Filter nach Phase+Kategorie+Text, Scope-Praefix in Kommando-Vorschau. | Datei: public/index.html, public/app.js, public/styles.css
- [2026-08-05] Tests: Phase 1 >=10 Tools, dig DMARC-Scope-Aufbau. | Datei: test/server.test.js
- [2026-08-05] Phase 1 auf 15 Info-Sammler umgestellt, Phasen auf 4 verdichtet (Fingerprint/HTTP in Phase 1 bzw. Content), Fallback-Phase 4. Test auf >=15 angehoben. | Datei: API/toolAdapter.js, test/server.test.js
- [2026-08-05] Parallel-Recon: MAX_TOOL_SESSIONS 4->16, spawnSession extrahiert, startReconBatch + POST /api/recon-runs (validiert Phase-1-Allowlist, Auth-Guard 403). | Datei: server.js
- [2026-08-05] Recon-Batch-UI: Leiste (Ziel/Env) nur Phase 1, Multi-Terminal-Grid mit Live-SSE je Tool, Status-Dots, Einzelabbruch; wireStream generalisiert. | Datei: public/index.html, public/app.js, public/styles.css
- [2026-08-05] Test: /api/recon-runs Auth-Guard 403. | Datei: test/server.test.js
- [2026-08-05] Katalog rendert immer alle Tools kategorisiert (nicht nur execReady); nicht installierte markiert/deaktiviert; Gruppen zeigen verfuegbar/gesamt. | Datei: public/app.js, public/styles.css
- [2026-08-05] Regeln: 5-Stufen-Vorausdenken + Selbstpruefung; Knowledge-Semantik (knowledge=Projekt, changelog=letzte Aenderungen, bugfix=Bugs); knowledge/knowledge.md angelegt; Doku-Pflicht fuer alle Agenten (Subagenten lesen+zitieren via GELESEN, Master schreibt nach jeder Aenderung). | Datei: .github/copilot-instructions.md, .github/agents/*.agent.md, knowledge/INDEX.md, knowledge/knowledge.md
- [2026-08-05] Fix (Funktion-Vorschlag): fehlenden `node:crypto`-Import ergaenzt (crypto.randomUUID versionsunabhaengig). | Datei: server.js
- [2026-08-05] Fix (kombinierte Funktion+Bug-Analyse): SSE-Reconnect fuer Livestream repariert, onerror schliesst EventSource nicht mehr; npm test 12/12 gruen. | Datei: public/app.js
- [2026-08-05] Bugfix-Runde (Bug-Vorschlaege A-D): openssl-SNI aus Ziel abgeleitet; serveStatic path-sep+pathname-Guard; Tool-Sessions Private-IP/SSRF-Block (spawnSession async); GET Session-Summary. | Datei: API/toolAdapter.js, server.js, public/app.js
