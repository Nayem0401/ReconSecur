# Changelog

Durchgefuehrte Code-Aenderungen. Append-only. Format: `- [YYYY-MM-DD] <Aenderung> | Datei: <pfad>`.

- [2026-08-05] Git-Repo initialisiert, Remote origin=github.com/Nayem0401/ReconSecur, Rebase-Merge (.gitignore, README) + Push main.
- [2026-08-05] Tool-Adapter: erkennt Windows- + WSL2/Kali-Tools (Allowlist 37), Endpoint GET /api/tools. | Datei: API/toolAdapter.js, server.js
- [2026-08-05] Adapter Discovery erweitert: listet ALLE Executables (Kali ~6155, Windows ~736) via ls/PATH-Scan; Allowlist nur noch Execution-Gate (execReady). | Datei: API/toolAdapter.js
- [2026-08-05] Web-UI auf SecureOS-v4-Design neu aufgebaut (Sidebar, Phasen-Stepper, Terminal, Findings-Tabelle, Tools-Ansicht), verdrahtet mit echtem Backend (/api/assessments, /api/tools). | Datei: public/index.html, public/app.js, public/styles.css
