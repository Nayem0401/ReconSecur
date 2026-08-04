# Changelog

Durchgefuehrte Code-Aenderungen. Append-only. Format: `- [YYYY-MM-DD] <Aenderung> | Datei: <pfad>`.

- [2026-08-05] Git-Repo initialisiert, Remote origin=github.com/Nayem0401/ReconSecur, Rebase-Merge (.gitignore, README) + Push main.
- [2026-08-05] Tool-Adapter: erkennt Windows- + WSL2/Kali-Tools (Allowlist 37), Endpoint GET /api/tools. | Datei: API/toolAdapter.js, server.js
- [2026-08-05] Adapter Discovery erweitert: listet ALLE Executables (Kali ~6155, Windows ~736) via ls/PATH-Scan; Allowlist nur noch Execution-Gate (execReady). | Datei: API/toolAdapter.js
