# Chatlog

Entscheidungen und Master-Beschluesse. Append-only. Format: `- [YYYY-MM-DD] <Kurztext>`.

- [2026-08-05] Subagent-Architektur (Master/GUI/Funktion/Bug) + feste Knowledge-Pfade eingefuehrt.
- [2026-08-05] Entscheidung: WSL-Tool-Detektion via `which <tools>` (direkte Args), nicht `bash -lc` (wsl.exe zerlegt Shell-Scripts, Login-Shell scheiterte). Ausfuehrung bleibt allowlist-gated, kein HTTP-Run-Endpoint.
