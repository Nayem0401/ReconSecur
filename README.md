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

Kali-Tools werden erst ueber einen separaten, allowlist-basierten Adapter aktiviert. Dieser muss Scope-Verifikation, Rate-Limits, Prozess-Timeouts, Audit-Logs und eine explizite Phasenfreigabe erzwingen.

Fuer ausdruecklich autorisierte interne Labore kann der Betreiber private Targets lokal freigeben:

```powershell
$env:AETHER_ALLOW_PRIVATE="true"
npm start
```
