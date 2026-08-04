# SecureOS — Master Documentation Bundle

**Version:** v4 MASTER  
**Team:** Red / Blue / Purple  
**Prinzip:** Consent First. Always.

---

## Enthaltene Dateien

| Datei | Inhalt | Verwenden für |
|-------|--------|---------------|
| `secureos_agent_directive.md` | Vollständiger System-Prompt für AI-Agent | Ollama, FastAPI, .cursorrules, VS Code |
| `secureos_ai_manual_analysis.md` | AI-Spezialisierung für manuelle Findings, DevTools, Code-Analyse | AI-Training, User-Onboarding |
| `secureos_tool_pipeline.md` | 100+ Tools, nach Phasen sortiert, mit Commands | Backend-Konfiguration, Tool-Integration |
| `README.md` | Diese Datei | Orientierung |

---

## Schnellstart

### 1. Ollama / Mistral lokal

```bash
# Modell starten
ollama serve
ollama pull mistral

# Test mit System-Prompt
ollama run mistral --system "$(cat secureos_agent_directive.md)"
```

### 2. FastAPI Backend

```bash
# System-Prompt laden
cp secureos_agent_directive.md backend/prompts/

# In backend/main.py:
SYSTEM_PROMPT = open("prompts/secureos_agent_directive.md").read()
```

### 3. VS Code / Cursor

```bash
# .cursorrules in Projekt-Root:
cp secureos_agent_directive.md .cursorrules
# Oder Kurzversion aus secureos_ai_manual_analysis.md → Abschnitt ".cursorrules"
```

---

## Die 8 Phasen auf einen Blick

```
Phase 1  RECON          Tier 1+   OSINT, DNS, Subdomains, Google Dorks
Phase 2  FINGERPRINT    Tier 1+   Tech-Stack, Ports, WAF, CDN
Phase 3  ENUMERATION    Tier 2+   Directories, Endpoints, Crawling
Phase 4  VULN SCAN      Tier 2+   Nuclei, Nikto, SQLMap (verified!)
Phase 5  ANALYSIS       Tier 3+   AI-Analyse, Manual Review, DevTools
Phase 6  PAYLOAD        Tier 4+   ⛔ Admin required
Phase 7  EXPLOIT        Tier 4+   ⛔ Admin + doppeltes Consent
Phase 8  REPORT         alle      PDF-Bericht, CVSS, Remediation
```

---

## Consent Gate — Checkliste vor jedem Engagement

```
[ ] Signierter Vertrag vorhanden
[ ] DNS-TXT Record verifiziert: secureos-verify=[token]
    ODER Website-Snippet: <meta name="secureos-consent" content="[token]">
[ ] Scope-Liste schriftlich bestätigt
[ ] Tier-Level geprüft
[ ] Engagement-Zeitfenster definiert
[ ] Admin anwesend (bei Phase 6-8)
[ ] Notfallkontakt beim Kunden hinterlegt
```

---

## AI Finding-Format (Kurzreferenz)

Jedes Finding der AI folgt diesem Schema:

```
[SEVERITY: CRITICAL/HIGH/MEDIUM/LOW/INFO]

Typ:         [Finding-Name]
OWASP:       [A0X:2021 – Name]
CWE:         [CWE-XXX]
CVSS:        [0.0–10.0] [CRITICAL/HIGH/MEDIUM/LOW]

Was:         [Klare Erklärung]
Ausnutzbar:  [Ja/Nein/Kontext-abhängig]
Scope:       [IN SCOPE / OUT OF SCOPE]

Nächster Schritt:
→ [Exakter Command]
```

---

*SecureOS — Ethical Pentesting with Consent. Built for professionals.*
