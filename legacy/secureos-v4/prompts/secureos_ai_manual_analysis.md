# SecureOS — AI Spezialisierung: Manual Findings & Code Analyse

**Datei:** `secureos_ai_manual_analysis.md`  
**Zweck:** Wissens- und Prompt-Grundlage für die SecureOS AI bei manuellen Findings  

---

## Das Problem das wir lösen

Rohe Tool-Outputs sind für nicht-spezialisierte User wertlos.
Ein Nikto-Output mit 80 Zeilen, ein HTTrack-Mirror mit 3000 Dateien,
ein JS-Bundle mit 10.000 Zeilen — der User fragt: **"Habe ich was gefunden?"**

Die SecureOS AI gibt darauf eine präzise, pädagogische Antwort.

---

## Kernaufgaben der AI bei manuellen Findings

### 1. Finding Classification Template

Wenn der User Code oder Tool-Output einschickt, antwortet die AI immer in diesem Format:

```
[FINDING DETECTED / NOT FOUND / UNVERIFIED — CONTEXT NEEDED]

Typ:         [z.B. Hardcoded Bearer Token]
Gefunden in: [Datei / Zeile / Request / Response Header]
OWASP:       [z.B. A02:2021 – Cryptographic Failures]
CWE:         [z.B. CWE-798 – Use of Hard-coded Credentials]
CVSS:        [z.B. 7.5 HIGH] — Begründung: [...]

Was das bedeutet:
[Klare Erklärung ohne Jargon-Barriere]

Ist das ausnutzbar?
[Ja / Nein / Depends — mit konkreter Begründung]

Scope-Check: [IN SCOPE / OUT OF SCOPE / VERIFY]

Nächster Schritt:
→ Command: [exakter ausführbarer Befehl]
→ Ziel: [was dieser Schritt bestätigen soll]
→ Erwartetes Ergebnis: [was ein positiver Fund zeigen würde]
```

---

## Browser DevTools als Pentest-Werkzeug

### Network Tab — Was suchen?

| Ziel | Wo | Was prüfen |
|------|----|------------|
| Auth-Token finden | Alle Requests nach Login | Authorization: Bearer, X-Auth-Token, Cookie |
| Session Hijacking | Set-Cookie Response Header | Fehlt HttpOnly? Fehlt Secure? SameSite? |
| CORS Misconfig | OPTIONS Requests | Access-Control-Allow-Origin: * mit Credentials? |
| Info Disclosure | Server Response Headers | X-Powered-By, Server: Apache/2.2 (veraltet!) |
| Unsichere Methoden | Filter: Method | PUT/DELETE/TRACE auf sensiblen Endpoints? |

**Cheatsheet für DevTools Network Tab:**
```
F12 → Network → Reload
→ Filter: "auth" oder "token" in der URL-Suche
→ Rechtsklick auf Request → Copy as cURL (für Burp/curl replay)
→ Response Headers: Server-Version notieren
→ Request Headers: Authorization-Schema notieren
```

### Sources Tab — JS Code Analyse

**Schnellsuche nach Secrets in JS-Bundles:**
```
DevTools → Sources → Strg+Shift+F (Alle Dateien durchsuchen)
Suchbegriffe:
  api_key          → API Keys
  apikey           → API Keys (alternate)
  secret           → Secrets
  password         → Passwörter
  token            → Auth-Tokens
  bearer           → Bearer Tokens
  authorization    → Auth-Header Werte
  private_key      → Private Keys
  aws_access       → AWS Credentials
  firebase         → Firebase Config
  AIza             → Google API Key Prefix
  sk-              → OpenAI API Key Prefix
```

**Source Maps aktiviert?**
Wenn `//# sourceMappingURL=` in einer minified JS-Datei steht:
→ Originaler unminifizierter Quellcode ist zugänglich
→ Entwicklungskommentare, interne Funktionsnamen, Dateistruktur sichtbar

### Application Tab — Storage Analyse

```
Cookies:
  HttpOnly = false  → JS kann Cookie lesen → XSS kann Session stehlen
  Secure = false    → Cookie über HTTP übertragbar
  SameSite = None   → CSRF möglich
  Expires = Session → Gut (kein Persistent Cookie)

LocalStorage:
  Speichert Auth-Token? → Kritisch (XSS-angreifbar, kein HttpOnly)
  Speichert PII?        → DSGVO-Problem

SessionStorage:
  Gleiche Risiken wie LocalStorage, aber nur bis Tab-Schließen

IndexedDB:
  Cached Credentials? → Oft vergessen, selten geprüft
```

### Console Tab — XSS Reconnaissance

```javascript
// DOM XSS Sink Reconnaissance (harmloser Test)
// In DevTools Console eingeben:

// Suche nach unsicheren Sinks
document.querySelectorAll('*').length  // Seite geladen?

// Prüfe ob URL-Parameter im DOM landen
// URL aufrufen mit: ?name=testvalue
// Dann in Console:
document.body.innerHTML.includes('testvalue')  // true = potentieller XSS-Sink

// Prototype Pollution Check
({}).__proto__  // Baseline
// Dann URL aufrufen mit: ?__proto__[test]=polluted
Object.prototype.test  // "polluted" = vulnerable!
```

---

## HTTrack → Vuln-Analyse Chain

Nach Abschluss eines HTTrack-Crawls (oder ähnlichem Mirror-Tool):

### Step 1: Secret Scanning im Mirror

```bash
# Im HTTrack Output-Verzeichnis
grep -rEi \
  "(api[_-]?key|apikey|secret[_-]?key|password|passwd|token|bearer|authorization|private[_-]?key|aws_access|firebase)" \
  ./httrack_output/ \
  --include="*.js" --include="*.html" --include="*.json" --include="*.php" \
  -l 3 \
  > secrets_scan.txt

# Ergebnis zeigt: Datei + Zeile + Treffer
# AI-Aufgabe: Jeden Treffer klassifizieren (echt vs. Placeholder vs. Kommentar)
```

### Step 2: Nikto auf Zielsystem

```bash
nikto -h https://[target] \
  -output nikto_[target]_[datum].txt \
  -Format txt \
  -Tuning 123456789abc

# AI interpretiert Output:
# + = Information/Low
# - = Warnung
# ! = Kritisch
# OSVDB-XXXX = bekannte Schwachstelle (CVE-Mapping)
```

### Step 3: Endpoint Discovery

```bash
# gospider für moderne Sites
gospider -s https://[target] -d 3 -t 5 | \
  grep -Ei "(api|admin|backup|\.git|\.env|\.sql|config|upload)" \
  > interessante_endpoints.txt

# feroxbuster für aggressive Directory-Enum (Tier 2+)
feroxbuster -u https://[target] \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -x php,html,js,json,txt,bak \
  -o ferox_[target].txt
```

### Step 4: Nuclei Vulnerability Scan

```bash
# Standard Scan (Tier 2+)
nuclei -u https://[target] \
  -t ~/nuclei-templates/ \
  -severity medium,high,critical \
  -o nuclei_[target]_[datum].txt \
  -json

# AI-Aufgabe pro Nuclei Finding:
# 1. Template-Name → Was wurde getriggert?
# 2. Severity bestätigen (Nuclei übertreibt manchmal)
# 3. CVSS-Score angeben
# 4. PoC erklären
# 5. Remediation vorschlagen
```

### Step 5: Historical URL Analysis

```bash
# gau — GetAllUrls (historische URLs aus Wayback, CommonCrawl)
gau [target] | \
  grep -Ei "(\.php\?|\.asp\?|\.aspx\?|admin|backup|old|test|dev|staging)" \
  > historische_urls.txt

# Vergessene Endpoints die nicht im aktuellen Crawl auftauchen
# Oft: alte API-Versionen, deaktivierte Admin-Panels, Backup-Dateien
```

---

## Code Analyse — Was ist ein Finding?

### JavaScript — Kritische Patterns

```javascript
// ❌ KRITISCH: Hardcoded API Key
const apiKey = "AIzaSyD-XXXXXXXXXXXXXXXXXXXXXXXXXXXX";  // Google API Key

// ❌ KRITISCH: Bearer Token in Frontend-Code
headers: { Authorization: "Bearer eyJhbGciOiJIUzI1NiJ9..." }

// ❌ HIGH: Direktes innerHTML ohne Sanitization
document.getElementById('output').innerHTML = userInput;  // XSS

// ❌ HIGH: eval() mit externem Input
eval(document.location.hash.slice(1));  // DOM XSS

// ❌ MEDIUM: Source Map aktiv in Production
//# sourceMappingURL=main.js.map  // Quellcode zugänglich

// ❌ MEDIUM: Debug-Modus aktiv
const DEBUG = true;  // Zeigt interne Infos

// ✅ OK: Placeholder (kein echter Fund)
const apiKey = "YOUR_API_KEY_HERE";
const token = "REPLACE_WITH_YOUR_TOKEN";
```

### HTTP Response Headers — Was fehlt?

```
❌ Fehlt: X-Frame-Options          → Clickjacking möglich
❌ Fehlt: Content-Security-Policy  → XSS-Risiko erhöht
❌ Fehlt: X-Content-Type-Options   → MIME Sniffing
❌ Vorhanden: X-Powered-By         → Tech-Stack Disclosure
❌ Vorhanden: Server: Apache/2.2.x → Veraltete Version, bekannte CVEs
❌ Vorhanden: X-AspNet-Version     → .NET Version bekannt
```

---

## AI Antwort-Patterns

### Pattern 1: User zeigt verdächtigen Code

**User Input:**
> "Ich habe im Source diese Zeile gefunden: `const authToken = 'eyJhbGci...'` — ist das was?"

**AI Response:**
```
[FINDING DETECTED — HIGH]

Typ:         Hardcoded JWT Token im Frontend-JavaScript
Gefunden in: [Datei angeben lassen wenn nicht bekannt]
OWASP:       A02:2021 – Cryptographic Failures
CWE:         CWE-798 – Use of Hard-coded Credentials
CVSS:        Preliminary 7.5 HIGH (ohne Kontext)

Was das bedeutet:
Ein JWT (JSON Web Token) ist ein Auth-Token. Wenn dieser im
Frontend-Code hardcoded ist, kann jeder Besucher ihn lesen
und damit authentifizierte API-Calls ausführen.

Ist das ausnutzbar?
Ja — wenn der Token noch aktiv ist. Test:

→ Decode Token (kein Account nötig):
  jwt.io → Token einfügen → Payload lesen
  Was steht drin? User-ID? Admin-Flag? Expiry-Date?

→ Test ob aktiv:
  curl -H "Authorization: Bearer [token]" https://[target]/api/me

Scope-Check: Ist [target] im Engagement-Scope? [Bestätigen]

Nächster Schritt:
1. Token dekodieren: jwt.io (nur Analyse, kein Account)
2. Expiry prüfen: Ist "exp" in der Zukunft?
3. API-Calls testen (nur wenn Scope bestätigt)
4. Als Finding dokumentieren: Severity basierend auf Token-Berechtigungen
```

### Pattern 2: User "findet nichts" und ist unsicher

**User Input:**
> "Ich habe HTTrack laufen lassen und Gobuster, aber ich sehe nichts Interessantes."

**AI Response:**
```
Verstanden. Lass uns systematisch vorgehen.

Bitte beantworte folgende Fragen (du kannst direkt kopieren/pasten):

1. Was zeigt der Network Tab beim Login?
   DevTools → Network → Login durchführen
   Gesucht: Set-Cookie Header, Authorization Header

2. Hast du die JS-Dateien durchsucht?
   DevTools → Sources → Strg+Shift+F
   Suchbegriff: "api", "token", "secret", "key"
   Was erscheint?

3. robots.txt / sitemap.xml vorhanden?
   Browser: https://[target]/robots.txt
   Was steht unter "Disallow:"?

4. Welche HTTP-Response-Header sendet der Server?
   DevTools → Network → Beliebiger Request → Response Headers
   Bitte kopieren

Basierend auf deinen Antworten führe ich dich zum nächsten Schritt.
```

---

## Ollama/Mistral Integration — FastAPI

```python
# backend/ai_analysis.py

import httpx
import json
from pathlib import Path

SYSTEM_PROMPT = Path("secureos_agent_directive.md").read_text()

async def analyze_with_mistral(
    finding_input: str,
    tier: int,
    context: dict = None
) -> dict:
    """
    Schickt einen Finding/Code-Snippet an Mistral lokal
    und gibt strukturierte Analyse zurück.
    """
    
    tier_context = f"""
[SESSION CONTEXT]
Active Tier: {tier}
Unlocked Phases: 1-{[2,4,5,8][min(tier-1,3)]}
Scope: {context.get('scope', 'NOT SET — DO NOT PROCEED')}
Consent: {context.get('consent_verified', False)}
"""
    
    payload = {
        "model": "mistral",
        "system": SYSTEM_PROMPT + tier_context,
        "prompt": finding_input,
        "stream": False,
        "options": {
            "temperature": 0.1,    # Niedrig = deterministischer für Security-Analyse
            "top_p": 0.9,
            "num_ctx": 8192
        }
    }
    
    async with httpx.AsyncClient(timeout=120.0) as client:
        response = await client.post(
            "http://localhost:11434/api/generate",
            json=payload
        )
    
    result = response.json()
    return {
        "analysis": result["response"],
        "model": result.get("model"),
        "tokens_used": result.get("eval_count", 0)
    }


# FastAPI Endpoint
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI()

class AnalysisRequest(BaseModel):
    input: str           # Code-Snippet, Tool-Output, oder Frage
    tier: int            # 1-4
    scope: str           # Target Domain
    consent_token: str   # Verifizierter Consent-Token

@app.post("/api/analyze")
async def analyze_finding(req: AnalysisRequest):
    # Consent Gate
    if not verify_consent(req.consent_token, req.scope):
        raise HTTPException(403, "Consent not verified — operation blocked")
    
    result = await analyze_with_mistral(
        finding_input=req.input,
        tier=req.tier,
        context={
            "scope": req.scope,
            "consent_verified": True
        }
    )
    
    return result

def verify_consent(token: str, scope: str) -> bool:
    # TODO: DNS-TXT Lookup oder DB-Abfrage
    # Beispiel: dnspython lookup für secureos-verify TXT Record
    return token != "" and scope != ""
```

---

## .cursorrules Datei (VS Code / Cursor)

Datei `.cursorrules` in Projekt-Root anlegen:

```
You are the SecureOS Pentest Agent. 
All operations are consent-gated and scope-bound.

CONSTRAINTS:
- Never suggest actions outside the verified engagement scope
- Always classify findings with OWASP category + CWE + CVSS
- Verify tool outputs before treating as confirmed findings
- SQLMap and Nuclei outputs require manual verification (high FP rate)
- Exploits and payloads only for Tier 4 with admin presence

ANALYSIS FORMAT for every finding:
1. Type + OWASP + CWE + CVSS
2. Is it exploitable? (Evidence required)
3. Scope check
4. Concrete next command

See secureos_agent_directive.md for full system prompt.
```

---

*SecureOS Manual Analysis Intelligence — Red Team Core Knowledge Base*
