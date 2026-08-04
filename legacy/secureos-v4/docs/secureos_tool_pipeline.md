# SecureOS — Tool Pipeline Reference (100+ Tools)

**Datei:** `secureos_tool_pipeline.md`  
**Zweck:** Vollständige Tool-Liste, nach Phasen sortiert, mit Tier-Zuordnung und AI-Interpretation  

---

## Phase 1 — RECON (Tier 1+) ~30 Tools

### OSINT & Domain Intelligence
```
amass enum -d [target]               # Subdomain-Enumeration (passiv + aktiv)
subfinder -d [target] -o subs.txt    # Subfinder (ProjectDiscovery)
dnsx -l subs.txt -a -cname -o dns.txt  # DNS-Auflösung der Subdomains
theHarvester -d [target] -b all      # Email, Name, Host-OSINT
shodan search hostname:[target]      # Shodan (exposed services)
censys search [target]               # Censys (alternative zu Shodan)
```

### Historical & Passive
```
waybackurls [target]                 # Wayback Machine URLs
gau [target]                         # GetAllURLs (Wayback + CommonCrawl + AlienVault)
github-dorker -d [target]            # GitHub Dorks für Target
gitdorker -d [target]                # Alternativ
trufflehog github --org=[org]        # Secret Scanning in GitHub Repos
```

### Google Dorks (manuell + AI-gestützt)
```
site:[target] filetype:env           # .env Dateien
site:[target] filetype:sql           # SQL-Dumps
site:[target] inurl:admin            # Admin-Panels
site:[target] intitle:"index of"     # Directory Listings
site:[target] "api_key" OR "apikey"  # Hardcoded Keys in indexierten Seiten
```

**AI-Aufgabe Phase 1:** Erstellt strukturierte Asset-Liste mit: Domains, IPs, Subdomains, Email-Adressen, Tech-Stack-Hinweise aus OSINT

---

## Phase 2 — FINGERPRINT (Tier 1+)

### Tech-Stack Detection
```
whatweb [target] -a 3               # CMS, Frameworks, Server
wappalyzer-cli [target]             # Browser-basierter Tech-Stack (CLI-Version)
httpx -l subs.txt -tech-detect      # Bulk Tech-Detection für alle Subdomains
```

### Port & Service Scanning
```
nmap -sV -sC -O -p- [target]       # Full Port Scan + Service Version + OS Detection
nmap -sV --script=banner [target]  # Banner Grabbing
masscan -p0-65535 [target] --rate=1000  # Schneller Mass-Scan
```

### WAF / CDN Detection
```
wafw00f [target]                    # WAF-Erkennung (Cloudflare, ModSecurity, etc.)
identywaf -u [target]               # Alternative WAF-Detection
cloudcheck [target]                 # CDN-Erkennung
```

**AI-Aufgabe Phase 2:** Erstellt Tech-Stack-Profil. Ordnet erkannte Versionen bekannten CVEs zu. Flaggt veraltete Software.

---

## Phase 3 — ENUMERATION (Tier 2+)

### Directory & File Discovery
```
gobuster dir -u [target] -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,js,json,bak,txt
ffuf -w wordlist.txt -u [target]/FUZZ -mc 200,301,302,403
feroxbuster -u [target] -w wordlist.txt -x php,html,js,json
```

### Web Crawling & Spidering
```
gospider -s [target] -d 3 -t 10     # Schneller Web-Spider
katana -u [target] -d 5             # ProjectDiscovery Crawler
hakrawler -url [target] -depth 3    # Hakrawler (passiv)
httrack [target] -O ./mirror/ -r3   # Vollständiger Website-Mirror
```

### API Endpoint Discovery
```
kiterunner scan urls -u [target]    # API-Endpoint Bruteforce (ProjectDiscovery)
arjun -u [target]/api               # HTTP Parameter Discovery
```

### User Enumeration
```
# Über Avatar/Profile Endpoint (wie bei hubba.cc gefunden):
for i in {1..1000}; do curl -s -o /dev/null -w "%{http_code} $i\n" [target]/api/avatar/$i; done

# Username Enumeration via Response-Zeit-Unterschied:
hydra -L userlist.txt -p dummy [target] http-form-post "/login:user=^USER^&pass=^PASS^:Invalid"
```

**AI-Aufgabe Phase 3:** Kategorisiert Endpoints nach Interessensgrad. Flaggt: /admin, /api/v*, /.git, /.env, /backup, /upload, /config

---

## Phase 4 — VULNERABILITY SCAN (Tier 2+)

### Automated Vuln Scanning
```
nuclei -u [target] -t ~/nuclei-templates/ -severity medium,high,critical -o nuclei_out.txt
nikto -h [target] -o nikto_out.txt -Format txt
wpscan --url [target] --enumerate u,p,t  # WordPress only
droopescan scan [target]                  # Drupal/Silverstripe
```

### SQL Injection
```
# WICHTIG: Immer manuell verifizieren — FP-Rate ~30%
sqlmap -u "[target]/page?id=1" --dbs --batch --random-agent
sqlmap -u "[target]" --forms --crawl=3 --batch
```

### XSS Detection
```
dalfox url [target]                  # XSS Scanner
xsstrike -u "[target]/search?q=test" # XSS Strike
kxss -u [target]                     # Passive XSS
```

### SSL/TLS Analysis
```
testssl.sh [target]                  # TLS-Konfiguration, Cipher Suites, Zertifikat
sslscan [target]                     # Alternative
sslyze [target]                      # Python-basiert
```

### Spezial-Tools (Project Discovery Stack)
```
nuclei -u [target] -t exposures/      # Exposed Dateien
nuclei -u [target] -t cves/           # Nur CVE-Templates
nuclei -u [target] -t misconfiguration/  # Misconfigurations
notify -bulk -provider telegram       # Notifications bei Nuclei-Hits
```

**AI-Aufgabe Phase 4:** Bewertet jeden Scan-Output. Unterscheidet echte Findings von False Positives. Ordnet CVSS zu. Priorisiert nach Exploitability.

---

## Phase 5 — ANALYSIS (Tier 3+)

### Manuelle Code-Analyse Tools
```
semgrep --config=p/security-audit ./  # Static Analysis
bandit -r . -f json                   # Python Security Linter
eslint --plugin security ./           # JS Security Linting
```

### Traffic Interception & Analyse
```
burpsuite                            # Proxy + Manual Testing (Community/Pro)
mitmproxy -p 8080                    # Open-Source Proxy
caido                                # Moderner Burp-Alternativ
```

### Secret Scanning
```
trufflehog filesystem ./             # Lokaler Mirror
gitleaks detect --source ./          # Git-History Secrets
detect-secrets scan ./               # Yelp's Secret Scanner
semgrep --config=p/secrets ./        # Semgrep Secrets Ruleset
```

### AI-gestützte Analyse (Ollama/Mistral lokal)
```python
# Direkte Code-Analyse via Ollama API
ollama run mistral "Analysiere diesen JavaScript Code auf Security-Issues: [code]"

# Oder via SecureOS Backend:
POST /api/analyze
{
  "input": "[code oder tool-output]",
  "tier": 3,
  "scope": "example.com",
  "consent_token": "verified-token"
}
```

---

## Phase 6–7 — EXPLOIT (Tier 4 + Admin)

**⛔ Nur mit Admin-Anwesenheit und doppeltem Consent-Signing**

### Exploitation Frameworks
```
msfconsole                           # Metasploit
searchsploit [technology] [version]  # Exploit-DB Suche
exploit-db.com                       # Web-Interface

# Custom PoC Development:
python3 exploit.py [target]          # Maßgeschneiderter PoC
```

### Post-Exploitation (nach erfolgreichem Exploit)
```
# Nur zur Demonstration des Impact für den Report
# Nie produktive Daten exfiltrieren
# Screenshots für Proof-of-Concept ausreichend
```

---

## Phase 8 — REPORT (alle Tier)

### Report-Generierung
```
# SecureOS eigener Report-Generator (Python)
python3 secureos_report.py \
  --findings findings.json \
  --template professional \
  --output "Pentest_Report_[target]_[datum].pdf"
```

### Externe Report-Tools
```
pwndoc                               # Open-Source Pentest Report Tool
ghostwriter                          # Pentest Report Management
sysreptor                            # Moderne Alternative
```

---

## Spezial-Images & Custom Setups

### Project Discovery Stack (Kali oder eigenes Image)
```bash
# Installation
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest

# Nuclei Templates aktuell halten
nuclei -update-templates
```

### Athena OS Spezifische Tools
```
# Athena OS kommt mit kategorisierten Tool-Sets
# Cyber Defense → Blue Team Tools
# Pentesting → Red Team Tools
# Forensics → Digital Forensics
```

---

## Schnell-Referenz: Tool → Vulnerability Type

| Vulnerability | Tool(s) | Phase |
|---------------|---------|-------|
| SQL Injection | sqlmap, ghauri | 4 |
| XSS | dalfox, xsstrike, kxss | 4 |
| SSRF | nuclei (ssrf templates), ssrfmap | 4 |
| LFI/RFI | ffuf + LFI wordlist, liffy | 4 |
| Open Redirect | nuclei, manual testing | 4 |
| CSRF | burp, caido (manual) | 5 |
| IDOR | manuelle Analyse + arjun | 5 |
| JWT Issues | jwt_tool | 5 |
| Secret Leaks | trufflehog, gitleaks, semgrep | 3/5 |
| Subdomain Takeover | subjack, nuclei (takeover) | 1/4 |
| SSL/TLS Issues | testssl.sh, sslscan | 4 |
| Directory Listing | gobuster, ffuf, feroxbuster | 3 |
| Default Credentials | hydra, medusa (nur Scope!) | 4 |
| CVE-Based | nuclei (cves/), searchsploit | 4 |
| Race Condition | turbo intruder (Burp), custom | 5/6 |

---

*SecureOS Tool Pipeline Reference — Consent-Gated Ethical Pentesting*
