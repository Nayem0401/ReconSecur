"use strict";

// Aether Tool-Adapter: erkennt Security-Tools gleichzeitig unter Windows und in
// WSL2-Distributionen (z. B. Kali). Ausfuehrung ist strikt allowlist-basiert und
// nutzt argumentbasierte spawn-APIs ohne Shell-Interpolation von Nutzereingaben.

const { spawn } = require("node:child_process");
const fs = require("node:fs");
const path = require("node:path");

const NAME_RE = /^[a-z0-9][a-z0-9._-]*$/;
const DISTRO_RE = /^[A-Za-z0-9._-]+$/;
const INVENTORY_TTL_MS = 60_000;

// Vordefinierte Kali-Wortlisten (feste Auswahl statt freier Pfadeingabe).
const WORDLISTS = [
  "/usr/share/wordlists/dirb/common.txt",
  "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",
  "/usr/share/seclists/Discovery/Web-Content/common.txt",
];

// Deklaratives Tool-Schema, fokussiert auf Red-Team Web Application. Einzige
// Wahrheitsquelle fuer Allowlist, Katalog (Client-Rendering) und Argumentbau.
// Jede Option ist typisiert; buildToolCommand erzeugt daraus serverseitig die
// Argumente. Keine rohen Args/Shell vom Client, kein Freitext ausser strikten Mustern.
const PROFILES = {
  // 🔍 Recon & Fingerprinting
  whatweb: {
    category: "🔍 Recon & Fingerprinting", summary: "Webtechnologien und Frameworks erkennen",
    target: { kind: "url", placeholder: "https://ziel.example" },
    flags: [
      { key: "aggression", flag: "-a", type: "enum", values: ["1", "3", "4"], default: "1", label: "Aggression", desc: "Scan-Tiefe: 1 passiv, 3 aktiv, 4 aggressiv." },
      { key: "verbose", flag: "-v", type: "boolean", label: "Verbose", desc: "Ausfuehrliche Ausgabe je Plugin." },
    ],
  },
  httpx: {
    category: "🔍 Recon & Fingerprinting", summary: "HTTP-Dienste pruefen und Metadaten erfassen",
    target: { kind: "url", arg: "-u", placeholder: "https://ziel.example" },
    flags: [
      { key: "title", flag: "-title", type: "boolean", default: true, label: "Title", desc: "Seitentitel ausgeben." },
      { key: "statuscode", flag: "-sc", type: "boolean", default: true, label: "Status Code", desc: "HTTP-Statuscode anzeigen." },
      { key: "tech", flag: "-td", type: "boolean", label: "Tech Detect", desc: "Erkannte Technologien anzeigen." },
      { key: "server", flag: "-server", type: "boolean", label: "Web Server", desc: "Server-Header ausgeben." },
    ],
  },
  wafw00f: {
    category: "🔍 Recon & Fingerprinting", summary: "Web Application Firewalls erkennen",
    target: { kind: "url", placeholder: "https://ziel.example" },
    flags: [{ key: "findall", flag: "-a", type: "boolean", label: "Alle WAFs", desc: "Auf saemtliche bekannten WAFs pruefen." }],
  },
  whois: {
    category: "🔍 Recon & Fingerprinting", summary: "Registrierungsdaten einer Domain abfragen",
    target: { kind: "domain", placeholder: "ziel.example" }, flags: [],
  },
  dig: {
    category: "🔍 Recon & Fingerprinting", summary: "DNS- und E-Mail-Security-Records (SPF, DMARC, DKIM) abfragen",
    target: { kind: "domain", placeholder: "ziel.example", note: "Scope + TXT liefert SPF/DMARC/DKIM." },
    flags: [
      { key: "scope", role: "prefix", type: "enum", values: ["(root)", "_dmarc", "default._domainkey"], default: "(root)", label: "Scope", desc: "(root)=Domain (SPF), _dmarc=DMARC-Policy, default._domainkey=DKIM-Selector." },
      { key: "type", flag: "-t", type: "enum", values: ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"], default: "TXT", label: "Record-Typ", desc: "TXT liefert SPF/DMARC/DKIM; MX zeigt Mailserver." },
      { key: "short", flag: "+short", type: "boolean", default: true, label: "Short", desc: "Nur die Ergebniswerte anzeigen." },
    ],
  },

  // 🌐 Subdomain & OSINT
  subfinder: {
    category: "🌐 Subdomain & OSINT", summary: "Passive Subdomain-Erkennung",
    target: { kind: "domain", arg: "-d", placeholder: "ziel.example" },
    flags: [{ key: "silent", flag: "-silent", type: "boolean", default: true, label: "Silent", desc: "Nur gefundene Subdomains ausgeben." }],
  },
  sublist3r: {
    category: "🌐 Subdomain & OSINT", summary: "Subdomains aus offenen Quellen sammeln",
    target: { kind: "domain", arg: "-d", placeholder: "ziel.example" }, flags: [],
  },
  amass: {
    category: "🌐 Subdomain & OSINT", summary: "Attack-Surface- und DNS-Mapping",
    prefix: ["enum"], target: { kind: "domain", arg: "-d", placeholder: "ziel.example" },
    flags: [{ key: "passive", flag: "-passive", type: "boolean", default: true, label: "Passiv", desc: "Nur passive Quellen, kein aktives DNS." }],
  },
  assetfinder: {
    category: "🌐 Subdomain & OSINT", summary: "Zugehoerige Domains und Subdomains finden",
    target: { kind: "domain", placeholder: "ziel.example" },
    flags: [{ key: "subsonly", flag: "--subs-only", type: "boolean", default: true, label: "Nur Subdomains", desc: "Ausgabe auf Subdomains beschraenken." }],
  },
  theharvester: {
    category: "🌐 Subdomain & OSINT", summary: "Offene Quellen nach Domain-Artefakten durchsuchen",
    target: { kind: "domain", arg: "-d", placeholder: "ziel.example" },
    flags: [{ key: "source", flag: "-b", type: "enum", values: ["duckduckgo", "bing", "crtsh", "hackertarget"], default: "duckduckgo", label: "Quelle", desc: "Datenquelle fuer die Suche." }],
  },
  dnsrecon: {
    category: "🌐 Subdomain & OSINT", summary: "DNS-Eintraege und Delegation untersuchen",
    target: { kind: "domain", arg: "-d", placeholder: "ziel.example" }, flags: [],
  },
  dnsenum: {
    category: "🌐 Subdomain & OSINT", summary: "Umfassende DNS-Enumeration inkl. MX/NS/Zonetransfer-Test",
    target: { kind: "domain", placeholder: "ziel.example" },
    flags: [{ key: "noreverse", flag: "--noreverse", type: "boolean", default: true, label: "Kein Reverse", desc: "Reverse-Lookups ueberspringen (schneller)." }],
  },

  // 📂 Content Discovery
  gobuster: {
    category: "📂 Content Discovery", summary: "Webpfade mit Wortlisten finden",
    prefix: ["dir"], target: { kind: "url", arg: "-u", placeholder: "https://ziel.example" },
    flags: [{ key: "wordlist", flag: "-w", type: "enum", values: WORDLISTS, default: WORDLISTS[0], label: "Wortliste", desc: "Kali-Wortliste fuer Pfade." }],
  },
  ffuf: {
    category: "📂 Content Discovery", summary: "HTTP-Fuzzing und Content Discovery",
    target: { kind: "url", arg: "-u", placeholder: "https://ziel.example/FUZZ", note: "FUZZ markiert die Fuzzing-Stelle." },
    flags: [
      { key: "wordlist", flag: "-w", type: "enum", values: WORDLISTS, default: WORDLISTS[0], label: "Wortliste", desc: "Werte fuer FUZZ." },
      { key: "matchcodes", flag: "-mc", type: "string", pattern: "^\\d{3}(,\\d{3})*$", placeholder: "200,301,403", label: "Match Codes", desc: "Nur diese HTTP-Statuscodes anzeigen." },
    ],
  },
  dirb: {
    category: "📂 Content Discovery", summary: "Webverzeichnisse mit Wortlisten finden",
    target: { kind: "url", placeholder: "https://ziel.example" },
    positional: [{ key: "wordlist", type: "enum", values: WORDLISTS, default: WORDLISTS[0], label: "Wortliste", desc: "Kali-Wortliste fuer Pfade." }],
  },
  feroxbuster: {
    category: "📂 Content Discovery", summary: "Rekursive Web-Content-Erkennung",
    target: { kind: "url", arg: "-u", placeholder: "https://ziel.example" },
    flags: [{ key: "wordlist", flag: "-w", type: "enum", values: WORDLISTS, default: WORDLISTS[0], label: "Wortliste", desc: "Kali-Wortliste fuer Pfade." }],
  },

  // 🛡️ Vulnerability Scanning
  nikto: {
    category: "🛡️ Vulnerability Scanning", summary: "Webserver auf bekannte Fehlkonfigurationen pruefen",
    target: { kind: "url", arg: "-h", placeholder: "https://ziel.example" },
    flags: [{ key: "ssl", flag: "-ssl", type: "boolean", label: "SSL erzwingen", desc: "TLS-Verbindung erzwingen." }],
  },
  nuclei: {
    category: "🛡️ Vulnerability Scanning", summary: "Template-basierte Sicherheitspruefungen",
    target: { kind: "url", arg: "-u", placeholder: "https://ziel.example" },
    flags: [{ key: "severity", flag: "-severity", type: "enum", values: ["info", "low", "medium", "high", "critical"], default: "medium", label: "Severity", desc: "Mindest-Schweregrad der Templates." }],
  },
  wpscan: {
    category: "🛡️ Vulnerability Scanning", summary: "WordPress-Installationen defensiv pruefen",
    target: { kind: "url", arg: "--url", placeholder: "https://ziel.example" },
    flags: [{ key: "enumerate", flag: "-e", type: "enum", values: ["vp", "vt", "u"], default: "vp", label: "Enumerate", desc: "vp=Vuln-Plugins, vt=Vuln-Themes, u=User." }],
  },

  // 💉 Injection
  sqlmap: {
    category: "💉 Injection", summary: "SQL-Injection in autorisierten Zielen validieren",
    target: { kind: "url", arg: "-u", placeholder: "https://ziel.example/?id=1", note: "URL mit dem zu pruefenden Parameter." },
    flags: [
      { key: "risk", flag: "--risk", type: "integer", join: "equals", min: 1, max: 3, default: 1, label: "Risk (1–3)", desc: "Risiko der Payloads. SQLMap kennt keinen Wert 5." },
      { key: "level", flag: "--level", type: "integer", join: "equals", min: 1, max: 5, default: 1, label: "Level (1–5)", desc: "Umfang der Tests und Parameter." },
      { key: "batch", flag: "--batch", type: "boolean", default: true, label: "Batch", desc: "Nicht-interaktiv mit Standardantworten." },
    ],
  },

  // 🔒 TLS / SSL
  sslscan: {
    category: "🔒 TLS / SSL", summary: "TLS-Protokolle und Cipher Suites pruefen",
    target: { kind: "host", placeholder: "ziel.example" },
    flags: [{ key: "nofailed", flag: "--no-failed", type: "boolean", default: true, label: "Nur akzeptierte", desc: "Abgelehnte Cipher ausblenden." }],
  },
  sslyze: {
    category: "🔒 TLS / SSL", summary: "TLS-Konfiguration analysieren",
    target: { kind: "host", placeholder: "ziel.example" }, flags: [],
  },
  "testssl.sh": {
    category: "🔒 TLS / SSL", summary: "Umfassende TLS-Konfigurationspruefung",
    target: { kind: "url", placeholder: "https://ziel.example" }, flags: [],
  },
  openssl: {
    category: "🔒 TLS / SSL", summary: "TLS-Verbindung und Zertifikat untersuchen",
    prefix: ["s_client"], target: { kind: "hostport", arg: "-connect", placeholder: "ziel.example" },
    sni: true, flags: [],
  },

  // 🚀 HTTP Client
  curl: {
    category: "🚀 HTTP Client", summary: "HTTP-Anfragen senden",
    target: { kind: "url", placeholder: "https://ziel.example" },
    flags: [
      { key: "head", flag: "-I", type: "boolean", default: true, label: "Nur Header", desc: "Nur Response-Header abrufen." },
      { key: "follow", flag: "-L", type: "boolean", default: true, label: "Redirects folgen", desc: "HTTP-Weiterleitungen folgen." },
      { key: "method", flag: "-X", type: "enum", values: ["GET", "POST", "HEAD", "OPTIONS"], label: "Methode", desc: "HTTP-Methode festlegen." },
    ],
  },
  wget: {
    category: "🚀 HTTP Client", summary: "Webressourcen abrufen",
    target: { kind: "url", placeholder: "https://ziel.example" },
    flags: [{ key: "spider", flag: "--spider", type: "boolean", default: true, label: "Spider", desc: "Nur pruefen, nichts speichern." }],
  },

  // 🛰️ Port & Service
  nmap: {
    category: "🛰️ Port & Service", summary: "Host-, Port- und Service-Erkennung",
    target: { kind: "host", placeholder: "ziel.example" },
    flags: [
      { key: "version", flag: "-sV", type: "boolean", default: true, label: "Service-Version", desc: "Dienstversionen erkennen." },
      { key: "ports", flag: "-p", type: "string", pattern: "^\\d{1,5}(-\\d{1,5})?(,\\d{1,5}(-\\d{1,5})?)*$", default: "1-1000", placeholder: "80,443,1-1000", label: "Ports", desc: "Ports, Bereiche oder Liste." },
      { key: "timing", flag: "-T", type: "integer", join: "append", min: 0, max: 5, default: 3, label: "Timing (0–5)", desc: "Hoeher = schneller, auffaelliger." },
    ],
  },
};

const ALLOWLIST = Object.keys(PROFILES).filter((name) => NAME_RE.test(name));
const ALLOW = new Set(ALLOWLIST);

// Assessment-Phasen. Phase 1 buendelt bewusst die 15 Tools, die am meisten
// Informationen sammeln (DNS/OSINT/Fingerprint/Portscan) und laeuft immer zuerst.
const PHASES = {
  1: "① Information Gathering",
  2: "② Content Discovery",
  3: "③ TLS / SSL",
  4: "④ Vuln & Injection",
};
const PHASE_BY_TOOL = {
  // Phase 1 – die 15 staerksten Informationssammler (immer zuerst)
  nmap: 1, dig: 1, dnsenum: 1, dnsrecon: 1, whois: 1, subfinder: 1, sublist3r: 1,
  amass: 1, assetfinder: 1, theharvester: 1, httpx: 1, whatweb: 1, wafw00f: 1,
  curl: 1, wget: 1,
  gobuster: 2, ffuf: 2, dirb: 2, feroxbuster: 2,
  sslscan: 3, sslyze: 3, "testssl.sh": 3, openssl: 3,
  nikto: 4, nuclei: 4, wpscan: 4, sqlmap: 4,
};

function usageLine(f) {
  if (f.role === "prefix") return { flag: `<${f.label}>`, description: f.desc };
  if (f.type === "boolean") return { flag: f.flag, description: f.desc };
  return { flag: `${f.flag || ""} <${f.label}>`.trim(), description: f.desc };
}

const TOOL_CATALOG = ALLOWLIST.map((name) => {
  const p = PROFILES[name];
  const phase = PHASE_BY_TOOL[name] || 4;
  return {
    name, category: p.category, summary: p.summary,
    phase, phaseName: PHASES[phase],
    prefix: p.prefix || [], target: p.target, sni: p.sni || false,
    flags: (p.flags || []).map((f) => ({ ...f })),
    positional: (p.positional || []).map((f) => ({ ...f })),
    usage: [
      ...(p.flags || []).map(usageLine),
      ...(p.positional || []).map((f) => ({ flag: `<${f.label}>`, description: f.desc })),
    ],
  };
});

let inventoryCache = null;

function run(command, args, { timeoutMs = 8000 } = {}) {
  return new Promise((resolve) => {
    const child = spawn(command, args, { windowsHide: true });
    let stdout = "";
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), timeoutMs);

    child.stdout.on("data", (chunk) => { stdout += chunk; });
    child.stderr.on("data", (chunk) => { stderr += chunk; });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ code: -1, stdout, stderr: error.message });
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr });
    });
  });
}

function detectWindowsExecutables() {
  const exts = (process.env.PATHEXT || ".EXE;.BAT;.CMD").split(";").map((e) => e.toLowerCase());
  const dirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  const found = new Set();

  for (const dir of dirs) {
    let entries;
    try {
      entries = fs.readdirSync(dir);
    } catch {
      continue;
    }
    for (const entry of entries) {
      const ext = path.extname(entry).toLowerCase();
      const base = ext ? entry.slice(0, -ext.length) : entry;
      if (ext && exts.includes(ext)) {
        found.add(base.toLowerCase());
      }
    }
  }
  return [...found].sort();
}

async function listWslDistros() {
  const result = await run("wsl.exe", ["-l", "-q"], { timeoutMs: 5000 });
  if (result.code !== 0) return [];
  return result.stdout
    .replace(/\u0000/g, "")
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => DISTRO_RE.test(line));
}

// Alle ausfuehrbaren Namen in den Standard-PATH-Verzeichnissen einer Distro.
// Nutzt `ls` mit direkten Verzeichnis-Argumenten (keine Shell-Interpolation).
async function detectWslExecutables(distro) {
  if (!DISTRO_RE.test(distro)) return [];
  const dirs = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin", "/usr/local/sbin"];
  const result = await run("wsl.exe", ["-d", distro, "--", "ls", "-1", ...dirs], { timeoutMs: 25_000 });
  const found = new Set();
  for (const line of result.stdout.split(/\r?\n/)) {
    const name = line.trim();
    if (name && !name.endsWith(":")) found.add(name);
  }
  return [...found].sort();
}

function withMeta(tools) {
  return { count: tools.length, execReady: tools.filter((t) => ALLOW.has(t)), tools };
}

function requireTarget(value) {
  if (typeof value !== "string" || !value.trim() || value.length > 2048 || /[\r\n\0]/.test(value)) {
    throw new Error("Ungueltiges Tool-Ziel.");
  }
  return value.trim();
}

function integerOption(value, minimum, maximum, fallback) {
  if (value === undefined || value === "") return fallback;
  const number = Number(value);
  if (!Number.isInteger(number) || number < minimum || number > maximum) {
    throw new Error(`Wert muss zwischen ${minimum} und ${maximum} liegen.`);
  }
  return number;
}

function isEnabled(raw, fallback) {
  if (raw === undefined) return !!fallback;
  return raw === true || raw === "true" || raw === "on" || raw === "1";
}

function resolveValue(field, raw) {
  if (field.type === "integer") return integerOption(raw, field.min, field.max, field.default);
  let value = raw === undefined || raw === "" ? field.default : raw;
  if (value === undefined || value === "") return undefined;
  value = String(value);
  if (field.type === "enum" && !field.values.includes(value)) {
    throw new Error(`Ungueltiger Wert fuer ${field.flag || field.label}.`);
  }
  if (field.type === "string" && !new RegExp(field.pattern).test(value)) {
    throw new Error(`Ungueltiger Wert fuer ${field.flag || field.label}.`);
  }
  return value;
}

function emitFlag(args, field, value) {
  const join = field.join || "space";
  if (join === "equals") args.push(`${field.flag}=${value}`);
  else if (join === "append") args.push(`${field.flag}${value}`);
  else args.push(field.flag, String(value));
}

function buildToolCommand(tool, target, options = {}) {
  const profile = PROFILES[tool];
  if (!profile) throw new Error("Dieses Tool besitzt kein sicheres Ausfuehrungsprofil.");
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new Error("Tool-Optionen muessen ein Objekt sein.");
  }
  const safeTarget = requireTarget(target);
  const args = [...(profile.prefix || [])];
  // SNI wird immer aus dem Ziel-Host abgeleitet (openssl -servername braucht einen Wert).
  if (profile.sni) args.push("-servername", safeTarget.split(":")[0]);

  for (const field of profile.flags || []) {
    if (field.role === "prefix") continue;
    if (field.type === "boolean") {
      if (isEnabled(options[field.key], field.default)) args.push(field.flag);
      continue;
    }
    const value = resolveValue(field, options[field.key]);
    if (value !== undefined) emitFlag(args, field, value);
  }

  if (profile.target.arg) args.push(profile.target.arg, safeTarget);
  else args.push(safeTarget);

  for (const field of profile.positional || []) {
    const value = resolveValue(field, options[field.key]);
    if (value !== undefined) args.push(String(value));
  }
  return args;
}

function startTool({ env, distro, tool, target, options = {}, timeoutMs = 120_000 }, handlers = {}) {
  if (!ALLOW.has(tool)) throw new Error("Tool nicht in Allowlist.");
  const args = buildToolCommand(tool, target, options);
  let command;
  let commandArgs;

  if (env === "windows") {
    command = tool;
    commandArgs = args;
  } else if (env === "wsl") {
    if (!DISTRO_RE.test(distro || "")) throw new Error("Ungueltige WSL-Distribution.");
    command = "wsl.exe";
    commandArgs = ["-d", distro, "--", tool, ...args];
  } else {
    throw new Error("Unbekannte Umgebung.");
  }

  const child = spawn(command, commandArgs, { windowsHide: true, shell: false });
  const timeout = setTimeout(() => {
    handlers.onTimeout?.();
    child.kill("SIGKILL");
  }, Math.min(Math.max(timeoutMs, 1000), 300_000));
  child.stdout.on("data", (chunk) => handlers.onStdout?.(chunk.toString("utf8")));
  child.stderr.on("data", (chunk) => handlers.onStderr?.(chunk.toString("utf8")));
  child.on("error", (error) => {
    clearTimeout(timeout);
    handlers.onError?.(error);
  });
  child.on("close", (code, signal) => {
    clearTimeout(timeout);
    handlers.onClose?.(code, signal);
  });
  return { child, command: [tool, ...args] };
}

async function inventory({ force = false } = {}) {
  if (!force && inventoryCache && Date.now() - inventoryCache.at < INVENTORY_TTL_MS) {
    return inventoryCache.data;
  }

  const windows = detectWindowsExecutables();
  const distros = await listWslDistros();
  const wsl = {};
  for (const distro of distros) {
    wsl[distro] = withMeta(await detectWslExecutables(distro));
  }

  const data = {
    generatedAt: new Date().toISOString(),
    execAllowlist: [...ALLOW].sort(),
    catalog: TOOL_CATALOG,
    windows: withMeta(windows),
    wsl,
  };
  inventoryCache = { at: Date.now(), data };
  return data;
}

// Gated Ausfuehrung: nur Allowlist-Tools, args als String-Array, feste Timeouts.
async function runTool({ env, distro, tool, args = [], timeoutMs = 30_000 }) {
  if (!ALLOW.has(tool)) throw new Error("Tool nicht in Allowlist.");
  if (!Array.isArray(args) || !args.every((a) => typeof a === "string")) {
    throw new Error("Argumente muessen ein String-Array sein.");
  }

  if (env === "windows") {
    return run(tool, args, { timeoutMs });
  }
  if (env === "wsl") {
    if (!DISTRO_RE.test(distro || "")) throw new Error("Ungueltige WSL-Distribution.");
    return run("wsl.exe", ["-d", distro, "--", tool, ...args], { timeoutMs });
  }
  throw new Error("Unbekannte Umgebung.");
}

module.exports = {
  ALLOWLIST: [...ALLOW],
  PROFILES,
  PHASES,
  TOOL_CATALOG,
  buildToolCommand,
  detectWindowsExecutables,
  detectWslExecutables,
  inventory,
  listWslDistros,
  startTool,
  runTool,
};
