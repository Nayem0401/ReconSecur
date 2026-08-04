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

// Kuratiertes Allowlist-Set gaengiger Recon-/Assessment-Tools. Nur erweitern.
const ALLOWLIST = [
  "nmap", "masscan", "whatweb", "nikto", "gobuster", "ffuf", "dirb", "feroxbuster",
  "wpscan", "nuclei", "subfinder", "sublist3r", "amass", "assetfinder", "httpx",
  "dnsrecon", "dnsenum", "dig", "host", "whois", "theharvester", "sslscan",
  "sslyze", "testssl.sh", "sqlmap", "wafw00f", "curl", "wget", "openssl",
  "enum4linux", "smbclient", "onesixtyone", "snmpwalk", "fping", "netdiscover",
  "arp-scan", "nbtscan",
];

const ALLOW = new Set(ALLOWLIST.filter((name) => NAME_RE.test(name)));

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
  detectWindowsExecutables,
  detectWslExecutables,
  inventory,
  listWslDistros,
  runTool,
};
