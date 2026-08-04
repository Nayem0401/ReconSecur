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

function detectWindowsTools() {
  const exts = (process.env.PATHEXT || ".EXE;.BAT;.CMD").split(";").map((e) => e.toLowerCase());
  const dirs = (process.env.PATH || "").split(path.delimiter).filter(Boolean);
  const found = [];

  for (const tool of ALLOW) {
    const hit = dirs.some((dir) => {
      try {
        if (fs.existsSync(path.join(dir, tool))) return true;
        return exts.some((ext) => fs.existsSync(path.join(dir, tool + ext)));
      } catch {
        return false;
      }
    });
    if (hit) found.push(tool);
  }
  return found.sort();
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

async function detectWslTools(distro) {
  if (!DISTRO_RE.test(distro)) return [];
  const names = [...ALLOW];
  const result = await run("wsl.exe", ["-d", distro, "--", "which", ...names], { timeoutMs: 20_000 });
  const found = result.stdout
    .split(/\r?\n/)
    .map((line) => line.trim().split("/").pop())
    .filter((tool) => ALLOW.has(tool));
  return [...new Set(found)].sort();
}

async function inventory({ force = false } = {}) {
  if (!force && inventoryCache && Date.now() - inventoryCache.at < INVENTORY_TTL_MS) {
    return inventoryCache.data;
  }

  const windows = detectWindowsTools();
  const distros = await listWslDistros();
  const wsl = {};
  for (const distro of distros) {
    wsl[distro] = await detectWslTools(distro);
  }

  const data = {
    generatedAt: new Date().toISOString(),
    allowlistSize: ALLOW.size,
    windows,
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
  detectWindowsTools,
  detectWslTools,
  inventory,
  listWslDistros,
  runTool,
};
