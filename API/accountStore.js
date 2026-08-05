"use strict";

const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");

// Persistenter Account-Store. Passwoerter werden nur als scrypt-Hash + Salt
// gespeichert (nie Klartext, nie im Repo — artifacts/ ist .gitignored).
const STORE_PATH = path.join(__dirname, "..", "artifacts", "accounts.json");

const SCRYPT_KEYLEN = 64;

function ensureDir() {
  fs.mkdirSync(path.dirname(STORE_PATH), { recursive: true });
}

function load() {
  try {
    const raw = fs.readFileSync(STORE_PATH, "utf8");
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed.accounts) ? parsed : { accounts: [] };
  } catch {
    return { accounts: [] };
  }
}

function save(data) {
  ensureDir();
  fs.writeFileSync(STORE_PATH, JSON.stringify(data, null, 2));
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const derived = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  return `scrypt:${salt}:${derived}`;
}

function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;
  const [scheme, salt, hash] = stored.split(":");
  if (scheme !== "scrypt" || !salt || !hash) return false;
  const derived = crypto.scryptSync(password, salt, SCRYPT_KEYLEN).toString("hex");
  const a = Buffer.from(hash, "hex");
  const b = Buffer.from(derived, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function normalizeEmail(email) {
  return typeof email === "string" ? email.trim().toLowerCase() : "";
}

function findAccount(email) {
  const target = normalizeEmail(email);
  if (!target) return null;
  return load().accounts.find((a) => a.email === target) || null;
}

// Legt einen Account an oder aktualisiert das Passwort/die Rolle, falls er existiert.
function upsertAccount({ email, password, role = "customer" }) {
  const normalized = normalizeEmail(email);
  if (!normalized || !normalized.includes("@")) throw new Error("Gueltige E-Mail erforderlich.");
  if (typeof password !== "string" || password.length < 8) {
    throw new Error("Passwort muss mindestens 8 Zeichen haben.");
  }
  const data = load();
  let account = data.accounts.find((a) => a.email === normalized);
  if (account) {
    account.passwordHash = hashPassword(password);
    account.role = role;
  } else {
    account = {
      id: crypto.randomUUID(),
      email: normalized,
      role,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
      engagements: [],
    };
    data.accounts.push(account);
  }
  save(data);
  return { id: account.id, email: account.email, role: account.role };
}

// Prueft E-Mail + Passwort timing-safe. Gibt bei Erfolg die Account-Metadaten zurueck.
function authenticate(email, password) {
  const account = findAccount(email);
  if (!account) return null;
  if (typeof password !== "string" || !verifyPassword(password, account.passwordHash)) return null;
  return { id: account.id, email: account.email, role: account.role };
}

// Haengt einen Engagement-/Fortschrittseintrag an die Account-Historie an.
function recordEngagement(accountId, entry) {
  const data = load();
  const account = data.accounts.find((a) => a.id === accountId);
  if (!account) return;
  account.engagements = account.engagements || [];
  account.engagements.push(entry);
  if (account.engagements.length > 200) account.engagements = account.engagements.slice(-200);
  save(data);
}

// Aktualisiert einen bestehenden Historieneintrag (z. B. Phase/Findings) anhand der Engagement-ID.
function updateEngagement(accountId, engagementId, patch) {
  const data = load();
  const account = data.accounts.find((a) => a.id === accountId);
  if (!account || !Array.isArray(account.engagements)) return;
  const entry = account.engagements.find((e) => e.engagementId === engagementId);
  if (!entry) return;
  Object.assign(entry, patch);
  save(data);
}

function getHistory(accountId) {
  const data = load();
  const account = data.accounts.find((a) => a.id === accountId);
  return account && Array.isArray(account.engagements) ? account.engagements : [];
}

// Legt den Super-Admin einmalig an, wenn er fehlt (Seed aus Umgebungsvariablen).
function ensureSuperAdmin(email, password) {
  if (!email || !password) return;
  if (findAccount(email)) return;
  upsertAccount({ email, password, role: "superadmin" });
}

module.exports = {
  STORE_PATH,
  authenticate,
  ensureSuperAdmin,
  findAccount,
  getHistory,
  hashPassword,
  recordEngagement,
  updateEngagement,
  upsertAccount,
  verifyPassword,
};
