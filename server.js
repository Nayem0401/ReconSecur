const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const dns = require("node:dns/promises");
const tls = require("node:tls");
const net = require("node:net");
const crypto = require("node:crypto");
const toolAdapter = require("./API/toolAdapter");

const PORT = Number(process.env.PORT || 4173);
const HOST = process.env.HOST || "127.0.0.1";
const PUBLIC_DIR = path.join(__dirname, "public");
const MAX_BODY_BYTES = 16 * 1024;
const ALLOW_PRIVATE_TARGETS = process.env.AETHER_ALLOW_PRIVATE === "true";
const MAX_TOOL_SESSIONS = 16;
const MAX_SESSION_EVENTS = 500;
const MAX_TOOL_STARTS_PER_MINUTE = 20;
const MAX_AUDIT_OUTPUT_BYTES = 64 * 1024;
const configuredEngagementTtl = Number(process.env.AETHER_ENGAGEMENT_TTL_MS || 8 * 60 * 60 * 1000);
const ENGAGEMENT_TTL_MS = Number.isFinite(configuredEngagementTtl)
  ? Math.min(Math.max(configuredEngagementTtl, 60_000), 24 * 60 * 60 * 1000)
  : 8 * 60 * 60 * 1000;
const configuredApprovalTtl = Number(process.env.AETHER_APPROVAL_TTL_MS || 15 * 60 * 1000);
const APPROVAL_TTL_MS = Number.isFinite(configuredApprovalTtl)
  ? Math.min(Math.max(configuredApprovalTtl, 60_000), 24 * 60 * 60 * 1000)
  : 15 * 60 * 1000;
const ADMIN_TOKEN = process.env.AETHER_ADMIN_TOKEN || "";
const APPROVAL_CODE_CHARS = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
const APPROVAL_CODE_LENGTH = 20;
const LOGIN_CODE_LENGTH = 15;
const configuredSessionTtl = Number(process.env.AETHER_SESSION_TTL_MS || 12 * 60 * 60 * 1000);
const SESSION_TTL_MS = Number.isFinite(configuredSessionTtl)
  ? Math.min(Math.max(configuredSessionTtl, 60_000), 7 * 24 * 60 * 60 * 1000)
  : 12 * 60 * 60 * 1000;
const configuredCustomerCodeTtl = Number(process.env.AETHER_CUSTOMER_CODE_TTL_MS || 30 * 24 * 60 * 60 * 1000);
const CUSTOMER_CODE_TTL_MS = Number.isFinite(configuredCustomerCodeTtl)
  ? Math.min(Math.max(configuredCustomerCodeTtl, 60 * 60 * 1000), 365 * 24 * 60 * 60 * 1000)
  : 30 * 24 * 60 * 60 * 1000;
// Mindestens 3 Master-Codes fuers interne Lab (voller Testzugriff); Kunden erhalten
// stattdessen einzeln geprägte 15-stellige Login-Codes ueber /api/admin/logins.
const MASTER_CODES = (process.env.AETHER_MASTER_CODES || "").split(",").map((s) => s.trim()).filter(Boolean);
if (MASTER_CODES.length > 0 && MASTER_CODES.length < 3) {
  console.warn(`AETHER_MASTER_CODES sollte mindestens 3 Codes enthalten, gefunden: ${MASTER_CODES.length}.`);
}
const AUDIT_LOG_PATH = path.join(__dirname, "artifacts", "audit.jsonl");
const toolSessions = new Map();
const engagements = new Map();
const approvals = new Map();
const loginCodes = new Map();
const sessions = new Map();

const contentTypes = {
  ".css": "text/css; charset=utf-8",
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
};

function normalizeTarget(value) {
  if (typeof value !== "string" || value.length > 2048) {
    throw new Error("Target muss eine gueltige URL sein.");
  }

  const raw = value.trim();
  const candidate = /^[a-z][a-z\d+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  const target = new URL(candidate);

  if (!["http:", "https:"].includes(target.protocol) || target.username || target.password) {
    throw new Error("Nur HTTP(S)-Targets ohne Zugangsdaten sind erlaubt.");
  }

  if (!target.hostname || /[\s/\\]/.test(target.hostname)) {
    throw new Error("Hostname ist ungueltig.");
  }

  target.hash = "";
  return target;
}

function finding(id, severity, title, evidence, recommendation) {
  return { id, severity, title, evidence, recommendation };
}

function isPrivateAddress(value) {
  const address = value.replace(/^\[|\]$/g, "").toLowerCase();
  if (net.isIPv4(address)) {
    const [first, second] = address.split(".").map(Number);
    return first === 0 || first === 10 || first === 127 ||
      (first === 169 && second === 254) ||
      (first === 172 && second >= 16 && second <= 31) ||
      (first === 192 && second === 168) || first >= 224;
  }
  if (net.isIPv6(address)) {
    return address === "::" || address === "::1" || address.startsWith("fc") ||
      address.startsWith("fd") || /^fe[89ab]/.test(address) ||
      address.startsWith("::ffff:127.") || address.startsWith("::ffff:10.") ||
      address.startsWith("::ffff:192.168.");
  }
  return false;
}

async function resolveAllowedTarget(target, { allowPrivate = false } = {}) {
  const hostname = target.hostname.replace(/^\[|\]$/g, "");
  const addresses = net.isIP(hostname)
    ? [{ address: hostname, family: net.isIP(hostname) }]
    : await dns.lookup(hostname, { all: true });

  if (!ALLOW_PRIVATE_TARGETS && !allowPrivate && addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error("Private und lokale Targets sind standardmaessig blockiert.");
  }
  return addresses;
}

async function fetchAllowedTarget(initialTarget, signal) {
  let target = initialTarget;
  let initialAddresses = null;

  for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
    const addresses = await resolveAllowedTarget(target);
    initialAddresses ||= addresses;
    const response = await fetch(target, {
      redirect: "manual",
      signal,
      headers: { "user-agent": "Aether-Authorized-Assessment/1.0" },
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) {
      return { response, addresses: initialAddresses, finalTarget: target };
    }

    const location = response.headers.get("location");
    if (!location) return { response, addresses: initialAddresses, finalTarget: target };
    target = normalizeTarget(new URL(location, target).href);
  }
  throw new Error("Zu viele Weiterleitungen.");
}

function inspectHeaders(headers, target) {
  const findings = [];
  const header = (name) => headers.get(name);

  if (target.protocol !== "https:") {
    findings.push(finding("transport-http", "high", "Unverschluesselte HTTP-Verbindung", target.href, "HTTPS erzwingen und HTTP dauerhaft umleiten."));
  } else if (!header("strict-transport-security")) {
    findings.push(finding("missing-hsts", "medium", "HSTS fehlt", "Strict-Transport-Security wurde nicht geliefert.", "HSTS mit geeigneter max-age und includeSubDomains aktivieren."));
  }

  if (!header("content-security-policy")) {
    findings.push(finding("missing-csp", "medium", "Content Security Policy fehlt", "Content-Security-Policy wurde nicht geliefert.", "Eine restriktive, anwendungsspezifische CSP definieren."));
  }

  if (!header("x-content-type-options")) {
    findings.push(finding("missing-nosniff", "low", "MIME-Sniffing-Schutz fehlt", "X-Content-Type-Options wurde nicht geliefert.", "X-Content-Type-Options: nosniff setzen."));
  }

  if (!header("x-frame-options") && !header("content-security-policy")?.includes("frame-ancestors")) {
    findings.push(finding("missing-frame-policy", "low", "Clickjacking-Schutz nicht erkennbar", "Keine X-Frame-Options oder CSP frame-ancestors Direktive.", "frame-ancestors in der CSP definieren."));
  }

  if (header("server")) {
    findings.push(finding("server-disclosure", "info", "Server-Header offengelegt", header("server"), "Versions- und Produktdetails im Server-Header minimieren."));
  }

  return findings;
}

async function inspectTls(target) {
  if (target.protocol !== "https:") return null;

  return new Promise((resolve) => {
    const socket = tls.connect({
      host: target.hostname,
      port: Number(target.port || 443),
      servername: target.hostname,
      rejectUnauthorized: true,
      timeout: 6000,
    });

    socket.once("secureConnect", () => {
      const certificate = socket.getPeerCertificate();
      resolve({
        authorized: socket.authorized,
        protocol: socket.getProtocol(),
        validTo: certificate.valid_to || null,
        issuer: certificate.issuer?.O || certificate.issuer?.CN || "Unbekannt",
      });
      socket.end();
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve({ error: "TLS-Verbindung hat das Zeitlimit ueberschritten." });
    });
    socket.once("error", (error) => resolve({ error: error.message }));
  });
}

async function analyzeTarget(target) {
  const startedAt = new Date().toISOString();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const { response, addresses, finalTarget } = await fetchAllowedTarget(target, controller.signal);
    const tlsInfo = await inspectTls(finalTarget);

    const findings = inspectHeaders(response.headers, finalTarget);
    if (tlsInfo?.error) {
      findings.push(finding("tls-validation", "high", "TLS-Validierung fehlgeschlagen", tlsInfo.error, "Zertifikatskette, Hostname und Ablaufdatum pruefen."));
    }

    return {
      assessmentId: crypto.randomUUID(),
      target: target.href,
      startedAt,
      completedAt: new Date().toISOString(),
      summary: {
        status: response.status,
        finalUrl: finalTarget.href,
        addresses,
        tls: tlsInfo,
        findingCount: findings.length,
      },
      findings,
      nextSteps: [
        "Findings manuell validieren und False Positives markieren.",
        "Scope-konforme Inhalts- und Endpoint-Enumeration planen.",
        "Bestaetigte Befunde mit reproduzierbaren Nachweisen dokumentieren.",
      ],
    };
  } finally {
    clearTimeout(timeout);
  }
}

function sendJson(response, status, value) {
  response.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" });
  response.end(JSON.stringify(value));
}

function requestError(message, status = 400) {
  const error = new Error(message);
  error.status = status;
  return error;
}

function appendAudit(record, filePath = AUDIT_LOG_PATH) {
  const entry = { at: new Date().toISOString(), ...record };
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.appendFileSync(filePath, `${JSON.stringify(entry)}\n`, { encoding: "utf8", mode: 0o600 });
  return entry;
}

function engagementSummary(engagement) {
  return {
    id: engagement.id,
    target: engagement.target,
    scopeOrigin: engagement.scopeOrigin,
    unlockedPhase: engagement.unlockedPhase,
    createdAt: engagement.createdAt,
    expiresAt: engagement.expiresAt,
  };
}

function generateApprovalCode() {
  const bytes = crypto.randomBytes(APPROVAL_CODE_LENGTH);
  let code = "";
  for (let i = 0; i < APPROVAL_CODE_LENGTH; i++) code += APPROVAL_CODE_CHARS[bytes[i] % APPROVAL_CODE_CHARS.length];
  return code;
}

// Nur der Admin (HTTP-Layer prueft AETHER_ADMIN_TOKEN) darf Codes praegen; hier reine Geschaeftslogik.
function mintApprovalCode(body) {
  const target = normalizeTarget(body.target);
  const approval = {
    code: generateApprovalCode(),
    scopeOrigin: target.origin,
    target: target.href,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + APPROVAL_TTL_MS).toISOString(),
    used: false,
  };
  approvals.set(approval.code, approval);
  appendAudit({ event: "approval.created", target: approval.target, expiresAt: approval.expiresAt });
  return approval;
}

function requireAdmin(request) {
  if (!ADMIN_TOKEN) throw requestError("Admin-Freigabe ist nicht konfiguriert (AETHER_ADMIN_TOKEN fehlt).", 503);
  const header = request.headers["authorization"] || "";
  const expected = `Bearer ${ADMIN_TOKEN}`;
  const headerBuf = Buffer.from(header);
  const expectedBuf = Buffer.from(expected);
  const ok = headerBuf.length === expectedBuf.length && crypto.timingSafeEqual(headerBuf, expectedBuf);
  if (!ok) throw requestError("Nur der Admin darf Freigabecodes erteilen.", 403);
}

function generateLoginCode() {
  const bytes = crypto.randomBytes(LOGIN_CODE_LENGTH);
  let code = "";
  for (let i = 0; i < LOGIN_CODE_LENGTH; i++) code += APPROVAL_CODE_CHARS[bytes[i] % APPROVAL_CODE_CHARS.length];
  return code;
}

// Admin praegt einen 15-stelligen Kunden-Login-Code (wiederverwendbar bis TTL, kein Single-Use).
function mintLoginCode() {
  const entry = {
    code: generateLoginCode(),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + CUSTOMER_CODE_TTL_MS).toISOString(),
  };
  loginCodes.set(entry.code, entry);
  appendAudit({ event: "login_code.created", expiresAt: entry.expiresAt });
  return entry;
}

function createSession(role) {
  const session = {
    token: crypto.randomUUID(),
    role,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_TTL_MS).toISOString(),
  };
  sessions.set(session.token, session);
  appendAudit({ event: "login.success", role });
  return session;
}

// Login: 3 feste Master-Codes (AETHER_MASTER_CODES) geben vollen Lab-Testzugriff
// (kein Freigabecode, alle Phasen sofort frei, private Targets erlaubt). Kunden
// loggen sich mit einem admin-gepraegten 15-Zeichen-Code ein (Rolle "customer").
function login(body) {
  const code = typeof body.code === "string" ? body.code.trim() : "";
  if (!code) throw requestError("Login-Code erforderlich.", 400);
  if (MASTER_CODES.includes(code)) return createSession("master");
  const entry = loginCodes.get(code);
  if (entry && Date.parse(entry.expiresAt) > Date.now()) return createSession("customer");
  if (entry) loginCodes.delete(code);
  appendAudit({ event: "login.failed" });
  throw requestError("Login-Code ungueltig oder abgelaufen.", 401);
}

function requireSession(token) {
  if (typeof token !== "string" || !token) throw requestError("Login erforderlich.", 401);
  const session = sessions.get(token);
  if (!session) throw requestError("Session ungueltig oder abgelaufen.", 401);
  if (Date.parse(session.expiresAt) <= Date.now()) {
    sessions.delete(token);
    throw requestError("Session ist abgelaufen.", 401);
  }
  return session;
}

function consumeApprovalCode(code, target) {
  if (typeof code !== "string" || code.length !== APPROVAL_CODE_LENGTH) {
    throw requestError(`Admin-Freigabecode (${APPROVAL_CODE_LENGTH} Zeichen) erforderlich.`, 403);
  }
  const approval = approvals.get(code);
  if (!approval || approval.used) throw requestError("Freigabecode ungueltig oder bereits verwendet.", 403);
  if (Date.parse(approval.expiresAt) <= Date.now()) {
    approvals.delete(code);
    throw requestError("Freigabecode ist abgelaufen.", 403);
  }
  if (target.origin !== approval.scopeOrigin) {
    throw requestError("Freigabecode gilt nicht fuer dieses Ziel.", 403);
  }
  approval.used = true;
  approvals.delete(code);
  return approval;
}

function createEngagement(body) {
  const session = requireSession(body.sessionToken);
  if (body.authorized !== true) {
    throw requestError("Die ausdrueckliche Autorisierung muss bestaetigt werden.", 403);
  }
  const target = normalizeTarget(body.target);
  const maxPhase = Math.max(...Object.keys(toolAdapter.PHASES).map(Number));
  let unlockedPhase = 1;
  if (session.role === "master") {
    unlockedPhase = maxPhase;
  } else {
    consumeApprovalCode(body.approvalCode, target);
  }
  const engagement = {
    id: crypto.randomUUID(),
    target: target.href,
    scopeOrigin: target.origin,
    role: session.role,
    sessionToken: session.token,
    unlockedPhase,
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + ENGAGEMENT_TTL_MS).toISOString(),
    toolStarts: [],
  };
  engagements.set(engagement.id, engagement);
  appendAudit({ event: "engagement.created", engagementId: engagement.id, target: engagement.target, phase: unlockedPhase, role: session.role });
  return engagement;
}

function requireEngagement(engagementId, target, phase = 1, sessionToken) {
  const engagement = engagements.get(engagementId);
  if (!engagement) throw requestError("Gueltiges Engagement erforderlich.", 403);
  const session = requireSession(sessionToken);
  if (session.token !== engagement.sessionToken) {
    throw requestError("Diese Login-Session besitzt kein Zugriffsrecht auf das Engagement.", 403);
  }
  if (Date.parse(engagement.expiresAt) <= Date.now()) {
    engagements.delete(engagement.id);
    throw requestError("Engagement ist abgelaufen.", 403);
  }
  if (target.origin !== engagement.scopeOrigin) {
    throw requestError("Ziel liegt ausserhalb des bestaetigten Engagement-Scopes.", 403);
  }
  if (phase > engagement.unlockedPhase) {
    throw requestError(`Phase ${phase} ist noch nicht freigegeben.`, 403);
  }
  return engagement;
}

function advanceEngagementPhase(engagementId, body) {
  const engagement = engagements.get(engagementId);
  if (!engagement || Date.parse(engagement.expiresAt) <= Date.now()) {
    throw requestError("Gueltiges Engagement erforderlich.", 403);
  }
  const session = requireSession(body.sessionToken);
  if (session.token !== engagement.sessionToken) {
    throw requestError("Diese Login-Session besitzt kein Zugriffsrecht auf das Engagement.", 403);
  }
  const requestedPhase = Number(body.phase);
  const maxPhase = Math.max(...Object.keys(toolAdapter.PHASES).map(Number));
  if (!Number.isInteger(requestedPhase) || requestedPhase !== engagement.unlockedPhase + 1 || requestedPhase > maxPhase) {
    throw requestError("Phasen muessen einzeln und in Reihenfolge freigegeben werden.");
  }
  engagement.unlockedPhase = requestedPhase;
  appendAudit({ event: "engagement.phase_advanced", engagementId: engagement.id, target: engagement.target, phase: requestedPhase });
  return engagement;
}

function enforceStartRate(engagement, requestedStarts) {
  const now = Date.now();
  engagement.toolStarts = engagement.toolStarts.filter((startedAt) => startedAt > now - 60_000);
  if (engagement.toolStarts.length + requestedStarts > MAX_TOOL_STARTS_PER_MINUTE) {
    throw requestError(`Maximal ${MAX_TOOL_STARTS_PER_MINUTE} Tool-Starts pro Minute und Engagement.`, 429);
  }
  engagement.toolStarts.push(...Array.from({ length: requestedStarts }, () => now));
}

function captureSessionOutput(session, stream, text) {
  if (session.auditOutput.length >= MAX_AUDIT_OUTPUT_BYTES) {
    session.auditOutputTruncated = true;
    return;
  }
  const entry = `[${stream}] ${text}`;
  const remaining = MAX_AUDIT_OUTPUT_BYTES - session.auditOutput.length;
  session.auditOutput += entry.slice(0, remaining);
  session.auditOutputTruncated ||= entry.length > remaining;
}

function publishSession(session, type, data) {
  const event = { id: ++session.sequence, type, data, at: new Date().toISOString() };
  session.events.push(event);
  if (session.events.length > MAX_SESSION_EVENTS) session.events.shift();
  const payload = `id: ${event.id}\nevent: ${type}\ndata: ${JSON.stringify(event)}\n\n`;
  for (const client of session.clients) client.write(payload);
  return event;
}

function sessionSummary(session) {
  return {
    id: session.id,
    engagementId: session.engagementId,
    tool: session.tool,
    target: session.target,
    env: session.env,
    distro: session.distro,
    command: session.command,
    status: session.status,
    startedAt: session.startedAt,
    completedAt: session.completedAt || null,
  };
}

async function startToolSession(body) {
  const normalized = normalizeTarget(body.target);
  const profile = toolAdapter.PROFILES[body.tool];
  if (!profile) throw new Error("Unbekanntes Tool.");
  const phase = toolAdapter.TOOL_CATALOG.find((tool) => tool.name === body.tool)?.phase || 4;
  const engagement = requireEngagement(body.engagementId, normalized, phase, body.sessionToken);
  const activeCount = [...toolSessions.values()].filter(({ status }) => status === "running").length;
  if (activeCount >= MAX_TOOL_SESSIONS) throw new Error(`Maximal ${MAX_TOOL_SESSIONS} Tool-Sessions koennen gleichzeitig laufen.`);
  enforceStartRate(engagement, 1);
  return spawnSession(body, normalized, engagement);
}

// Startet alle Recon-Tools (Phase 1) parallel gegen dasselbe Ziel. Der Client
// liefert die im gewaehlten Env verfuegbaren Tools; hier wird gegen Phase-1-
// Allowlist validiert und die Gesamtlast auf MAX_TOOL_SESSIONS begrenzt.
async function startReconBatch(body) {
  const normalized = normalizeTarget(body.target);
  const engagement = requireEngagement(body.engagementId, normalized, 1, body.sessionToken);
  const phase1 = new Set(toolAdapter.TOOL_CATALOG.filter((t) => t.phase === 1).map((t) => t.name));
  const requested = Array.isArray(body.tools) && body.tools.length
    ? [...new Set(body.tools)].filter((t) => phase1.has(t))
    : [...phase1];
  if (!requested.length) throw new Error("Keine Recon-Tools fuer die gewaehlte Umgebung verfuegbar.");
  const running = [...toolSessions.values()].filter(({ status }) => status === "running").length;
  if (running + requested.length > MAX_TOOL_SESSIONS) {
    throw new Error(`Zu viele parallele Sessions (${running} aktiv + ${requested.length} neu > ${MAX_TOOL_SESSIONS}).`);
  }
  enforceStartRate(engagement, requested.length);
  return Promise.all(requested.map((tool) => spawnSession({
    tool, target: body.target, env: body.env, distro: body.distro, options: {},
  }, normalized, engagement)));
}

async function spawnSession(body, normalized = normalizeTarget(body.target), engagement = requireEngagement(body.engagementId, normalized, 1, body.sessionToken)) {
  await resolveAllowedTarget(normalized, { allowPrivate: engagement.role === "master" });
  const profile = toolAdapter.PROFILES[body.tool];
  if (!profile) throw new Error("Unbekanntes Tool.");
  const kind = profile.target.kind;
  const port = normalized.port || (normalized.protocol === "http:" ? "80" : "443");
  let target =
    kind === "host" || kind === "domain" ? normalized.hostname
      : kind === "hostport" ? `${normalized.hostname}:${port}`
      : normalized.href;

  const prefixField = (profile.flags || []).find((f) => f.role === "prefix");
  if (prefixField && (kind === "host" || kind === "domain")) {
    const raw = body.options?.[prefixField.key];
    const value = raw === undefined || raw === "" ? prefixField.default : String(raw);
    if (!prefixField.values.includes(value)) throw new Error("Ungueltiger Scope.");
    if (value !== "(root)") target = `${value}.${target}`;
  }
  const session = {
    id: crypto.randomUUID(),
    engagementId: engagement.id,
    tool: body.tool,
    target: normalized.href,
    env: body.env,
    distro: body.distro || null,
    status: "running",
    startedAt: new Date().toISOString(),
    sequence: 0,
    events: [],
    clients: new Set(),
    auditOutput: "",
    auditOutputTruncated: false,
  };

  const execution = toolAdapter.startTool({
    env: body.env,
    distro: body.distro,
    tool: body.tool,
    target,
    options: body.options,
  }, {
    onStdout: (text) => {
      captureSessionOutput(session, "stdout", text);
      publishSession(session, "stdout", { text });
    },
    onStderr: (text) => {
      captureSessionOutput(session, "stderr", text);
      publishSession(session, "stderr", { text });
    },
    onTimeout: () => publishSession(session, "timeout", {}),
    onError: (error) => {
      session.status = "failed";
      publishSession(session, "error", { message: error.message });
      appendAudit({ event: "tool.error", engagementId: session.engagementId, sessionId: session.id, tool: session.tool, message: error.message });
    },
    onClose: (code, signal) => {
      session.status = session.status === "cancelled" ? "cancelled" : (code === 0 ? "completed" : "failed");
      session.completedAt = new Date().toISOString();
      publishSession(session, "exit", { code, signal, status: session.status });
      appendAudit({
        event: "tool.finished",
        engagementId: session.engagementId,
        sessionId: session.id,
        tool: session.tool,
        target: session.target,
        status: session.status,
        code,
        signal,
        output: session.auditOutput,
        outputTruncated: session.auditOutputTruncated,
      });
      for (const client of session.clients) client.end();
      session.clients.clear();
    },
  });
  session.child = execution.child;
  session.command = execution.command;
  toolSessions.set(session.id, session);
  appendAudit({
    event: "tool.started",
    engagementId: session.engagementId,
    sessionId: session.id,
    tool: session.tool,
    target: session.target,
    env: session.env,
    distro: session.distro,
    command: session.command,
    options: body.options || {},
  });
  publishSession(session, "start", sessionSummary(session));
  return session;
}

function streamToolSession(request, response, session) {
  response.writeHead(200, {
    "content-type": "text/event-stream; charset=utf-8",
    "cache-control": "no-cache, no-store",
    connection: "keep-alive",
    "x-content-type-options": "nosniff",
  });
  const lastId = Number(request.headers["last-event-id"] || 0);
  for (const event of session.events.filter(({ id }) => id > lastId)) {
    response.write(`id: ${event.id}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`);
  }
  if (session.status !== "running") {
    response.end();
    return;
  }
  session.clients.add(response);
  request.on("close", () => session.clients.delete(response));
}

async function readJson(request) {
  let body = "";
  for await (const chunk of request) {
    body += chunk;
    if (Buffer.byteLength(body) > MAX_BODY_BYTES) throw new Error("Anfrage ist zu gross.");
  }
  return JSON.parse(body || "{}");
}

function serveStatic(request, response) {
  const pathname = new URL(request.url, "http://localhost").pathname;
  const requestPath = pathname === "/" ? "/index.html" : pathname;
  const filePath = path.resolve(PUBLIC_DIR, `.${requestPath}`);
  const withinRoot = filePath === PUBLIC_DIR || filePath.startsWith(PUBLIC_DIR + path.sep);
  if (!withinRoot || !fs.existsSync(filePath) || fs.statSync(filePath).isDirectory()) {
    sendJson(response, 404, { error: "Nicht gefunden." });
    return;
  }
  response.writeHead(200, { "content-type": contentTypes[path.extname(filePath)] || "application/octet-stream" });
  fs.createReadStream(filePath).pipe(response);
}

function createServer() {
  return http.createServer(async (request, response) => {
    if (request.method === "POST" && request.url === "/api/assessments") {
      try {
        const body = await readJson(request);
        const target = normalizeTarget(body.target);
        const engagement = requireEngagement(body.engagementId, target, 1, body.sessionToken);
        appendAudit({ event: "assessment.started", engagementId: engagement.id, target: target.href });
        const assessment = await analyzeTarget(target);
        appendAudit({ event: "assessment.finished", engagementId: engagement.id, target: target.href, findingCount: assessment.findings.length });
        sendJson(response, 200, assessment);
      } catch (error) {
        const status = error.name === "AbortError" ? 504 : (error.status || 400);
        sendJson(response, status, { error: error.name === "AbortError" ? "Analyse-Zeitlimit ueberschritten." : error.message });
      }
      return;
    }

    if (request.method === "POST" && request.url === "/api/login") {
      try {
        sendJson(response, 200, login(await readJson(request)));
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    if (request.method === "POST" && request.url === "/api/admin/logins") {
      try {
        requireAdmin(request);
        sendJson(response, 201, mintLoginCode());
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    if (request.method === "POST" && request.url === "/api/admin/approvals") {
      try {
        requireAdmin(request);
        const approval = mintApprovalCode(await readJson(request));
        sendJson(response, 201, { code: approval.code, target: approval.target, expiresAt: approval.expiresAt });
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    if (request.method === "POST" && request.url === "/api/engagements") {
      try {
        sendJson(response, 201, engagementSummary(createEngagement(await readJson(request))));
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    const engagementPhaseRoute = request.url.match(/^\/api\/engagements\/([0-9a-f-]+)\/phases$/i);
    if (request.method === "POST" && engagementPhaseRoute) {
      try {
        sendJson(response, 200, engagementSummary(advanceEngagementPhase(engagementPhaseRoute[1], await readJson(request))));
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    if (request.method === "GET" && request.url === "/api/tools") {
      try {
        sendJson(response, 200, await toolAdapter.inventory());
      } catch (error) {
        sendJson(response, 500, { error: error.message });
      }
      return;
    }

    if (request.method === "GET" && request.url === "/api/tool-sessions") {
      sendJson(response, 200, { sessions: [...toolSessions.values()].map(sessionSummary) });
      return;
    }

    if (request.method === "POST" && request.url === "/api/tool-sessions") {
      try {
        const session = await startToolSession(await readJson(request));
        sendJson(response, 202, sessionSummary(session));
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    if (request.method === "POST" && request.url === "/api/recon-runs") {
      try {
        const sessions = await startReconBatch(await readJson(request));
        sendJson(response, 202, { sessions: sessions.map(sessionSummary) });
      } catch (error) {
        sendJson(response, error.status || 400, { error: error.message });
      }
      return;
    }

    const sessionRoute = request.url.match(/^\/api\/tool-sessions\/([0-9a-f-]+)(?:\/events)?$/i);
    if (sessionRoute) {
      const session = toolSessions.get(sessionRoute[1]);
      if (!session) {
        sendJson(response, 404, { error: "Tool-Session nicht gefunden." });
        return;
      }
      if (request.method === "GET" && request.url.endsWith("/events")) {
        streamToolSession(request, response, session);
        return;
      }
      if (request.method === "GET") {
        sendJson(response, 200, sessionSummary(session));
        return;
      }
      if (request.method === "DELETE" && !request.url.endsWith("/events")) {
        if (session.status === "running") {
          session.status = "cancelled";
          publishSession(session, "cancel", {});
          appendAudit({ event: "tool.cancel_requested", engagementId: session.engagementId, sessionId: session.id, tool: session.tool });
          session.child.kill("SIGKILL");
        }
        sendJson(response, 200, sessionSummary(session));
        return;
      }
    }

    if (request.method === "GET") {
      serveStatic(request, response);
      return;
    }
    sendJson(response, 405, { error: "Methode nicht erlaubt." });
  });
}

if (require.main === module) {
  createServer().listen(PORT, HOST, () => console.log(`Aether UI: http://${HOST}:${PORT}`));
}

module.exports = {
  AUDIT_LOG_PATH,
  MAX_TOOL_STARTS_PER_MINUTE,
  appendAudit,
  createEngagement,
  createServer,
  enforceStartRate,
  inspectHeaders,
  isPrivateAddress,
  login,
  mintApprovalCode,
  mintLoginCode,
  normalizeTarget,
  requireEngagement,
  startToolSession,
  startReconBatch,
};