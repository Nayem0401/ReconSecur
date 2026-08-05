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
const toolSessions = new Map();

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

async function resolveAllowedTarget(target) {
  const hostname = target.hostname.replace(/^\[|\]$/g, "");
  const addresses = net.isIP(hostname)
    ? [{ address: hostname, family: net.isIP(hostname) }]
    : await dns.lookup(hostname, { all: true });

  if (!ALLOW_PRIVATE_TARGETS && addresses.some(({ address }) => isPrivateAddress(address))) {
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

function startToolSession(body) {
  if (body.authorized !== true) throw new Error("Die ausdrueckliche Autorisierung muss bestaetigt werden.");
  const activeCount = [...toolSessions.values()].filter(({ status }) => status === "running").length;
  if (activeCount >= MAX_TOOL_SESSIONS) throw new Error(`Maximal ${MAX_TOOL_SESSIONS} Tool-Sessions koennen gleichzeitig laufen.`);
  return spawnSession(body);
}

// Startet alle Recon-Tools (Phase 1) parallel gegen dasselbe Ziel. Der Client
// liefert die im gewaehlten Env verfuegbaren Tools; hier wird gegen Phase-1-
// Allowlist validiert und die Gesamtlast auf MAX_TOOL_SESSIONS begrenzt.
function startReconBatch(body) {
  if (body.authorized !== true) throw new Error("Die ausdrueckliche Autorisierung muss bestaetigt werden.");
  const phase1 = new Set(toolAdapter.TOOL_CATALOG.filter((t) => t.phase === 1).map((t) => t.name));
  const requested = Array.isArray(body.tools) && body.tools.length
    ? [...new Set(body.tools)].filter((t) => phase1.has(t))
    : [...phase1];
  if (!requested.length) throw new Error("Keine Recon-Tools fuer die gewaehlte Umgebung verfuegbar.");
  const running = [...toolSessions.values()].filter(({ status }) => status === "running").length;
  if (running + requested.length > MAX_TOOL_SESSIONS) {
    throw new Error(`Zu viele parallele Sessions (${running} aktiv + ${requested.length} neu > ${MAX_TOOL_SESSIONS}).`);
  }
  return Promise.all(requested.map((tool) => spawnSession({
    authorized: true, tool, target: body.target, env: body.env, distro: body.distro, options: {},
  })));
}

async function spawnSession(body) {
  const normalized = normalizeTarget(body.target);
  await resolveAllowedTarget(normalized);
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
    tool: body.tool,
    target: normalized.href,
    env: body.env,
    distro: body.distro || null,
    status: "running",
    startedAt: new Date().toISOString(),
    sequence: 0,
    events: [],
    clients: new Set(),
  };

  const execution = toolAdapter.startTool({
    env: body.env,
    distro: body.distro,
    tool: body.tool,
    target,
    options: body.options,
  }, {
    onStdout: (text) => publishSession(session, "stdout", { text }),
    onStderr: (text) => publishSession(session, "stderr", { text }),
    onTimeout: () => publishSession(session, "timeout", {}),
    onError: (error) => {
      session.status = "failed";
      publishSession(session, "error", { message: error.message });
    },
    onClose: (code, signal) => {
      session.status = session.status === "cancelled" ? "cancelled" : (code === 0 ? "completed" : "failed");
      session.completedAt = new Date().toISOString();
      publishSession(session, "exit", { code, signal, status: session.status });
      for (const client of session.clients) client.end();
      session.clients.clear();
    },
  });
  session.child = execution.child;
  session.command = execution.command;
  toolSessions.set(session.id, session);
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
        if (body.authorized !== true) {
          sendJson(response, 403, { error: "Die ausdrueckliche Autorisierung muss bestaetigt werden." });
          return;
        }
        const target = normalizeTarget(body.target);
        sendJson(response, 200, await analyzeTarget(target));
      } catch (error) {
        const status = error.name === "AbortError" ? 504 : 400;
        sendJson(response, status, { error: error.name === "AbortError" ? "Analyse-Zeitlimit ueberschritten." : error.message });
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
        sendJson(response, /Autorisierung/.test(error.message) ? 403 : 400, { error: error.message });
      }
      return;
    }

    if (request.method === "POST" && request.url === "/api/recon-runs") {
      try {
        const sessions = await startReconBatch(await readJson(request));
        sendJson(response, 202, { sessions: sessions.map(sessionSummary) });
      } catch (error) {
        sendJson(response, /Autorisierung/.test(error.message) ? 403 : 400, { error: error.message });
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

module.exports = { createServer, inspectHeaders, isPrivateAddress, normalizeTarget, startToolSession, startReconBatch };