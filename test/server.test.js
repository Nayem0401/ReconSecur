process.env.AETHER_MASTER_CODES = "TEST-MASTER-CODE-1,TEST-MASTER-CODE-2,TEST-MASTER-CODE-3";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const {
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
} = require("../server");
const accountStore = require("../API/accountStore");

function createTestEngagement(target, role = "customer") {
  const session = role === "master" ? login({ code: "TEST-MASTER-CODE-1" }) : login({ code: mintLoginCode().code });
  const body = { target, authorized: true, sessionToken: session.token };
  if (role !== "master") body.approvalCode = mintApprovalCode({ target }).code;
  return { engagement: createEngagement(body), session };
}
const { buildToolCommand, TOOL_CATALOG } = require("../API/toolAdapter");

test("normalizes a hostname to HTTPS", () => {
  assert.equal(normalizeTarget("example.com").href, "https://example.com/");
});

test("rejects unsupported protocols and embedded credentials", () => {
  assert.throws(() => normalizeTarget("file:///etc/passwd"), /HTTP/);
  assert.throws(() => normalizeTarget("https://user:pass@example.com"), /HTTP/);
});

test("creates actionable findings for missing security headers", () => {
  const findings = inspectHeaders(new Headers(), new URL("https://example.com"));
  assert.ok(findings.some(({ id }) => id === "missing-hsts"));
  assert.ok(findings.some(({ id }) => id === "missing-csp"));
  assert.ok(findings.every(({ recommendation }) => recommendation.length > 0));
});

test("identifies loopback and private network addresses", () => {
  assert.equal(isPrivateAddress("127.0.0.1"), true);
  assert.equal(isPrivateAddress("10.20.30.40"), true);
  assert.equal(isPrivateAddress("192.168.1.10"), true);
  assert.equal(isPrivateAddress("::1"), true);
  assert.equal(isPrivateAddress("93.184.216.34"), false);
});

test("catalog exposes emoji categories and documented flags", () => {
  assert.ok(TOOL_CATALOG.length > 0);
  assert.ok(TOOL_CATALOG.every((t) => t.name && /\p{Emoji}/u.test(t.category) && t.summary));
  assert.ok(TOOL_CATALOG.every((t) => Array.isArray(t.flags)));
  const sqlmap = TOOL_CATALOG.find((t) => t.name === "sqlmap");
  const risk = sqlmap.flags.find((f) => f.key === "risk");
  assert.equal(risk.min, 1);
  assert.equal(risk.max, 3);
});

test("builds sqlmap args safely and enforces the 1..3 risk range", () => {
  const args = buildToolCommand("sqlmap", "https://example.com/?id=1", { risk: 3, level: 2 });
  assert.ok(args.includes("--risk=3"));
  assert.ok(args.includes("--level=2"));
  assert.ok(args.includes("--batch"));
  assert.deepEqual(args.slice(-2), ["-u", "https://example.com/?id=1"]);
  assert.throws(() => buildToolCommand("sqlmap", "https://example.com", { risk: 5 }), /zwischen 1 und 3/);
});

test("builds openssl SNI from the target host", () => {
  const args = buildToolCommand("openssl", "example.com:443");
  assert.deepEqual(args, ["s_client", "-servername", "example.com", "-connect", "example.com:443"]);
});

test("every catalog tool has an executable profile", () => {
  for (const tool of TOOL_CATALOG) {
    const args = buildToolCommand(tool.name, "https://example.com", {});
    assert.ok(Array.isArray(args) && args.length > 0, tool.name);
  }
});

test("phase 1 offers at least 15 powerful information-gathering tools", () => {
  const phase1 = TOOL_CATALOG.filter((t) => t.phase === 1);
  assert.ok(phase1.length >= 15, `phase 1 hat nur ${phase1.length} Tools`);
  for (const name of ["nmap", "dig", "dnsrecon", "whois", "subfinder", "whatweb", "wafw00f"]) {
    assert.ok(phase1.some((t) => t.name === name), name);
  }
});

test("dig exposes DMARC/DKIM scope and TXT lookups without emitting scope as a flag", () => {
  const dig = TOOL_CATALOG.find((t) => t.name === "dig");
  const scope = dig.flags.find((f) => f.role === "prefix");
  assert.ok(scope.values.includes("_dmarc"));
  const args = buildToolCommand("dig", "_dmarc.example.com", { type: "TXT", scope: "_dmarc" });
  assert.ok(args.includes("-t") && args.includes("TXT"));
  assert.ok(args.includes("_dmarc.example.com"));
  assert.ok(!args.includes("_dmarc") || args.indexOf("_dmarc") === args.indexOf("_dmarc.example.com"));
});

test("never lets shell metacharacters escape as separate arguments", () => {
  const injected = "https://example.com/?id=1; rm -rf / && $(whoami)`id`";
  const args = buildToolCommand("curl", injected, {});
  assert.ok(args.includes(injected));
  assert.ok(args.every((a) => typeof a === "string"));
});

test("tool-session endpoint rejects missing authorization", async () => {
  const server = createServer().listen(0);
  await new Promise((r) => server.once("listening", r));
  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/api/tool-sessions`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ tool: "curl", target: "https://example.com", env: "windows" }),
  });
  assert.equal(response.status, 403);
  await new Promise((r) => server.close(r));
});

test("recon batch endpoint rejects missing authorization", async () => {
  const server = createServer().listen(0);
  await new Promise((r) => server.once("listening", r));
  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/api/recon-runs`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target: "https://example.com", env: "windows" }),
  });
  assert.equal(response.status, 403);
  await new Promise((r) => server.close(r));
});

test("engagement binds scope and blocks a locked phase", () => {
  const { engagement, session } = createTestEngagement("https://example.com");
  assert.equal(requireEngagement(engagement.id, normalizeTarget("https://example.com/path"), 1, session.token).id, engagement.id);
  assert.throws(() => requireEngagement(engagement.id, normalizeTarget("https://other.example"), 1, session.token), /ausserhalb/);
  assert.throws(() => requireEngagement(engagement.id, normalizeTarget("https://example.com"), 2, session.token), /noch nicht freigegeben/);
});

test("tool sessions block private targets after scope validation", async () => {
  const { engagement, session } = createTestEngagement("http://127.0.0.1");
  await assert.rejects(
    startToolSession({ engagementId: engagement.id, sessionToken: session.token, tool: "curl", target: "http://127.0.0.1", env: "windows" }),
    /Private und lokale Targets/,
  );
});

test("rate limit caps starts per engagement", () => {
  const { engagement } = createTestEngagement("https://example.com");
  enforceStartRate(engagement, MAX_TOOL_STARTS_PER_MINUTE);
  assert.throws(() => enforceStartRate(engagement, 1), /pro Minute/);
});

test("engagement creation requires a valid login session", () => {
  assert.throws(() => createEngagement({ target: "https://example.com", authorized: true }), /Login erforderlich/);
  assert.throws(() => createEngagement({ target: "https://example.com", authorized: true, sessionToken: "not-a-real-token" }), /Session ungueltig/);
});

test("engagement rejects a missing or invalid approval code", () => {
  const session = login({ code: mintLoginCode().code });
  assert.throws(() => createEngagement({ target: "https://example.com", authorized: true, sessionToken: session.token }), /Freigabecode/);
  assert.throws(
    () => createEngagement({ target: "https://example.com", authorized: true, sessionToken: session.token, approvalCode: "X".repeat(20) }),
    /Freigabecode/,
  );
});

test("approval code is single-use and scope-bound", () => {
  const session = login({ code: mintLoginCode().code });
  const approval = mintApprovalCode({ target: "https://example.com" });
  assert.throws(
    () => createEngagement({ target: "https://other.example", authorized: true, sessionToken: session.token, approvalCode: approval.code }),
    /gilt nicht/,
  );
  const engagement = createEngagement({ target: "https://example.com", authorized: true, sessionToken: session.token, approvalCode: approval.code });
  assert.ok(engagement.id);
  assert.throws(
    () => createEngagement({ target: "https://example.com", authorized: true, sessionToken: session.token, approvalCode: approval.code }),
    /ungueltig oder bereits verwendet/,
  );
});

test("master code logs in without an approval code and unlocks every phase", () => {
  const { engagement, session } = createTestEngagement("https://example.com", "master");
  const maxPhase = engagement.unlockedPhase;
  assert.equal(requireEngagement(engagement.id, normalizeTarget("https://example.com"), maxPhase, session.token).id, engagement.id);
  assert.throws(() => login({ code: "not-a-real-code" }), /ungueltig/);
});

test("engagement rejects a foreign login session", () => {
  const { engagement } = createTestEngagement("https://example.com");
  const foreignSession = login({ code: mintLoginCode().code });
  assert.throws(
    () => requireEngagement(engagement.id, normalizeTarget("https://example.com"), 1, foreignSession.token),
    /kein Zugriffsrecht/,
  );
});

test("admin approvals endpoint requires the admin token", async () => {
  const server = createServer().listen(0);
  await new Promise((r) => server.once("listening", r));
  const { port } = server.address();
  const response = await fetch(`http://127.0.0.1:${port}/api/admin/approvals`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ target: "https://example.com" }),
  });
  assert.ok([403, 503].includes(response.status));
  await new Promise((r) => server.close(r));
});

test("audit log appends structured records", () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "aether-audit-"));
  const auditPath = path.join(directory, "audit.jsonl");
  try {
    appendAudit({ event: "test.audit", engagementId: "test-engagement" }, auditPath);
    const [line] = fs.readFileSync(auditPath, "utf8").trim().split("\n");
    assert.equal(JSON.parse(line).event, "test.audit");
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test("account password is stored only as a scrypt hash and verified timing-safe", () => {
  const password = "SuperGeheim123";
  const stored = accountStore.hashPassword(password);
  assert.match(stored, /^scrypt:[0-9a-f]+:[0-9a-f]+$/);
  assert.ok(!stored.includes(password));
  assert.equal(accountStore.verifyPassword(password, stored), true);
  assert.equal(accountStore.verifyPassword("falsch", stored), false);
});

test("account login authenticates by email and password", () => {
  const email = `unit-${Date.now()}-${Math.random().toString(16).slice(2)}@example.de`;
  accountStore.upsertAccount({ email, password: "PasswortStark1", role: "customer" });
  const session = login({ email, password: "PasswortStark1" });
  assert.equal(session.role, "customer");
  assert.equal(session.email, email.toLowerCase());
  assert.throws(() => login({ email, password: "falsch" }), /falsch/);
});

test("superadmin account unlocks every phase without an approval code and stores progress", () => {
  const email = `admin-${Date.now()}-${Math.random().toString(16).slice(2)}@example.de`;
  accountStore.upsertAccount({ email, password: "AdminStark12", role: "superadmin" });
  const session = login({ email, password: "AdminStark12" });
  assert.equal(session.role, "superadmin");
  const engagement = createEngagement({ target: "https://example.com", authorized: true, sessionToken: session.token });
  const maxPhase = engagement.unlockedPhase;
  assert.ok(maxPhase >= 1);
  assert.equal(requireEngagement(engagement.id, normalizeTarget("https://example.com"), maxPhase, session.token).id, engagement.id);
  const history = accountStore.getHistory(session.accountId);
  assert.ok(history.some((e) => e.engagementId === engagement.id));
});