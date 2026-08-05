const test = require("node:test");
const assert = require("node:assert/strict");
const { inspectHeaders, isPrivateAddress, normalizeTarget, createServer } = require("../server");
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