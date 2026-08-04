const test = require("node:test");
const assert = require("node:assert/strict");
const { inspectHeaders, isPrivateAddress, normalizeTarget } = require("../server");

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