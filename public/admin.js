function $(sel) { return document.querySelector(sel); }

async function callAdmin(path, body) {
  const token = $("#admin-token").value.trim();
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Fehler (${response.status})`);
  return data;
}

async function mintLogin() {
  const errorEl = $("#login-code-error");
  const resultEl = $("#login-code-result");
  errorEl.textContent = "";
  resultEl.textContent = "";
  try {
    const data = await callAdmin("/api/admin/logins");
    resultEl.textContent = `Code: ${data.code}\nGueltig bis: ${data.expiresAt}`;
  } catch (err) {
    errorEl.textContent = err.message;
  }
}

async function mintApproval() {
  const errorEl = $("#approval-code-error");
  const resultEl = $("#approval-code-result");
  errorEl.textContent = "";
  resultEl.textContent = "";
  const target = $("#approval-target").value.trim();
  if (!target) {
    errorEl.textContent = "Ziel erforderlich.";
    return;
  }
  try {
    const data = await callAdmin("/api/admin/approvals", { target });
    resultEl.textContent = `Code: ${data.code}\nZiel: ${data.target}\nGueltig bis: ${data.expiresAt}`;
  } catch (err) {
    errorEl.textContent = err.message;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  $("#btn-mint-login").addEventListener("click", mintLogin);
  $("#btn-mint-approval").addEventListener("click", mintApproval);
});
