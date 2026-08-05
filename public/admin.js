function $(sel) { return document.querySelector(sel); }

async function callAdmin(path, body) {
  const token = $("#admin-token").value.trim();
  if (!token) {
    const err = new Error("Bitte zuerst das Admin-Token oben eintragen.");
    err.known = true;
    throw err;
  }
  const response = await fetch(path, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${token}` },
    body: JSON.stringify(body || {}),
  });
  const data = await response.json().catch(() => ({}));
  if (response.status === 503) {
    const err = new Error("Der Server wurde OHNE Admin-Token gestartet. Server neu starten mit gesetztem AETHER_ADMIN_TOKEN (siehe Status-Box).");
    err.known = true;
    throw err;
  }
  if (response.status === 403) {
    const err = new Error("Token stimmt nicht mit dem Server-Token (AETHER_ADMIN_TOKEN) ueberein.");
    err.known = true;
    throw err;
  }
  if (!response.ok) throw new Error(data.error || `Fehler (${response.status})`);
  return data;
}

async function refreshStatus() {
  const el = $("#status-text");
  try {
    const r = await fetch("/api/admin/status");
    const s = await r.json();
    if (s.adminConfigured) {
      el.innerHTML = `<span style="color:#1a7f3c">✓ Server bereit — Admin-Token ist gesetzt.</span> Master-Codes: ${s.masterCodes}.`;
      $("#server-status").style.borderLeftColor = "#34c759";
    } else {
      el.innerHTML = `<span style="color:#c0392b">✗ Server ohne Admin-Token gestartet.</span> Codeerzeugung ist deaktiviert. Server so neu starten:` +
        `<pre class="code-out" style="margin-top:8px">$env:AETHER_ADMIN_TOKEN="dein-token"\nnpm start</pre>`;
      $("#server-status").style.borderLeftColor = "#c0392b";
    }
  } catch {
    el.textContent = "Server nicht erreichbar.";
  }
}

async function mintLogin() {
  const errorEl = $("#login-code-error");
  const resultEl = $("#login-code-result");
  errorEl.textContent = "";
  resultEl.textContent = "";
  try {
    const data = await callAdmin("/api/admin/logins");
    resultEl.textContent = `Login-Code: ${data.code}\nGueltig bis: ${data.expiresAt}\n→ Diesen Code dem Kunden geben.`;
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
    errorEl.textContent = "Bitte eine Ziel-URL eingeben (z. B. https://example.com).";
    return;
  }
  try {
    const data = await callAdmin("/api/admin/approvals", { target });
    resultEl.textContent = `Freigabecode: ${data.code}\nZiel: ${data.target}\nGueltig bis: ${data.expiresAt}`;
  } catch (err) {
    errorEl.textContent = err.message;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  refreshStatus();
  $("#btn-mint-login").addEventListener("click", mintLogin);
  $("#btn-mint-approval").addEventListener("click", mintApproval);
});
