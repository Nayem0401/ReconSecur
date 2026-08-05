"use strict";

const state = {
  target: null,
  authorized: false,
  assessment: null,
  tools: null,
};

const $ = (sel) => document.querySelector(sel);

// ── Navigation ────────────────────────────────────────────────────────────────
function showPage(name) {
  document.querySelectorAll('[id^="page-"]').forEach((p) => { p.style.display = "none"; });
  const page = document.getElementById("page-" + name);
  if (page) page.style.display = "block";
  document.querySelectorAll(".nav-item").forEach((i) => {
    i.classList.toggle("active", i.dataset.page === name);
  });
  if (name === "tools" && !state.tools) loadTools();
}

// ── Terminal ──────────────────────────────────────────────────────────────────
function appendTerminal(targetId, cls, text) {
  const el = document.getElementById(targetId);
  if (!el) return;
  const span = document.createElement("span");
  if (cls) span.className = cls;
  span.textContent = text + "\n";
  el.appendChild(span);
  el.parentElement.scrollTop = el.parentElement.scrollHeight;
}

// ── Consent Modal ─────────────────────────────────────────────────────────────
function openConsent() { $("#consent-modal").classList.add("open"); }
function closeConsent() { $("#consent-modal").classList.remove("open"); }

function verifyConsent() {
  const target = $("#modal-domain").value.trim();
  const authorized = $("#modal-authorized").checked;
  if (!target) { $("#modal-domain").focus(); return; }
  if (!authorized) { $("#modal-authorized").focus(); return; }

  state.target = target;
  state.authorized = true;
  $("#scan-target").value = target;
  $("#authorized").checked = true;
  setConsentBadge(target);
  closeConsent();
  showPage("scan");
  appendTerminal("scan-output", "t-line-ok", `[ENGAGEMENT] Ziel gesetzt: ${target}`);
  appendTerminal("scan-output", "t-line-info", "[BEREIT] Passive Analyse kann gestartet werden.");
}

function setConsentBadge(target) {
  const badge = $("#consent-status");
  badge.className = "consent-badge verified";
  $("#consent-text").textContent = target;
  $("#engagement-sub").textContent = `Aktiv: ${target} — passive Analyse bereit`;
}

// ── Assessment ────────────────────────────────────────────────────────────────
async function runAssessment(event) {
  if (event) event.preventDefault();
  const target = $("#scan-target").value.trim();
  const authorized = $("#authorized").checked;
  const btn = $("#scan-btn");
  const outId = "scan-output";

  if (!target) { $("#scan-target").focus(); return; }
  if (!authorized) {
    appendTerminal(outId, "t-line-err", "[BLOCKIERT] Autorisierung nicht bestaetigt.");
    return;
  }

  state.target = target;
  setConsentBadge(target);
  btn.disabled = true;
  const original = btn.textContent;
  btn.textContent = "Analyse laeuft…";
  $("#scan-t-title").textContent = `scan — ${target}`;
  appendTerminal(outId, "t-prompt", `aether@local ~ % assess ${target}`);
  appendTerminal(outId, "t-line-info", "[1/4] Scope-Validierung…");

  try {
    const response = await fetch("/api/assessments", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ target, authorized: true }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Analyse fehlgeschlagen.");

    appendTerminal(outId, "t-line-info", `[2/4] DNS: ${result.summary.addresses.length} Adresse(n).`);
    appendTerminal(outId, "t-line-info", `[3/4] HTTP-Status ${result.summary.status} — ${result.summary.finalUrl}`);
    const tlsLine = result.summary.tls?.error
      ? `[4/4] TLS-Fehler: ${result.summary.tls.error}`
      : `[4/4] TLS: ${result.summary.tls?.protocol || "n/a"} (${result.summary.tls?.issuer || "?"})`;
    appendTerminal(outId, result.summary.tls?.error ? "t-line-warn" : "t-line-info", tlsLine);

    state.assessment = result;
    renderFindings(result);
    const critical = result.findings.filter((f) => ["critical", "high"].includes(f.severity)).length;
    appendTerminal(outId, "t-line-ok", `[FERTIG] ${result.findings.length} Findings, davon ${critical} High/Critical.`);
    showPage("findings");
  } catch (error) {
    appendTerminal(outId, "t-line-err", `[FEHLER] ${error.message}`);
  } finally {
    btn.disabled = false;
    btn.textContent = original;
  }
}

function renderFindings(assessment) {
  const tbody = $("#findings-tbody");
  const findings = assessment.findings;
  $("#findings-count").textContent = `${findings.length} Findings`;
  $("#m-findings").textContent = findings.length;
  $("#m-critical").textContent = findings.filter((f) => ["critical", "high"].includes(f.severity)).length;
  $("#export-btn").disabled = findings.length === 0;

  if (!findings.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text3);padding:32px">Keine Findings.</td></tr>';
    return;
  }

  tbody.replaceChildren();
  for (const f of findings) {
    const tr = document.createElement("tr");
    const sev = document.createElement("td");
    sev.innerHTML = `<span class="sev ${f.severity}"></span>`;
    sev.querySelector(".sev").textContent = f.severity;

    const title = document.createElement("td");
    const t = document.createElement("div"); t.className = "finding-title"; t.textContent = f.title;
    const id = document.createElement("div"); id.className = "finding-sub"; id.textContent = f.id;
    title.append(t, id);

    const ev = document.createElement("td");
    ev.className = "finding-sub"; ev.textContent = f.evidence;

    const rec = document.createElement("td");
    rec.style.fontSize = "12px"; rec.style.color = "var(--text2)"; rec.textContent = f.recommendation;

    tr.append(sev, title, ev, rec);
    tbody.append(tr);
  }
}

function exportFindings() {
  if (!state.assessment) return;
  const blob = new Blob([JSON.stringify(state.assessment, null, 2)], { type: "application/json" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = `aether-assessment-${state.assessment.assessmentId}.json`;
  a.click();
  URL.revokeObjectURL(a.href);
}

// ── Tools Inventory ───────────────────────────────────────────────────────────
async function loadTools() {
  const container = $("#tools-container");
  container.innerHTML = '<div class="empty-note">Inventar wird geladen… (WSL2-Erkennung kann einige Sekunden dauern)</div>';
  try {
    const response = await fetch("/api/tools");
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Inventar fehlgeschlagen.");
    state.tools = data;
    renderTools(data);
    updateToolMetrics(data);
  } catch (error) {
    container.innerHTML = `<div class="empty-note">Fehler: ${error.message}</div>`;
  }
}

function updateToolMetrics(data) {
  const distros = Object.entries(data.wsl || {});
  const kali = distros.find(([name]) => /kali/i.test(name)) || distros[0];
  if (kali) {
    $("#m-kali").textContent = kali[1].count;
    $("#m-kali-sub").textContent = `${kali[0]} · ${kali[1].execReady.length} allowlisted`;
  } else {
    $("#m-kali").textContent = "0";
    $("#m-kali-sub").textContent = "Keine WSL2-Distro";
  }
  $("#m-windows").textContent = data.windows.count;
  $("#m-windows-sub").textContent = `${data.windows.execReady.length} allowlisted`;
}

function toolGroup(title, meta, tools, execReady) {
  const ready = new Set(execReady);
  const group = document.createElement("div");
  group.className = "tool-group";
  const head = document.createElement("div");
  head.className = "tool-group-head";
  head.innerHTML = `<div class="tool-group-title">${title}</div><div class="tool-group-meta">${meta}</div>`;
  const list = document.createElement("div");
  list.className = "tool-list";
  for (const name of tools) {
    const chip = document.createElement("span");
    chip.className = "tool-chip" + (ready.has(name) ? " ready" : "");
    chip.dataset.name = name;
    chip.textContent = name;
    list.append(chip);
  }
  group.append(head, list);
  return group;
}

function renderTools(data) {
  const container = $("#tools-container");
  container.replaceChildren();
  container.append(toolGroup(
    "⊞ Windows",
    `${data.windows.count} Tools · ${data.windows.execReady.length} allowlisted`,
    data.windows.tools, data.windows.execReady,
  ));
  for (const [distro, info] of Object.entries(data.wsl || {})) {
    container.append(toolGroup(
      `🐧 ${distro}`,
      `${info.count} Tools · ${info.execReady.length} allowlisted`,
      info.tools, info.execReady,
    ));
  }
  applyToolFilter();
}

function applyToolFilter() {
  const q = ($("#tools-filter").value || "").trim().toLowerCase();
  document.querySelectorAll(".tool-chip").forEach((chip) => {
    chip.classList.toggle("hidden", q && !chip.dataset.name.includes(q));
  });
}

// ── Wiring ────────────────────────────────────────────────────────────────────
document.addEventListener("click", (event) => {
  const nav = event.target.closest(".nav-item");
  if (nav) { showPage(nav.dataset.page); return; }
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (action === "open-consent") openConsent();
  else if (action === "close-consent") closeConsent();
  else if (action === "verify-consent") verifyConsent();
  else if (action === "export") exportFindings();
  else if (action === "refresh-tools") { state.tools = null; loadTools(); }
});

document.addEventListener("DOMContentLoaded", () => {
  $("#assessment-form").addEventListener("submit", runAssessment);
  $("#tools-filter").addEventListener("input", applyToolFilter);
  $("#consent-modal").addEventListener("click", (e) => { if (e.target.id === "consent-modal") closeConsent(); });
  loadTools();
});
