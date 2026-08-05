"use strict";

const state = {
  target: null,
  authorized: false,
  engagement: null,
  loginSession: null,
  assessment: null,
  tools: null,
  selectedTool: null,
  selectedEntry: null,
  catalog: null,
  activePhase: null,
  session: null,
  eventSource: null,
  reconSources: [],
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

async function verifyConsent() {
  const target = $("#modal-domain").value.trim();
  const loginCode = $("#modal-login-code").value.trim();
  const approvalCode = $("#modal-approval-code").value.trim().toUpperCase();
  const authorized = $("#modal-authorized").checked;
  if (!target) { $("#modal-domain").focus(); return; }
  if (!loginCode) { $("#modal-login-code").focus(); return; }
  if (!authorized) { $("#modal-authorized").focus(); return; }

  try {
    const loginResponse = await fetch("/api/login", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ code: loginCode }),
    });
    const session = await loginResponse.json();
    if (!loginResponse.ok) throw new Error(session.error || "Login fehlgeschlagen.");
    if (session.role !== "master" && approvalCode.length !== 20) {
      $("#modal-approval-code").focus();
      throw new Error("Admin-Freigabecode (20 Zeichen) erforderlich.");
    }
    state.loginSession = session;

    const response = await fetch("/api/engagements", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        target,
        authorized: true,
        sessionToken: session.token,
        ...(session.role !== "master" ? { approvalCode } : {}),
      }),
    });
    const engagement = await response.json();
    if (!response.ok) throw new Error(engagement.error || "Engagement konnte nicht erstellt werden.");

    state.engagement = engagement;
    state.target = engagement.target;
    state.authorized = true;
    $("#scan-target").value = engagement.target;
    $("#authorized").checked = true;
    $("#consent-error").textContent = "";
    setConsentBadge(engagement.target);
    if (state.tools) renderTools(state.tools);
    closeConsent();
    showPage("scan");
    appendTerminal("scan-output", "t-line-ok", `[ENGAGEMENT] Ziel gesetzt: ${engagement.target} (Rolle: ${session.role})`);
    appendTerminal("scan-output", "t-line-info", `[BEREIT] Phasen 1-${engagement.unlockedPhase} sind freigegeben.`);
  } catch (error) {
    $("#consent-error").textContent = error.message;
  }
}

function setConsentBadge(target) {
  const badge = $("#consent-status");
  badge.className = "consent-badge verified";
  $("#consent-text").textContent = target;
  const phase = state.engagement?.unlockedPhase || 1;
  const maxPhase = state.catalog ? Math.max(...[...state.catalog.values()].map((t) => t.phase)) : phase;
  $("#engagement-sub").textContent = `Aktiv: ${target} — Phase ${phase}/${maxPhase} freigegeben`;
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
  if (!state.engagement) {
    appendTerminal(outId, "t-line-err", "[BLOCKIERT] Serverseitiges Engagement erforderlich.");
    return;
  }

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
      body: JSON.stringify({ target, engagementId: state.engagement.id, sessionToken: state.loginSession.token }),
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

function renderTools(data) {
  state.catalog = new Map((data.catalog || []).map((t) => [t.name, t]));
  renderPhaseTabs(data);
  renderCategoryOptions(data);
  renderToolCatalog(data);
  applyToolFilter();
  updateReconBar();
  updatePhaseGate();
}

function renderPhaseTabs(data) {
  const wrap = $("#phase-tabs");
  if (!wrap) return;
  const phases = [...new Map((data.catalog || []).map((t) => [t.phase, t.phaseName])).entries()]
    .sort((a, b) => a[0] - b[0]);
  if (state.activePhase == null && phases.length) state.activePhase = phases[0][0];
  wrap.replaceChildren();
  for (const [phase, label] of phases) {
    const count = (data.catalog || []).filter((t) => t.phase === phase).length;
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "phase-tab" + (phase === state.activePhase ? " active" : "");
    btn.dataset.phase = phase;
    btn.textContent = `${label} · ${count}`;
    wrap.append(btn);
  }
}

function renderCategoryOptions(data) {
  const select = $("#tools-category");
  const categories = [...new Set((data.catalog || []).map((t) => t.category))];
  select.replaceChildren(new Option("Alle Kategorien", ""));
  for (const category of categories) select.append(new Option(category, category));
}

function execReadySet(data) {
  return new Set([...data.windows.execReady, ...Object.values(data.wsl || {}).flatMap((i) => i.execReady)]);
}

function renderToolCatalog(data) {
  const container = $("#tools-container");
  container.replaceChildren();
  const ready = execReadySet(data);
  const groups = new Map();
  for (const tool of data.catalog || []) {
    if (!groups.has(tool.category)) groups.set(tool.category, []);
    groups.get(tool.category).push(tool);
  }
  if (!groups.size) {
    container.innerHTML = '<div class="empty-note">Katalog konnte nicht geladen werden.</div>';
    return;
  }

  for (const [category, tools] of groups) {
    const group = document.createElement("div");
    group.className = "tool-group";
    group.dataset.category = category;
    const head = document.createElement("div");
    head.className = "tool-group-head";
    const avail = tools.filter((t) => ready.has(t.name)).length;
    head.innerHTML = `<div class="tool-group-title">${category}</div><div class="tool-group-meta">${avail}/${tools.length} verfuegbar</div>`;
    const body = document.createElement("div");
    body.className = "catalog-list";

    for (const tool of tools) {
      const installed = ready.has(tool.name);
      const phaseUnlocked = state.engagement && tool.phase <= state.engagement.unlockedPhase;
      const row = document.createElement("details");
      row.className = "tool-details" + (installed ? "" : " tool-unavailable");
      row.dataset.name = tool.name;
      row.dataset.category = category;
      row.dataset.phase = tool.phase;
      const summary = document.createElement("summary");
      const name = document.createElement("span"); name.className = "cat-name"; name.textContent = tool.name;
      const desc = document.createElement("span"); desc.className = "cat-desc"; desc.textContent = tool.summary;
      const load = document.createElement("button");
      load.type = "button"; load.className = "btn btn-secondary run-select";
      if (installed && phaseUnlocked) {
        load.textContent = "▶ Starten"; load.dataset.select = tool.name;
      } else if (installed) {
        load.textContent = `Phase ${tool.phase} gesperrt`; load.disabled = true;
        load.title = "Diese Phase muss im Engagement explizit freigegeben werden.";
      } else {
        load.textContent = "nicht installiert"; load.disabled = true; load.title = "Tool in Windows-PATH oder WSL2/Kali installieren.";
      }
      summary.append(name, desc, load);
      row.append(summary);

      if (tool.usage.length) {
        const table = document.createElement("div");
        table.className = "usage-list";
        for (const u of tool.usage) {
          const line = document.createElement("div");
          line.className = "usage-row";
          const flag = document.createElement("code"); flag.textContent = u.flag;
          const d = document.createElement("span"); d.textContent = u.description;
          line.append(flag, d);
          table.append(line);
        }
        row.append(table);
      }
      body.append(row);
    }
    group.append(head, body);
    container.append(group);
  }
}

function toolEnvironments() {
  const envs = [];
  if (state.tools?.windows?.execReady?.includes(state.selectedTool)) envs.push({ env: "windows", label: "Windows" });
  for (const [distro, info] of Object.entries(state.tools?.wsl || {})) {
    if (info.execReady.includes(state.selectedTool)) envs.push({ env: "wsl", distro, label: `WSL · ${distro}` });
  }
  return envs;
}

function selectTool(name) {
  const entry = state.catalog?.get(name);
  if (!entry) return;
  if (!state.engagement || entry.phase > state.engagement.unlockedPhase) return;
  state.selectedTool = name;
  state.selectedEntry = entry;
  $("#tool-run-panel").hidden = false;
  $("#run-tool").value = name;

  const envSelect = $("#run-env");
  envSelect.replaceChildren();
  const envs = toolEnvironments();
  for (const e of envs) {
    const opt = new Option(e.label, e.env);
    if (e.distro) opt.dataset.distro = e.distro;
    envSelect.append(opt);
  }
  const targetInput = $("#run-target");
  targetInput.placeholder = entry.target.placeholder || "https://ziel.example";
  targetInput.title = entry.target.note || "";
  targetInput.value = state.engagement.target || $("#scan-target")?.value || "";
  renderToolOptions();
  $("#run-start").disabled = envs.length === 0;
  $("#tool-run-panel").scrollIntoView({ behavior: "smooth", block: "nearest" });
}

function optionField(field) {
  const wrap = document.createElement("div");
  wrap.className = "field opt-field";
  const label = document.createElement("label");
  label.setAttribute("for", `opt-${field.key}`);
  label.textContent = field.label;

  let input;
  if (field.type === "boolean") {
    wrap.classList.add("opt-boolean");
    input = document.createElement("input");
    input.type = "checkbox";
    input.checked = !!field.default;
    label.prepend(input);
    label.classList.add("checkbox");
    wrap.append(label);
  } else if (field.type === "enum") {
    input = document.createElement("select");
    for (const v of field.values) input.append(new Option(v, v));
    if (field.default) input.value = field.default;
    wrap.append(label, input);
  } else {
    input = document.createElement("input");
    input.type = field.type === "integer" ? "number" : "text";
    if (field.min !== undefined) input.min = field.min;
    if (field.max !== undefined) input.max = field.max;
    if (field.placeholder) input.placeholder = field.placeholder;
    if (field.default !== undefined) input.value = field.default;
    wrap.append(label, input);
  }
  input.id = `opt-${field.key}`;
  input.dataset.key = field.key;
  input.addEventListener("input", buildCommandPreview);
  input.addEventListener("change", buildCommandPreview);

  if (field.desc) {
    const hint = document.createElement("div");
    hint.className = "opt-hint";
    hint.textContent = field.desc;
    wrap.append(hint);
  }
  return wrap;
}

function renderToolOptions() {
  const container = $("#run-options");
  container.replaceChildren();
  const e = state.selectedEntry;
  for (const field of [...(e.flags || []), ...(e.positional || [])]) container.append(optionField(field));
  buildCommandPreview();
}

function collectOptions() {
  const options = {};
  document.querySelectorAll("#run-options [data-key]").forEach((el) => {
    if (el.type === "checkbox") options[el.dataset.key] = el.checked ? "on" : "off";
    else if (el.value !== "") options[el.dataset.key] = el.value;
  });
  return options;
}

function buildCommandPreview() {
  const e = state.selectedEntry;
  if (!e) return;
  const o = collectOptions();
  let target = $("#run-target").value.trim() || e.target.placeholder || "<ziel>";
  const prefixField = (e.flags || []).find((f) => f.role === "prefix");
  if (prefixField) {
    const val = o[prefixField.key] ?? prefixField.default;
    if (val && val !== "(root)") target = `${val}.${target.replace(/^https?:\/\//, "")}`;
  }
  const parts = [e.name, ...(e.prefix || [])];
  if (e.sni) parts.push("-servername", target.replace(/^https?:\/\//, "").split("/")[0].split(":")[0]);

  for (const f of e.flags || []) {
    if (f.role === "prefix") continue;
    if (f.type === "boolean") {
      if (o[f.key] === "on") parts.push(f.flag);
      continue;
    }
    const v = o[f.key] ?? f.default;
    if (v === undefined || v === "") continue;
    const join = f.join || "space";
    if (join === "equals") parts.push(`${f.flag}=${v}`);
    else if (join === "append") parts.push(`${f.flag}${v}`);
    else parts.push(f.flag, String(v));
  }
  if (e.target.arg) parts.push(e.target.arg, target);
  else parts.push(target);
  for (const f of e.positional || []) {
    const v = o[f.key] ?? f.default;
    if (v) parts.push(String(v));
  }
  $("#run-preview").textContent = parts.join(" ");
}

async function startToolSession(event) {
  if (event) event.preventDefault();
  const target = $("#run-target").value.trim();
  if (!target) { $("#run-target").focus(); return; }
  if (!state.engagement) {
    appendSession("t-line-err", "[BLOCKIERT] Serverseitiges Engagement erforderlich.");
    return;
  }
  const envOpt = $("#run-env").selectedOptions[0];
  const body = {
    engagementId: state.engagement.id,
    sessionToken: state.loginSession.token,
    tool: state.selectedTool,
    target,
    env: envOpt?.value,
    distro: envOpt?.dataset.distro,
    options: collectOptions(),
  };

  try {
    const response = await fetch("/api/tool-sessions", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });
    const session = await response.json();
    if (!response.ok) throw new Error(session.error || "Session konnte nicht gestartet werden.");
    attachSession(session);
  } catch (error) {
    appendSession("t-line-err", `[FEHLER] ${error.message}`);
  }
}

function appendSession(cls, text) {
  const el = $("#session-output");
  const span = document.createElement("span");
  if (cls) span.className = cls;
  span.textContent = text.endsWith("\n") ? text : text + "\n";
  el.appendChild(span);
  el.parentElement.scrollTop = el.parentElement.scrollHeight;
}

function attachSession(session) {
  if (state.eventSource) state.eventSource.close();
  state.session = session;
  $("#session-output").replaceChildren();
  $("#session-title").textContent = `${session.command.join(" ")}`;
  $("#session-cancel").hidden = false;
  appendSession("t-line-info", `[SESSION ${session.id.slice(0, 8)}] gestartet · ${session.tool} → ${session.target}`);

  state.eventSource = wireStream(session, appendSession, () => { $("#session-cancel").hidden = true; });
}

// Verbindet eine Session mit einem SSE-Stream. append(cls,text) rendert Zeilen,
// onExit(status) laeuft beim Prozessende. Wird von Einzel- und Batch-Terminals genutzt.
function wireStream(session, append, onExit) {
  const source = new EventSource(`/api/tool-sessions/${session.id}/events`);
  source.addEventListener("stdout", (e) => append("", JSON.parse(e.data).data.text));
  source.addEventListener("stderr", (e) => append("t-line-warn", JSON.parse(e.data).data.text));
  source.addEventListener("error", (e) => { if (e.data) append("t-line-err", `[FEHLER] ${JSON.parse(e.data).data.message}`); });
  source.addEventListener("timeout", () => append("t-line-warn", "[TIMEOUT] Session beendet."));
  source.addEventListener("cancel", () => append("t-line-warn", "[ABBRUCH] Session gestoppt."));
  source.addEventListener("exit", (e) => {
    const d = JSON.parse(e.data).data;
    append(d.status === "completed" ? "t-line-ok" : "t-line-err", `[EXIT] Code ${d.code} · ${d.status}`);
    onExit?.(d.status);
    source.close();
  });
  // Nicht schliessen: EventSource reconnectet bei Netz-/Proxy-Unterbrechungen
  // automatisch mit Last-Event-ID; explizites close() passiert nur im exit-Handler.
  source.onerror = () => append("t-line-warn", "[VERBINDUNG] Stream unterbrochen, verbinde erneut…");
  return source;
}

// ── Recon-Batch: alle Phase-1-Tools parallel ───────────────────────────────────
function phase1Tools() {
  if (!state.catalog) return [];
  return [...state.catalog.values()].filter((e) => e.phase === 1).map((e) => e.name);
}

function reconEnvironments() {
  const names = phase1Tools();
  const envs = [];
  if (names.some((n) => state.tools?.windows?.execReady?.includes(n))) envs.push({ env: "windows", label: "Windows" });
  for (const [distro, info] of Object.entries(state.tools?.wsl || {})) {
    if (names.some((n) => info.execReady.includes(n))) envs.push({ env: "wsl", distro, label: `WSL · ${distro}` });
  }
  return envs;
}

function updateReconBar() {
  const bar = $("#recon-batch");
  if (!bar) return;
  const show = state.activePhase === 1;
  bar.hidden = !show;
  if (!show) return;
  const sel = $("#recon-env");
  const current = sel.value;
  sel.replaceChildren();
  const envs = reconEnvironments();
  for (const e of envs) {
    const opt = new Option(e.label, e.env);
    if (e.distro) opt.dataset.distro = e.distro;
    sel.append(opt);
  }
  if (current) sel.value = current;
  $("#recon-start").disabled = envs.length === 0 || !state.engagement;
  if (!$("#recon-target").value) $("#recon-target").value = state.engagement?.target || $("#scan-target")?.value || "";
}

function envAvailableTools(env, distro) {
  const ready = env === "windows" ? state.tools?.windows?.execReady : state.tools?.wsl?.[distro]?.execReady;
  return phase1Tools().filter((n) => ready?.includes(n));
}

async function runReconBatch() {
  const target = $("#recon-target").value.trim();
  if (!target) { $("#recon-target").focus(); return; }
  if (!state.engagement) {
    $("#recon-hint").textContent = "Serverseitiges Engagement erforderlich.";
    return;
  }
  const envOpt = $("#recon-env").selectedOptions[0];
  if (!envOpt) { $("#recon-hint").textContent = "Keine Umgebung verfuegbar."; return; }
  const env = envOpt.value;
  const distro = envOpt.dataset.distro;
  const tools = envAvailableTools(env, distro);
  if (!tools.length) { $("#recon-hint").textContent = "Keine Recon-Tools in dieser Umgebung installiert."; return; }

  state.reconSources.forEach((s) => s.close());
  state.reconSources = [];
  $("#recon-grid").replaceChildren();
  $("#recon-hint").textContent = `Starte ${tools.length} Tools parallel…`;

  try {
    const response = await fetch("/api/recon-runs", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ engagementId: state.engagement.id, sessionToken: state.loginSession.token, target, env, distro, tools }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Recon konnte nicht gestartet werden.");
    for (const session of data.sessions) addReconCell(session);
    $("#recon-hint").textContent = `${data.sessions.length} Tools laufen gegen ${target}.`;
  } catch (error) {
    $("#recon-hint").textContent = `Fehler: ${error.message}`;
  }
}

function addReconCell(session) {
  const cell = document.createElement("div");
  cell.className = "recon-cell";
  cell.dataset.id = session.id;

  const head = document.createElement("div");
  head.className = "recon-cell-head";
  const dot = document.createElement("span");
  dot.className = "recon-dot running";
  const name = document.createElement("span");
  name.className = "recon-cell-name";
  name.textContent = session.tool;
  const cancel = document.createElement("button");
  cancel.className = "recon-cell-cancel";
  cancel.type = "button";
  cancel.dataset.cancel = session.id;
  cancel.textContent = "■";
  head.append(dot, name, cancel);

  const out = document.createElement("pre");
  out.className = "recon-cell-out";
  out.setAttribute("role", "log");
  cell.append(head, out);
  $("#recon-grid").append(cell);

  const append = (cls, text) => {
    const span = document.createElement("span");
    if (cls) span.className = cls;
    span.textContent = text.endsWith("\n") ? text : text + "\n";
    out.append(span);
    out.scrollTop = out.scrollHeight;
  };
  append("t-line-info", `$ ${session.command.join(" ")}`);

  const source = wireStream(session, append, (status) => {
    dot.className = `recon-dot ${status === "completed" ? "done" : "fail"}`;
    cancel.hidden = true;
  });
  state.reconSources.push(source);
}

async function cancelSession() {
  if (!state.session) return;
  await fetch(`/api/tool-sessions/${state.session.id}`, { method: "DELETE" });
}

function applyToolFilter() {
  const q = ($("#tools-filter").value || "").trim().toLowerCase();
  const cat = $("#tools-category").value || "";
  const phase = state.activePhase;
  document.querySelectorAll(".tool-details").forEach((row) => {
    const hide = (q && !row.dataset.name.includes(q))
      || (cat && row.dataset.category !== cat)
      || (phase != null && Number(row.dataset.phase) !== phase);
    row.classList.toggle("hidden", !!hide);
  });
  document.querySelectorAll(".tool-group").forEach((group) => {
    const visible = [...group.querySelectorAll(".tool-details")].some((r) => !r.classList.contains("hidden"));
    group.classList.toggle("hidden", !visible);
  });
}

function updatePhaseGate() {
  const status = $("#phase-gate-status");
  const button = $("#phase-advance");
  if (!status || !button) return;
  const phase = state.activePhase;
  const engagement = state.engagement;
  if (!engagement || phase == null) {
    status.textContent = "Engagement erforderlich";
    button.disabled = true;
    button.textContent = "Phase freigeben";
    return;
  }
  if (phase <= engagement.unlockedPhase) {
    status.textContent = `Phase ${phase} freigegeben (${engagement.role})`;
    button.disabled = true;
    button.textContent = "Phase freigegeben";
    return;
  }
  if (phase === engagement.unlockedPhase + 1) {
    status.textContent = `Phase ${phase} bereit zur Freigabe`;
    button.disabled = false;
    button.textContent = `Phase ${phase} freigeben`;
    return;
  }
  status.textContent = `Zuerst Phase ${engagement.unlockedPhase + 1} freigeben`;
  button.disabled = true;
  button.textContent = "Phase freigeben";
}

async function advancePhase() {
  const engagement = state.engagement;
  const phase = state.activePhase;
  if (!engagement || phase !== engagement.unlockedPhase + 1) return;
  const button = $("#phase-advance");
  button.disabled = true;
  try {
    const response = await fetch(`/api/engagements/${engagement.id}/phases`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ phase, sessionToken: state.loginSession.token }),
    });
    const updated = await response.json();
    if (!response.ok) throw new Error(updated.error || "Phase konnte nicht freigegeben werden.");
    state.engagement = updated;
    setConsentBadge(updated.target);
    renderTools(state.tools);
  } catch (error) {
    $("#phase-gate-status").textContent = error.message;
    updatePhaseGate();
  }
}

// ── Wiring ────────────────────────────────────────────────────────────────────
document.addEventListener("click", (event) => {
  const nav = event.target.closest(".nav-item");
  if (nav) { showPage(nav.dataset.page); return; }
  const phaseTab = event.target.closest(".phase-tab");
  if (phaseTab) {
    state.activePhase = Number(phaseTab.dataset.phase);
    document.querySelectorAll(".phase-tab").forEach((t) => t.classList.toggle("active", t === phaseTab));
    applyToolFilter();
    updateReconBar();
    updatePhaseGate();
    return;
  }
  const cancelId = event.target.closest("[data-cancel]")?.dataset.cancel;
  if (cancelId) { fetch(`/api/tool-sessions/${cancelId}`, { method: "DELETE" }); return; }
  const select = event.target.closest("[data-select]");
  if (select) { event.preventDefault(); selectTool(select.dataset.select); return; }
  const action = event.target.closest("[data-action]")?.dataset.action;
  if (action === "open-consent") openConsent();
  else if (action === "close-consent") closeConsent();
  else if (action === "verify-consent") verifyConsent();
  else if (action === "export") exportFindings();
  else if (action === "cancel-session") cancelSession();
  else if (action === "run-recon") runReconBatch();
  else if (action === "advance-phase") advancePhase();
  else if (action === "refresh-tools") { state.tools = null; loadTools(); }
});

document.addEventListener("DOMContentLoaded", () => {
  $("#assessment-form").addEventListener("submit", runAssessment);
  $("#tools-filter").addEventListener("input", applyToolFilter);
  $("#tools-category").addEventListener("change", applyToolFilter);
  $("#tool-run-form").addEventListener("submit", startToolSession);
  $("#run-target").addEventListener("input", buildCommandPreview);
  $("#run-env").addEventListener("change", buildCommandPreview);
  $("#consent-modal").addEventListener("click", (e) => { if (e.target.id === "consent-modal") closeConsent(); });
  loadTools();
});
