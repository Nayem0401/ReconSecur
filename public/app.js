const form = document.querySelector("#assessment-form");
const runButton = document.querySelector("#run-button");
const stateLabel = document.querySelector("#state-label");
const stateTime = document.querySelector("#state-time");
const progressBar = document.querySelector("#progress-bar");
const findingList = document.querySelector("#finding-list");
const emptyState = document.querySelector("#empty-state");
const exportButton = document.querySelector("#export-button");
const nextSteps = document.querySelector("#next-steps");
let latestAssessment = null;

const wait = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));

function setProgress(index, label) {
  const steps = [...document.querySelectorAll(".steps li")];
  steps.forEach((step, stepIndex) => {
    step.classList.toggle("done", stepIndex < index);
    step.classList.toggle("active", stepIndex === index);
  });
  progressBar.style.width = `${Math.min((index / steps.length) * 100, 100)}%`;
  stateLabel.textContent = label;
}

function setMetric(id, value) {
  document.querySelector(id).textContent = value;
}

function renderFindings(assessment) {
  const priorityCount = assessment.findings.filter(({ severity }) => ["high", "medium"].includes(severity)).length;
  setMetric("#metric-status", assessment.summary.status);
  setMetric("#metric-total", assessment.findings.length);
  setMetric("#metric-priority", priorityCount);
  setMetric("#metric-addresses", assessment.summary.addresses.length);

  findingList.replaceChildren();
  for (const item of assessment.findings) {
    const article = document.createElement("article");
    article.className = "finding";

    const severity = document.createElement("span");
    severity.className = `severity ${item.severity}`;
    severity.textContent = item.severity;

    const identity = document.createElement("div");
    const title = document.createElement("h3");
    title.textContent = item.title;
    const evidence = document.createElement("p");
    evidence.textContent = item.evidence;
    identity.append(title, evidence);

    const recommendation = document.createElement("p");
    recommendation.className = "recommendation";
    recommendation.textContent = item.recommendation;
    article.append(severity, identity, recommendation);
    findingList.append(article);
  }

  emptyState.hidden = assessment.findings.length > 0;
  findingList.hidden = assessment.findings.length === 0;
  nextSteps.replaceChildren(...assessment.nextSteps.map((text) => {
    const item = document.createElement("li");
    item.textContent = text;
    return item;
  }));
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  runButton.disabled = true;
  runButton.textContent = "Assessment running...";
  stateTime.textContent = new Date().toLocaleTimeString("de-DE");

  try {
    setProgress(0, "Validating authorization");
    await wait(200);
    setProgress(1, "Resolving target");
    await wait(200);
    setProgress(2, "Inspecting web posture");

    const response = await fetch("/api/assessments", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        target: document.querySelector("#target").value,
        authorized: document.querySelector("#authorized").checked,
      }),
    });
    const result = await response.json();
    if (!response.ok) throw new Error(result.error || "Assessment failed.");

    setProgress(3, "Reviewing TLS evidence");
    await wait(250);
    latestAssessment = result;
    renderFindings(result);
    setProgress(5, "Assessment complete");
    progressBar.style.width = "100%";
    stateTime.textContent = `ID ${result.assessmentId.slice(0, 8)} / ${new Date(result.completedAt).toLocaleTimeString("de-DE")}`;
    exportButton.disabled = false;
    document.querySelector("#findings").scrollIntoView({ behavior: "smooth" });
  } catch (error) {
    setProgress(0, "Assessment blocked");
    stateTime.textContent = error.message;
    progressBar.style.width = "0";
  } finally {
    runButton.disabled = false;
    runButton.textContent = "Run passive assessment";
  }
});

exportButton.addEventListener("click", () => {
  if (!latestAssessment) return;
  const blob = new Blob([JSON.stringify(latestAssessment, null, 2)], { type: "application/json" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `aether-assessment-${latestAssessment.assessmentId}.json`;
  link.click();
  URL.revokeObjectURL(link.href);
});
