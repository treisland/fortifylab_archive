"use strict";
const endpoints = ["components", "health", "preflight", "history"];
const stateNames = new Set(["healthy", "degraded", "unhealthy", "unknown", "blocked", "stale", "starting", "misconfigured", "stopped", "unreachable"]);
const cleanState = value => stateNames.has(String(value).toLowerCase()) ? String(value).toLowerCase() : "unknown";
const text = (element, value) => { element.textContent = value == null || value === "" ? "—" : String(value); };
const byId = id => document.getElementById(id);
const status = value => {
  const span = document.createElement("span");
  const state = cleanState(value);
  span.className = `status ${state}`;
  span.textContent = state;
  return span;
};
const safeDate = value => {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? "Unknown time" : date.toLocaleString();
};
let selectedPlan = null;
let activeOperationId = sessionStorage.getItem("fortifylab.activeOperation");
let progressTimer = null;

async function readModel(name) {
  const response = await fetch(`/api/v1alpha1/${name}`, {headers: {"Accept": "application/json"}});
  if (response.status === 401) { window.location.assign("/"); throw new Error("session expired"); }
  if (!response.ok) throw new Error(`${name} unavailable`);
  return response.json();
}

function renderInventory(document) {
  const items = Array.isArray(document.items) ? document.items : [];
  text(byId("component-count"), items.length);
  text(byId("component-detail"), `${items.filter(item => (item.observedResources || []).every(resource => resource.state === "present")).length} fully observed`);
  const disconnected = document.observation?.state !== "available";
  const cluster = byId("cluster-state");
  cluster.className = `status ${disconnected ? "unreachable" : "healthy"}`;
  text(cluster, disconnected ? "Disconnected" : "Connected");
  const graph = byId("dependency-graph");
  graph.replaceChildren();
  for (const item of items) {
    const card = documentNode("article", "component-card");
    const heading = documentNode("div", "component-title");
    heading.append(documentNode("strong", "", item.identity?.displayName), status(
      disconnected ? "unknown" : ((item.observedResources || []).every(resource => resource.state === "present") ? "healthy" : "stopped")
    ));
    const versions = Object.entries(item.version?.images || {}).map(([name, version]) => `${name}: ${version}`).join(" · ");
    card.append(heading, documentNode("p", "version", versions || item.version?.chart || "Version not declared"));
    const dependencies = (item.dependencies || []).join(", ") || "Lab foundation";
    card.append(documentNode("p", "dependencies", `Depends on: ${dependencies}`));
    graph.append(card);
  }
  byId("inventory-empty").hidden = items.length !== 0;
  const choices = byId("operation-components");
  const selected = new Set(Array.from(choices.selectedOptions).map(item => item.value));
  choices.replaceChildren();
  for (const item of items) {
    const option = documentNode("option", "", item.identity?.displayName || item.identity?.id);
    option.value = item.identity?.id || "";
    option.selected = selected.has(option.value);
    choices.append(option);
  }
}

function renderHealth(document) {
  const items = Array.isArray(document.items) ? document.items : [];
  const state = cleanState(document.state);
  const overall = byId("environment-state");
  overall.className = `status ${state}`;
  text(overall, state);
  text(byId("checked-at"), document.generatedAt ? `Checked ${safeDate(document.generatedAt)}` : "Not checked");
  const list = byId("health-list");
  list.replaceChildren();
  const failures = items.filter(item => item.state !== "healthy");
  for (const item of (failures.length ? failures : items.slice(0, 3))) {
    const article = documentNode("article", "evidence-card");
    const heading = documentNode("div", "evidence-title");
    heading.append(documentNode("strong", "", item.displayName), status(item.state));
    article.append(heading);
    if (item.rootCause) article.append(documentNode("p", "root-cause", `Root cause: ${item.rootCause}`));
    for (const evidence of item.evidence || []) {
      const row = documentNode("div", "evidence-row");
      row.append(status(evidence.state), documentNode("span", "", evidence.summary));
      article.append(row);
    }
    if (item.remediation?.href) {
      const link = document.createElement("a");
      link.href = item.remediation.href;
      link.textContent = item.remediation.summary || "Open remediation";
      article.append(link);
    }
    list.append(article);
  }
  byId("health-empty").hidden = items.length !== 0;
}

function renderPreflight(document) {
  const items = Array.isArray(document.items) ? document.items : [];
  const state = byId("preflight-state");
  state.className = `status ${document.ready ? "healthy" : "blocked"}`;
  text(state, document.ready ? "Ready" : "Blocked");
  const summary = document.summary || {};
  text(byId("preflight-detail"), `${summary.blocker || 0} blockers · ${summary.warning || 0} warnings`);
  const list = byId("preflight-list");
  list.replaceChildren();
  for (const item of items.filter(item => item.status !== "pass").slice(0, 8)) {
    const article = documentNode("article", "check-row");
    article.append(status(item.status === "fail" ? "blocked" : "degraded"), documentNode("span", "", item.summary));
    if (item.remediation?.href) {
      const link = document.createElement("a");
      link.href = item.remediation.href;
      link.textContent = item.remediation.summary;
      article.append(link);
    }
    list.append(article);
  }
  if (!list.children.length && items.length) list.append(documentNode("p", "success-message", "All preflight checks passed."));
  byId("preflight-empty").hidden = items.length !== 0;
}

function renderHistory(document) {
  const items = Array.isArray(document.items) ? document.items : [];
  const body = byId("history-list");
  body.replaceChildren();
  for (const item of items) {
    const row = document.createElement("tr");
    for (const value of [safeDate(item.occurredAt), item.kind, item.subject, item.summary]) {
      const cell = document.createElement("td");
      text(cell, value);
      row.append(cell);
    }
    const cell = document.createElement("td");
    cell.append(status(item.state));
    row.append(cell);
    body.append(row);
  }
  byId("history-empty").hidden = items.length !== 0;
  byId("history-empty").previousElementSibling.hidden = items.length === 0;
}

function documentNode(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content != null) node.textContent = String(content);
  return node;
}

async function load() {
  byId("loading").hidden = false;
  byId("api-error").hidden = true;
  const results = await Promise.allSettled(endpoints.map(readModel));
  const renderers = [renderInventory, renderHealth, renderPreflight, renderHistory];
  results.forEach((result, index) => {
    if (result.status === "fulfilled") renderers[index](result.value);
  });
  byId("loading").hidden = true;
  byId("api-error").hidden = results.some(result => result.status === "rejected");
  if (activeOperationId) await refreshOperation();
}

async function mutate(path, body = {}) {
  const response = await fetch(path, {
    method: "POST",
    headers: {"Accept": "application/json", "Content-Type": "application/json"},
    body: JSON.stringify(body)
  });
  if (response.status === 401) { window.location.assign("/"); throw new Error("session expired"); }
  const document = await response.json();
  if (!response.ok) throw new Error(document.message || "operation request failed");
  return document;
}

function operationRequest() {
  return {
    operation: byId("operation").value,
    components: Array.from(byId("operation-components").selectedOptions).map(item => item.value)
  };
}

byId("operation-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    selectedPlan = await mutate("/api/v1alpha1/operations/plans", operationRequest());
    text(byId("plan-risk"), `${selectedPlan.risk} risk`);
    text(byId("plan-impact"), selectedPlan.dependencyImpact.length ? `Adds dependencies: ${selectedPlan.dependencyImpact.join(", ")}` : "No implicit dependency additions");
    const list = byId("plan-steps");
    list.replaceChildren();
    selectedPlan.steps.forEach(step => list.append(documentNode("li", "", `${step.operation} ${step.component} · timeout ${step.timeoutSeconds}s · ${step.verificationChecks.length} health checks`)));
    byId("operation-plan").hidden = false;
    byId("operation-message").hidden = true;
  } catch (error) { showOperationMessage(error.message, true); }
});

byId("cancel-plan").addEventListener("click", () => {
  selectedPlan = null;
  byId("operation-plan").hidden = true;
});

byId("execute-operation").addEventListener("click", () => {
  if (!selectedPlan) return;
  if (selectedPlan.approvalRequired || selectedPlan.destructive) {
    const deletion = selectedPlan.deletesData ? " This permanently deletes persistent data and is separate from uninstall." : "";
    text(byId("confirmation-detail"), `Confirm ${selectedPlan.operation} for ${selectedPlan.requestedTargets.join(", ")}.${deletion}`);
    const high = selectedPlan.risk === "high";
    byId("high-risk-label").hidden = !high;
    byId("high-risk-confirmation").hidden = !high;
    byId("operation-confirmation").showModal();
  } else startOperation();
});

byId("operation-confirmation").addEventListener("close", () => {
  if (byId("operation-confirmation").returnValue === "confirm") startOperation();
});

async function startOperation() {
  try {
    const request = {operation: selectedPlan.operation, components: selectedPlan.requestedTargets};
    if (selectedPlan.approvalRequired) {
      const approval = await mutate("/api/v1alpha1/approvals", request);
      const approved = await mutate(`/api/v1alpha1/approvals/${approval.id}/approve`, {
        confirmation: selectedPlan.risk === "high" ? byId("high-risk-confirmation").value : null
      });
      request.approvalId = approved.id;
    }
    const operation = await mutate("/api/v1alpha1/operations", request);
    activeOperationId = operation.id;
    sessionStorage.setItem("fortifylab.activeOperation", activeOperationId);
    byId("operation-plan").hidden = true;
    renderOperation(operation);
    scheduleProgress();
  } catch (error) { showOperationMessage(error.message, true); }
}

function renderOperation(operation) {
  byId("operation-progress").hidden = false;
  text(byId("progress-summary"), `${operation.operation} · ${operation.state} · ${operation.completedSteps}/${operation.totalSteps} steps · completion health: ${operation.completionHealth}`);
  byId("progress-bar").max = operation.totalSteps;
  byId("progress-bar").value = operation.completedSteps;
  const events = byId("progress-events");
  events.replaceChildren();
  (operation.events || []).forEach(event => events.append(documentNode("li", "", `${event.type} · ${event.component || "operation"} · attempt ${event.attempt || "—"}`)));
  byId("cancel-operation").hidden = operation.terminal;
  byId("retry-operation").hidden = !["failed", "timed-out", "interrupted"].includes(operation.state);
  if (operation.terminal) {
    clearTimeout(progressTimer);
    sessionStorage.removeItem("fortifylab.activeOperation");
  }
}

async function refreshOperation() {
  try {
    const response = await fetch(`/api/v1alpha1/operations/${activeOperationId}`, {headers: {"Accept": "application/json"}});
    if (!response.ok) throw new Error("operation state unavailable");
    const operation = await response.json();
    renderOperation(operation);
    if (!operation.terminal) scheduleProgress();
  } catch (error) { showOperationMessage(error.message, true); }
}

function scheduleProgress() {
  clearTimeout(progressTimer);
  progressTimer = setTimeout(refreshOperation, 1000);
}

byId("cancel-operation").addEventListener("click", async () => {
  try { renderOperation(await mutate(`/api/v1alpha1/operations/${activeOperationId}/cancel`)); }
  catch (error) { showOperationMessage(error.message, true); }
});
byId("retry-operation").addEventListener("click", async () => {
  try {
    const operation = await mutate(`/api/v1alpha1/operations/${activeOperationId}/retry`);
    activeOperationId = operation.id;
    sessionStorage.setItem("fortifylab.activeOperation", activeOperationId);
    renderOperation(operation);
    scheduleProgress();
  } catch (error) { showOperationMessage(error.message, true); }
});

function showOperationMessage(message, danger) {
  const element = byId("operation-message");
  text(element, message);
  element.className = danger ? "notice danger" : "notice";
  element.hidden = false;
}

byId("refresh").addEventListener("click", load);
byId("logout").addEventListener("click", async () => {
  await fetch("/api/v1alpha1/session", {method: "DELETE"});
  window.location.assign("/");
});
load();
