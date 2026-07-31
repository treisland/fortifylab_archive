"use strict";
const endpoints = ["components", "health", "preflight", "history"];
const stateNames = new Set(["healthy", "degraded", "unhealthy", "unknown", "blocked", "stale", "starting", "misconfigured", "stopped", "unreachable", "loading", "unavailable", "unauthorized", "error"]);
const errorCodePattern = /^[A-Z][A-Z0-9_]{2,63}$/;
const autoRefreshMilliseconds = 30000;
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
let autoRefreshTimer = null;
let refreshInFlight = false;
let sessionExpired = false;
const panelDocuments = new Map();

async function readModel(name) {
  let response;
  try {
    response = await fetch(`/api/v1alpha1/${name}`, {headers: {"Accept": "application/json"}});
  } catch (_) {
    throw {kind: "unavailable", code: "OBSERVER_DISCONNECTED"};
  }
  let document = {};
  try { document = await response.json(); } catch (_) { document = {}; }
  if (response.status === 401 || response.status === 403) {
    throw {kind: "unauthorized", code: "AUTHENTICATION_REQUIRED"};
  }
  if (!response.ok) {
    const code = errorCodePattern.test(String(document.code || "")) ? document.code : `HTTP_${response.status}`;
    throw {kind: response.status === 503 ? "unavailable" : "error", code};
  }
  return document;
}

function panelState(name, state, detail) {
  const element = byId(`${name}-panel-state`);
  element.className = `panel-state ${state}`;
  element.textContent = detail;
}

function failureMessage(name, failure, retained) {
  const label = name === "components" ? "Component inventory" : name[0].toUpperCase() + name.slice(1);
  const code = errorCodePattern.test(String(failure.code || "")) ? failure.code : "READ_FAILED";
  const next = failure.kind === "unauthorized"
    ? "Sign in again; no additional permissions are required."
    : "Refresh to retry. Do not broaden observer permissions.";
  return `${label} ${retained ? "is stale" : "is unavailable"} · ${code}. ${next}`;
}

function markPanelFailure(name, failure) {
  const retained = panelDocuments.has(name);
  panelState(name, failure.kind === "unauthorized" ? "unauthorized" : (retained ? "stale" : failure.kind), failureMessage(name, failure, retained));
  if (name === "components" && !retained) {
    text(byId("cluster-state"), "Unavailable");
    byId("cluster-state").className = "status unavailable";
    text(byId("cluster-detail"), "Observer connectivity unavailable");
    setOperationsAvailable(false, failure.code);
  }
}

function setOperationsAvailable(available, code = "") {
  const form = byId("operation-form");
  Array.from(form.elements).forEach(element => { element.disabled = !available; });
  panelState(
    "operations",
    available ? "available" : "unavailable",
    available
      ? "Available · Plans are validated before any action runs."
      : `Unavailable · ${errorCodePattern.test(String(code)) ? code : "OPERATIONS_UNAVAILABLE"}. Restore manager composition or observer connectivity, then refresh.`
  );
}

function renderInventory(document) {
  const items = Array.isArray(document.items) ? document.items : [];
  text(byId("component-count"), items.length);
  const observed = items.filter(item => (item.observedResources || []).every(resource => resource.state === "present")).length;
  text(byId("component-detail"), items.length ? `${observed} fully observed` : "No managed components registered");
  const disconnected = document.observation?.state !== "available";
  const cluster = byId("cluster-state");
  cluster.className = `status ${disconnected ? "unreachable" : "healthy"}`;
  text(cluster, disconnected ? "Disconnected" : "Connected");
  const observation = document.observation || {};
  text(
    byId("cluster-detail"),
    disconnected
      ? "Observer adapter disconnected · evidence unavailable"
      : `${observation.node || "Node not reported"} · Kubernetes ${observation.kubernetesVersion || "version not reported"} · evidence ${formatAge(observation.ageSeconds)}`
  );
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
  panelState(
    "components",
    items.length ? (disconnected ? "unavailable" : "available") : "empty",
    items.length
      ? (disconnected ? "Desired inventory is available; live observation is unavailable. Reconnect the allow-listed observer, then refresh." : `Current · ${items.length} components observed on ${observation.node || "the connected node"} · evidence ${formatAge(observation.ageSeconds)}`)
      : "Empty · No managed components are registered. Add components through the project registry, then refresh."
  );
  setOperationsAvailable(items.length > 0 && !disconnected, disconnected ? "OBSERVER_DISCONNECTED" : "");
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
  const degraded = items.filter(item => item.state !== "healthy");
  const componentIds = new Set((panelDocuments.get("components")?.items || []).map(item => item.identity?.id));
  const degradedComponents = degraded.filter(item => componentIds.has(item.id));
  text(byId("degraded-count"), degradedComponents.length);
  text(byId("degraded-detail"), degradedComponents.length ? `${degradedComponents.length} require attention` : "No degraded components");
  const roots = Array.from(new Set(degraded.map(item => item.rootCause).filter(Boolean)));
  const blocked = degraded.filter(item => item.blockedBy).map(item => item.displayName);
  text(byId("root-cause-summary"), roots.length ? roots.slice(0, 3).join(", ") : "No active root cause");
  text(byId("blocked-summary"), blocked.length ? blocked.join(", ") : "No blocked consumers");
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
  const age = evidenceAge(document.generatedAt);
  const unavailable = document.evidence?.source === "unavailable";
  panelState(
    "health",
    !items.length ? "empty" : (unavailable ? "unavailable" : (age.stale ? "stale" : "available")),
    !items.length
      ? "Empty · No health subjects are configured. Verify the component registry."
      : unavailable
        ? "Unavailable · Live health adapter is disconnected. Review the first safe remediation; do not grant Secret access."
        : `${age.stale ? "Stale" : "Current"} · Evidence ${age.label}. ${degraded.length} degraded; ${blocked.length} blocked consumers.`
  );
}

function renderPreflight(document) {
  const items = Array.isArray(document.items) ? document.items : [];
  const state = byId("preflight-state");
  state.className = `status ${document.ready ? "healthy" : "blocked"}`;
  text(state, document.ready ? "Ready" : "Blocked");
  const summary = document.summary || {};
  const profile = document.profile || {};
  text(byId("preflight-detail"), `${profile.id || "Unknown profile"} · ${profile.maturity || "unknown"} · ${summary.blocker || 0} blockers`);
  text(byId("preflight-summary"), `${document.ready ? "Ready" : "Blocked"} · ${summary.blocker || 0} blockers · ${summary.warning || 0} warnings`);
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
  const age = evidenceAge(document.generatedAt);
  const unavailable = document.evidence?.source === "unavailable";
  panelState(
    "preflight",
    !items.length ? "empty" : (unavailable ? "unavailable" : (age.stale ? "stale" : "available")),
    !items.length
      ? "Empty · No preflight checks are configured. Verify the component registry."
      : unavailable
        ? "Unavailable · The read-only preflight adapter is disconnected. Restore it, then refresh."
        : `${age.stale ? "Stale" : "Current"} · Evidence ${age.label}. ${document.ready ? "No blockers." : "Open the listed safe remediation before deployment."}`
  );
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
  panelState(
    "history",
    items.length ? "available" : "empty",
    items.length ? `Current · Showing ${items.length} sanitized manager records.` : "Empty · No recent operations have been recorded. No action is required."
  );
}

function documentNode(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content != null) node.textContent = String(content);
  return node;
}

function formatAge(seconds) {
  const value = Number(seconds);
  if (!Number.isFinite(value) || value < 0) return "age not reported";
  if (value < 60) return `${Math.round(value)}s old`;
  if (value < 3600) return `${Math.round(value / 60)}m old`;
  return `${Math.round(value / 3600)}h old`;
}

function evidenceAge(value) {
  const date = new Date(value);
  if (Number.isNaN(date.valueOf())) return {label: "age not reported", stale: true};
  const seconds = Math.max(0, (Date.now() - date.valueOf()) / 1000);
  return {label: formatAge(seconds), stale: seconds > 300};
}

async function load() {
  if (refreshInFlight || sessionExpired) return;
  refreshInFlight = true;
  byId("loading").hidden = false;
  const results = await Promise.allSettled(endpoints.map(readModel));
  const renderers = [renderInventory, renderHealth, renderPreflight, renderHistory];
  results.forEach((result, index) => {
    const name = endpoints[index];
    if (result.status === "fulfilled") {
      panelDocuments.set(name, result.value);
      renderers[index](result.value);
    } else {
      markPanelFailure(name, result.reason || {kind: "error", code: "READ_FAILED"});
    }
  });
  byId("loading").hidden = true;
  const fulfilled = results.filter(result => result.status === "fulfilled").length;
  const unauthorized = results.some(result => result.status === "rejected" && result.reason?.kind === "unauthorized");
  sessionExpired = unauthorized;
  byId("session-expired").hidden = !unauthorized;
  text(byId("last-refresh"), `Last refresh ${safeDate(new Date().toISOString())}`);
  text(byId("refresh-summary"), `${fulfilled} of ${endpoints.length} read models available${unauthorized ? " · session expired" : ""}`);
  if (activeOperationId && !unauthorized) await refreshOperation();
  refreshInFlight = false;
  scheduleAutoRefresh();
}

async function mutate(path, body = {}) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: {"Accept": "application/json", "Content-Type": "application/json"},
      body: JSON.stringify(body)
    });
  } catch (_) {
    panelState("operations", "unavailable", "Unavailable · MANAGER_DISCONNECTED. Restore manager connectivity, then retry.");
    throw new Error("Operation service is disconnected. Restore manager connectivity, then retry.");
  }
  let document = {};
  try { document = await response.json(); } catch (_) { document = {}; }
  if (response.status === 401 || response.status === 403) {
    sessionExpired = true;
    byId("session-expired").hidden = false;
    panelState("operations", "unauthorized", "Unauthorized · AUTHENTICATION_REQUIRED. Sign in again; no additional permissions are required.");
    throw new Error("Session expired. Sign in again to continue.");
  }
  if (!response.ok) {
    const code = errorCodePattern.test(String(document.code || "")) ? document.code : `HTTP_${response.status}`;
    panelState("operations", response.status === 503 ? "unavailable" : "error", `Unavailable · ${code}. Refresh prerequisites and review the safe manager guidance.`);
    throw new Error(`Operation request failed (${code})`);
  }
  panelState("operations", "available", "Available · The manager accepted the typed request.");
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
    const cleanInstall = byId("operation").value === "clean-install";
    selectedPlan = await mutate(
      cleanInstall ? "/api/v1alpha1/clean-install/plan" : "/api/v1alpha1/operations/plans",
      cleanInstall ? {} : operationRequest()
    );
    if (cleanInstall && !selectedPlan.ready) {
      const reason = selectedPlan.existingComponents.length
        ? `Existing footprint detected: ${selectedPlan.existingComponents.join(", ")}`
        : "Deployment preflight has blockers";
      throw new Error(`${reason}. Review clean-install evidence before retrying.`);
    }
    text(byId("plan-risk"), `${selectedPlan.risk} risk`);
    text(byId("plan-impact"), selectedPlan.dependencyImpact.length ? `Adds dependencies: ${selectedPlan.dependencyImpact.join(", ")}` : "No implicit dependency additions");
    const list = byId("plan-steps");
    list.replaceChildren();
    selectedPlan.steps.forEach(step => list.append(documentNode("li", "", `${step.operation} ${step.component} · ${step.recoveryClass} · timeout ${step.timeoutSeconds}s · ${step.verificationChecks.length} health checks`)));
    text(byId("plan-impact"), `${byId("plan-impact").textContent} · recovery boundary: ${selectedPlan.recoveryBoundary}`);
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
    if (selectedPlan.workflow === "clean-install") {
      const operation = await mutate("/api/v1alpha1/clean-install", {});
      activeOperationId = operation.id;
      sessionStorage.setItem("fortifylab.activeOperation", activeOperationId);
      byId("operation-plan").hidden = true;
      renderOperation(operation);
      scheduleProgress();
      return;
    }
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
    if (response.status === 401 || response.status === 403) {
      sessionExpired = true;
      byId("session-expired").hidden = false;
      panelState("operations", "unauthorized", "Unauthorized · AUTHENTICATION_REQUIRED. Sign in again to resume operation progress.");
      throw new Error("Session expired. Sign in again to resume.");
    }
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

function scheduleAutoRefresh() {
  clearTimeout(autoRefreshTimer);
  if (sessionExpired || !byId("auto-refresh").checked || document.hidden) return;
  autoRefreshTimer = setTimeout(load, autoRefreshMilliseconds);
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
byId("auto-refresh").addEventListener("change", scheduleAutoRefresh);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden && byId("auto-refresh").checked && !sessionExpired) load();
  else scheduleAutoRefresh();
});
byId("logout").addEventListener("click", async () => {
  await fetch("/api/v1alpha1/session", {method: "DELETE"});
  window.location.assign("/");
});
load();
