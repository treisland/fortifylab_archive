"use strict";
const panels = [
  {name: "components", path: "/api/v1alpha1/components", render: renderInventory},
  {name: "health", path: "/api/v1alpha1/health", render: renderHealth},
  {name: "availability", path: "/api/v1alpha1/availability", render: renderAvailability},
  {name: "preflight", path: "/api/v1alpha1/preflight", render: renderPreflight},
  {name: "history", path: "/api/v1alpha1/history", render: renderHistory},
  {name: "capabilities", path: "/api/v1alpha1/capabilities", render: renderCapabilities},
  {name: "operations", path: () => activeOperationId ? `/api/v1alpha1/operations/${activeOperationId}` : null, render: renderOperationsRead}
];
const stateNames = new Set(["available", "healthy", "reachable", "degraded", "tls-warning", "dns-mismatch", "not-configured", "unhealthy", "unknown", "blocked", "stale", "starting", "misconfigured", "stopped", "unreachable", "loading", "unavailable", "unauthorized", "timed-out", "error"]);
const errorCodePattern = /^[A-Z][A-Z0-9_]{2,63}$/;
const autoRefreshMilliseconds = 30000;
const readDeadlineMilliseconds = 8000;
const supportedCapabilityContractVersion = "1.0";
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
let refreshGeneration = 0;
let sessionExpired = false;
let lifecycleCapability = null;
let capabilityExpiresAt = 0;
let preflightReadiness = null;
let preflightGeneratedAt = 0;
let selectedComponentId = null;
let componentOpener = null;
const panelDocuments = new Map();
const activeReadControllers = new Set();

async function readModel(panel) {
  const path = typeof panel.path === "function" ? panel.path() : panel.path;
  if (!path) return null;
  const controller = new AbortController();
  activeReadControllers.add(controller);
  const deadline = setTimeout(() => controller.abort("deadline"), readDeadlineMilliseconds);
  try {
    const response = await fetch(path, {
      headers: {"Accept": "application/json"},
      signal: controller.signal
    });
    let payload = {};
    try { payload = await response.json(); } catch (_) { payload = {}; }
    if (response.status === 401 || response.status === 403) {
      throw {kind: "unauthorized", code: "AUTHENTICATION_REQUIRED"};
    }
    if (!response.ok) {
      const code = errorCodePattern.test(String(payload.code || "")) ? payload.code : `HTTP_${response.status}`;
      throw {kind: response.status === 503 ? "unavailable" : "error", code};
    }
    return payload;
  } catch (error) {
    if (error?.kind) throw error;
    if (controller.signal.reason === "deadline") {
      throw {kind: "timed-out", code: "READ_TIMED_OUT"};
    }
    throw {kind: "unavailable", code: "OBSERVER_DISCONNECTED"};
  } finally {
    clearTimeout(deadline);
    activeReadControllers.delete(controller);
  }
}

function panelState(name, state, detail, observedAt = null) {
  const element = byId(`${name}-panel-state`);
  element.className = `panel-state ${state}`;
  const observed = observedAt ? safeDate(observedAt) : "not reported";
  element.textContent = `${detail} · Observed ${observed} · refreshed ${safeDate(new Date().toISOString())}`;
}

function failureMessage(name, failure, retained) {
  const label = name === "components" ? "Component inventory" : name[0].toUpperCase() + name.slice(1);
  const code = errorCodePattern.test(String(failure.code || "")) ? failure.code : "READ_FAILED";
  const next = failure.kind === "unauthorized"
    ? "Sign in again; no additional permissions are required."
    : "Refresh to retry. Do not broaden observer permissions.";
  const condition = failure.kind === "timed-out" ? "timed out" : (retained ? "is stale" : "is unavailable");
  return `${label} ${condition} · ${code}. ${next}`;
}

function markPanelFailure(name, failure) {
  const retained = panelDocuments.has(name);
  const retainedDocument = panelDocuments.get(name);
  const observedAt = retainedDocument?.generatedAt
    || retainedDocument?.observation?.observedAt
    || retainedDocument?.items?.[0]?.occurredAt
    || retainedDocument?.updatedAt;
  panelState(
    name,
    failure.kind === "unauthorized" ? "unauthorized" : (retained ? "stale" : failure.kind),
    failureMessage(name, failure, retained),
    observedAt
  );
  if (name === "preflight") {
    preflightReadiness = null;
    preflightGeneratedAt = 0;
    updateSelectedActionControls();
  }
  if (name === "components" && !retained) {
    text(byId("cluster-state"), "Unavailable");
    byId("cluster-state").className = "status unavailable";
    text(byId("cluster-detail"), "Observer connectivity unavailable");
  }
  if (name === "capabilities") failClosedCapabilities(failure.code);
}

function setOperationsAvailable(available, code = "", state = "unavailable") {
  const form = byId("operation-form");
  Array.from(form.elements).forEach(element => { element.disabled = !available; });
  for (const id of ["execute-operation", "confirm-operation", "cancel-operation", "retry-operation"]) {
    byId(id).disabled = !available;
  }
  const badge = byId("operations-capability-badge");
  badge.className = `read-only ${available ? "available" : cleanCapabilityClass(state)}`;
  text(badge, available ? "OPERATIONS AVAILABLE" : `OPERATIONS ${state.replaceAll("-", " ").toUpperCase()}`);
  panelState(
    "operations",
    available ? "available" : cleanCapabilityClass(state),
    available
      ? "Available · Plans are validated before any action runs."
      : `Unavailable before submission · ${errorCodePattern.test(String(code)) ? code : "OPERATIONS_UNAVAILABLE"}. Review capability remediation, then refresh.`,
    panelDocuments.get("capabilities")?.generatedAt
  );
}

function cleanCapabilityClass(state) {
  if (state === "available") return "available";
  if (state === "unauthorized") return "unauthorized";
  if (state === "degraded") return "degraded";
  if (state === "temporarily-unavailable") return "unavailable";
  return "unavailable";
}

function failClosedCapabilities(code = "CAPABILITY_CONTRACT_UNAVAILABLE") {
  lifecycleCapability = null;
  capabilityExpiresAt = 0;
  setOperationsAvailable(false, code, "unavailable");
}

function renderInventory(payload) {
  const items = Array.isArray(payload.items) ? payload.items : [];
  text(byId("component-count"), items.length);
  const observed = items.filter(item => (item.observedResources || []).every(resource => resource.state === "present")).length;
  text(byId("component-detail"), items.length ? `${observed} fully observed` : "No managed components registered");
  const disconnected = payload.observation?.state !== "available";
  const cluster = byId("cluster-state");
  cluster.className = `status ${disconnected ? "unreachable" : "healthy"}`;
  text(cluster, disconnected ? "Disconnected" : "Connected");
  const observation = payload.observation || {};
  text(
    byId("cluster-detail"),
    disconnected
      ? "Observer adapter disconnected · evidence unavailable"
      : `${observation.node || "Node not reported"} · Kubernetes ${observation.kubernetesVersion || "version not reported"} · evidence ${formatAge(observation.ageSeconds)}`
  );
  renderComponentCards();
  panelState(
    "components",
    items.length ? (disconnected ? "unavailable" : "available") : "empty",
    items.length
      ? (disconnected ? "Desired inventory is available; live observation is unavailable. Reconnect the allow-listed observer, then refresh." : `Current · ${items.length} components observed on ${observation.node || "the connected node"} · evidence ${formatAge(observation.ageSeconds)}`)
      : "Empty · No managed components are registered. Add components through the project registry, then refresh.",
    payload.generatedAt || payload.observation?.observedAt
  );
  const choices = byId("operation-components");
  const selected = choices.value;
  choices.replaceChildren();
  const wholeLab = documentNode("option", "", "Complete tested profile");
  wholeLab.value = "";
  choices.append(wholeLab);
  for (const item of items) {
    const option = documentNode("option", "", item.identity?.displayName || item.identity?.id);
    option.value = item.identity?.id || "";
    option.selected = selected === option.value;
    choices.append(option);
  }
  const linked = new URLSearchParams(window.location.search).get("component");
  if (linked && items.some(item => item.identity?.id === linked)) selectComponent(linked, null, false);
}

function renderHealth(payload) {
  const items = Array.isArray(payload.items) ? payload.items : [];
  const state = cleanState(payload.state);
  const overall = byId("environment-state");
  overall.className = `status ${state}`;
  text(overall, state);
  text(byId("checked-at"), payload.generatedAt ? `Checked ${safeDate(payload.generatedAt)}` : "Not checked");
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
  const age = evidenceAge(payload.generatedAt);
  const unavailable = payload.evidence?.source === "unavailable";
  panelState(
    "health",
    !items.length ? "empty" : (unavailable ? "unavailable" : (age.stale ? "stale" : "available")),
    !items.length
      ? "Empty · No health subjects are configured. Verify the component registry."
      : unavailable
        ? "Unavailable · Live health adapter is disconnected. Review the first safe remediation; do not grant Secret access."
        : `${age.stale ? "Stale" : "Current"} · Evidence ${age.label}. ${degraded.length} degraded; ${blocked.length} blocked consumers.`,
    payload.generatedAt
  );
  renderComponentCards();
  refreshInspector();
}

function renderPreflight(payload) {
  const items = Array.isArray(payload.items) ? payload.items : [];
  const generated = new Date(payload.generatedAt);
  preflightReadiness = payload.readiness && typeof payload.readiness === "object"
    ? payload.readiness : null;
  preflightGeneratedAt = Number.isNaN(generated.valueOf()) ? 0 : generated.valueOf();
  const state = byId("preflight-state");
  state.className = `status ${payload.ready ? "healthy" : "blocked"}`;
  text(state, payload.ready ? "Ready" : "Blocked");
  const summary = payload.summary || {};
  const profile = payload.profile || {};
  text(byId("preflight-detail"), `${profile.id || "Unknown profile"} · ${profile.maturity || "unknown"} · ${summary.blocker || 0} blockers`);
  text(byId("preflight-summary"), `${payload.ready ? "Ready" : "Blocked"} · ${summary.blocker || 0} blockers · ${summary.warning || 0} warnings`);
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
  const age = evidenceAge(payload.generatedAt);
  const unavailable = payload.evidence?.source === "unavailable";
  panelState(
    "preflight",
    !items.length ? "empty" : (unavailable ? "unavailable" : (age.stale ? "stale" : "available")),
    !items.length
      ? "Empty · No preflight checks are configured. Verify the component registry."
      : unavailable
        ? "Unavailable · The read-only preflight adapter is disconnected. Restore it, then refresh."
        : `${age.stale ? "Stale" : "Current"} · Evidence ${age.label}. ${payload.ready ? "No blockers." : "Open the listed safe remediation before deployment."}`,
    payload.generatedAt
  );
  updateSelectedActionControls();
}

function renderAvailability(payload) {
  const items = Array.isArray(payload.items) ? payload.items : [];
  const list = byId("availability-list");
  list.replaceChildren();
  for (const item of items) {
    const article = documentNode("article", "availability-item");
    const heading = documentNode("div", "evidence-title");
    heading.append(documentNode("strong", "", item.displayName), status(item.state));
    article.append(
      heading,
      documentNode("p", "component-meta", `${item.summary || "No evidence"} · DNS ${item.dns || "unknown"} · TLS ${item.tls || "unknown"} · HTTP ${item.http || "unknown"}`),
      documentNode("small", "muted", item.checkedAt ? `Checked ${safeDate(item.checkedAt)} · ${item.latencyMs ?? "—"} ms` : "Not checked")
    );
    if (typeof item.url === "string" && /^https:\/\/[a-z0-9.-]+\/$/.test(item.url)) {
      const link = document.createElement("a");
      link.href = item.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Open service";
      article.append(link);
    }
    list.append(article);
  }
  byId("availability-empty").hidden = items.length !== 0;
  const configured = items.filter(item => item.state !== "not-configured");
  panelState(
    "availability",
    configured.length ? "available" : "empty",
    configured.length
      ? `${configured.filter(item => item.state === "reachable").length} of ${configured.length} approved routes are reachable from the Manager host.`
      : "Empty · No approved observed ingress routes are configured.",
    items.map(item => item.checkedAt).filter(Boolean).sort().at(-1)
  );
  refreshInspector();
}

function renderHistory(payload) {
  const items = Array.isArray(payload.items) ? payload.items : [];
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
    items.length ? `Current · Showing ${items.length} sanitized manager records.` : "Empty · No recent operations have been recorded. No action is required.",
    items[0]?.occurredAt
  );
  renderComponentCards();
  refreshInspector();
}

function componentHealth(componentId) {
  const item = (panelDocuments.get("health")?.items || []).find(candidate => candidate.id === componentId);
  return cleanState(item?.state || "unknown");
}

function componentRuntime(item) {
  const states = (item.observedResources || []).map(resource => resource.state);
  if (!states.length || states.every(value => value === "unknown")) return "unknown";
  if (states.every(value => value === "present")) return "present";
  if (states.every(value => value === "absent")) return "absent";
  return "partial";
}

function componentHasActiveOperation(item) {
  const terminal = new Set(["completed", "failed", "cancelled", "timed-out", "interrupted", "recorded"]);
  const names = new Set([item.identity?.id, item.identity?.displayName]);
  const operation = panelDocuments.get("operations");
  if (
    operation
    && !operation.terminal
    && (operation.components || []).includes(item.identity?.id)
  ) return true;
  return (panelDocuments.get("history")?.items || []).some(record =>
    names.has(record.subject) && !terminal.has(String(record.state).toLowerCase())
  );
}

function componentConsumers(componentId, items) {
  return items.filter(item => (item.dependencies || []).includes(componentId));
}

function componentSummary(componentId) {
  const health = (panelDocuments.get("health")?.items || []).find(item => item.id === componentId);
  if (!health) return "application health unknown";
  const labels = [];
  if (health.dimensions?.dependency?.state === "blocked") labels.push("blocked by dependency");
  if (health.dimensions?.workload?.state === "absent") labels.push("workload absent");
  if (health.dimensions?.workload?.state === "not-ready") labels.push("workload not ready");
  if (health.dimensions?.application?.state === "unknown") labels.push("application health unknown");
  return labels.join(" · ") || `workload ${health.dimensions?.workload?.state || "unknown"} · application ${health.dimensions?.application?.state || "unknown"}`;
}

function renderComponentCards() {
  const inventory = panelDocuments.get("components");
  if (!inventory) return;
  const items = Array.isArray(inventory.items) ? inventory.items : [];
  const query = byId("component-search").value.trim().toLowerCase();
  const healthFilter = byId("health-filter").value;
  const stateFilter = byId("state-filter").value;
  const updatesOnly = byId("updates-filter").checked;
  const operationsOnly = byId("operations-filter").checked;
  const graph = byId("dependency-graph");
  graph.replaceChildren();
  const visible = items.filter(item => {
    const searchable = [
      item.identity?.id, item.identity?.displayName, item.version?.chart,
      item.profile?.productVersion,
      ...Object.values(item.version?.images || {}),
      ...(item.observedDeployment?.workloads || []).flatMap(workload => [
        workload.workloadMetadata?.declaredReleaseName,
        workload.workloadMetadata?.chartVersion,
        workload.workloadMetadata?.appVersion,
        ...(workload.runningImages || []).flatMap(image => [image.name, image.version])
      ]),
      ...(item.workloads || []).flatMap(workload => [workload.id, workload.name, workload.role])
    ].join(" ").toLowerCase();
    return (!query || searchable.includes(query))
      && (!healthFilter || componentHealth(item.identity?.id) === healthFilter)
      && (!stateFilter || componentRuntime(item) === stateFilter)
      && (!updatesOnly || item.updateAvailable === true)
      && (!operationsOnly || componentHasActiveOperation(item));
  });
  for (const item of visible) {
    const id = item.identity?.id;
    const button = documentNode("button", "component-card");
    button.type = "button";
    button.dataset.componentId = id;
    button.setAttribute("aria-pressed", String(selectedComponentId === id));
    if (selectedComponentId === id) button.classList.add("selected");
    const selected = items.find(candidate => candidate.identity?.id === selectedComponentId);
    if ((selected?.dependencies || []).includes(id)) button.classList.add("dependency-highlight");
    if (
      selectedComponentId
      && (item.dependencies || []).includes(selectedComponentId)
      && ["blocked", "degraded", "unhealthy"].includes(componentHealth(id))
    ) button.classList.add("blocked-consumer-highlight");
    const heading = documentNode("span", "component-title");
    heading.append(documentNode("strong", "", item.identity?.displayName), status(componentHealth(id)));
    const runtime = componentRuntime(item);
    button.append(
      heading,
      documentNode("span", "component-meta", `${id} · observed ${runtime}`),
      documentNode("span", "component-meta", componentSummary(id)),
      documentNode("span", "version", `Desired ${item.profile?.productVersion || "not declared"} / chart ${item.version?.chart || "not declared"}`),
      documentNode("span", "version", `Observed deployment: ${item.observedDeployment?.state || "unavailable"}`),
      documentNode("span", "dependencies", `Depends on: ${(item.dependencies || []).join(", ") || "Lab foundation"}`)
    );
    if (componentHasActiveOperation(item)) button.append(documentNode("span", "active-operation", "Active operation"));
    button.addEventListener("click", () => selectComponent(id, button));
    graph.append(button);
  }
  byId("inventory-empty").hidden = visible.length !== 0;
}

function detailSection(title, rows) {
  const section = documentNode("section", "inspector-section");
  section.append(documentNode("h3", "", title));
  const list = documentNode("dl", "inspector-list");
  for (const [term, value] of rows) {
    list.append(documentNode("dt", "", term), documentNode("dd", "", value));
  }
  section.append(list);
  return section;
}

function selectComponent(componentId, opener = null, updateUrl = true) {
  const items = panelDocuments.get("components")?.items || [];
  if (!items.some(item => item.identity?.id === componentId)) return;
  selectedComponentId = componentId;
  componentOpener = opener || Array.from(document.querySelectorAll("[data-component-id]"))
    .find(button => button.dataset.componentId === componentId);
  if (updateUrl) {
    const url = new URL(window.location.href);
    url.searchParams.set("component", componentId);
    history.replaceState(null, "", url);
  }
  renderComponentCards();
  refreshInspector();
  if (!byId("component-inspector").open) byId("component-inspector").showModal();
  byId("close-component-inspector").focus();
}

function refreshInspector() {
  if (!selectedComponentId) return;
  const items = panelDocuments.get("components")?.items || [];
  const item = items.find(candidate => candidate.identity?.id === selectedComponentId);
  if (!item) return;
  const health = (panelDocuments.get("health")?.items || []).find(candidate => candidate.id === selectedComponentId);
  const availability = (panelDocuments.get("availability")?.items || []).find(candidate => candidate.componentId === selectedComponentId);
  const consumers = componentConsumers(selectedComponentId, items);
  const blockedConsumers = consumers.filter(candidate => {
    const candidateHealth = (panelDocuments.get("health")?.items || []).find(value => value.id === candidate.identity?.id);
    return candidateHealth?.blockedBy === selectedComponentId || candidateHealth?.state === "blocked";
  });
  const recent = (panelDocuments.get("history")?.items || []).filter(record =>
    new Set([item.identity?.id, item.identity?.displayName]).has(record.subject)
  ).slice(0, 5);
  text(byId("inspector-title"), item.identity?.displayName);
  text(byId("inspector-subtitle"), `${item.identity?.id} · desired configuration and sanitized observed state`);
  const content = byId("inspector-content");
  const sections = [
    detailSection("Overview", [
      ["Desired state", item.desiredState?.state || "not reported"],
      ["Observed state", componentRuntime(item)],
      ["Health", componentHealth(selectedComponentId)],
      ["Evidence", panelDocuments.get("components")?.observation?.state === "available" ? "connected" : "disconnected"]
    ]),
    detailSection("Health and root cause", [
      ["Root cause", health?.rootCause || "No root cause reported"],
      ["All actionable causes", (health?.rootCauses || []).join(", ") || "No actionable causes reported"],
      ["Blocked by", health?.blockedBy || "No upstream block reported"],
      ["Dependency", health?.dimensions?.dependency?.state || "unknown"],
      ["Workload", health?.dimensions?.workload?.state || "unknown"],
      ["Application health", health?.dimensions?.application?.state || "unknown"],
      ["Evidence", (health?.evidence || []).map(value => {
        const replicas = value.workload?.desiredReplicas == null ? "" : ` · replicas ${value.workload.readyReplicas}/${value.workload.desiredReplicas}`;
        return `${value.layer} ${value.id} · ${value.state}: ${value.summary}${replicas}`;
      }).join(" · ") || "Partially observed or unavailable"]
    ]),
    detailSection("Dependencies and consumers", [
      ["Upstream dependencies", (item.dependencies || []).join(", ") || "None"],
      ["Downstream consumers", consumers.map(value => value.identity?.displayName).join(", ") || "None"],
      ["Blocked consumers", blockedConsumers.map(value => value.identity?.displayName).join(", ") || "None"]
    ]),
    detailSection("Workloads (desired / observed)", (item.workloads || []).map(workload => {
      const observed = (item.observedResources || []).find(resource => resource.id.endsWith(`/${workload.id}`));
      return [workload.id, `${workload.kind} ${workload.name} · ${workload.role} · observed ${observed?.state || "unknown"}${workload.scalable ? " · scalable" : ""}`];
    })),
    detailSection("Profile and versions (desired)", [
      ["Profile", `${item.profile?.id || "not reported"} · ${item.profile?.maturity || "unknown"}`],
      ["Product", item.profile?.productVersion || "not reported"],
      ["Chart", item.version?.chart || "not reported"],
      ["Images", Object.entries(item.version?.images || {}).map(([name, version]) => `${name}: ${version}`).join(" · ") || "not reported"],
      ["Comparison", item.observedDeployment?.state || "unavailable"]
    ]),
    detailSection("Installed release (independent evidence)", [
      ["State", item.observedDeployment?.installedRelease?.state || "unavailable"],
      ["Reason", item.observedDeployment?.installedRelease?.reason === "helm-storage-not-observed" ? "Helm storage is intentionally not observed" : "Independent release evidence unavailable"]
    ]),
    detailSection("Workload-declared metadata and running versions", [
      ["Evidence source", item.observedDeployment?.comparisonSource === "workload-declared-metadata" ? "Allow-listed workload metadata; not proof of an installed Helm release" : "Unavailable"],
      ["Comparison", item.observedDeployment?.state || "unavailable"],
      ...((item.observedDeployment?.workloads || []).map(workload => [
        workload.id,
        workload.state !== "present"
          ? workload.state
          : `declared release ${workload.workloadMetadata?.declaredReleaseName || "unavailable"} · declared chart ${workload.workloadMetadata?.chartVersion || "unavailable"} · declared app ${workload.workloadMetadata?.appVersion || "unavailable"} · running ${(workload.runningImages || []).map(image => `${image.name}: ${image.version}`).join(", ") || "unavailable"}`
      ]))
    ]),
    detailSection("Ingress and storage (desired metadata)", [
      ["Ingress", (item.ingress || []).map(value => `${value.protocol.toUpperCase()} ${value.id}`).join(", ") || "None declared"],
      ["Storage", (item.storage || []).map(value => `${value.id}: ${value.purpose} · ${value.retainedOnUninstall ? "retained" : "not retained"} on uninstall`).join(" · ") || "None declared"]
    ]),
    detailSection("Supported operations", [
      ["Operations", (item.supportedOperations || []).map(value => `${value.id}${value.destructive ? " (destructive)" : value.disruptive ? " (disruptive)" : ""}`).join(", ") || "None"]
    ]),
    detailSection("Recent history", recent.length
      ? recent.map(record => [safeDate(record.occurredAt), `${record.state} · ${record.summary}`])
      : [["History", "No recent sanitized records for this component"]])
  ];
  if (availability) {
    const section = detailSection("Service availability (independent from health)", [
      ["State", availability.state],
      ["Evidence", `DNS ${availability.dns} · TLS ${availability.tls} · HTTP ${availability.http}`],
      ["Checked", availability.checkedAt ? `${safeDate(availability.checkedAt)} · ${availability.latencyMs ?? "—"} ms` : "Not checked"]
    ]);
    if (typeof availability.url === "string" && /^https:\/\/[a-z0-9.-]+\/$/.test(availability.url)) {
      const link = document.createElement("a");
      link.href = availability.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = "Open service";
      section.append(link);
    }
    sections.splice(2, 0, section);
  }
  content.replaceChildren(...sections);
}

function renderCapabilities(payload) {
  const expires = new Date(payload.expiresAt);
  const valid = payload.apiVersion === "fortifylab.io/v1alpha1"
    && payload.kind === "ManagerCapabilities"
    && payload.contractVersion === supportedCapabilityContractVersion
    && Array.isArray(payload.capabilities)
    && !Number.isNaN(expires.valueOf())
    && expires.valueOf() > Date.now();
  if (!valid) {
    text(byId("capability-profile"), "Unsupported contract");
    text(byId("capability-detail"), "Mutation controls fail closed");
    byId("capability-list").replaceChildren();
    panelState("capabilities", "stale", "Unavailable · CAPABILITY_CONTRACT_UNSUPPORTED_OR_STALE. Refresh or upgrade this Web client.", payload.generatedAt);
    failClosedCapabilities("CAPABILITY_CONTRACT_UNSUPPORTED_OR_STALE");
    return;
  }
  text(byId("capability-profile"), `Contract ${payload.contractVersion}`);
  text(byId("capability-detail"), `${payload.capabilities.length} effective capability states · refresh within ${payload.refreshAfterSeconds || 30}s`);
  const list = byId("capability-list");
  list.replaceChildren();
  for (const capability of payload.capabilities) {
    const item = documentNode("article", "capability-item");
    item.append(
      documentNode("strong", "", capability.id?.replaceAll("-", " ")),
      status(cleanCapabilityClass(capability.state)),
      documentNode("small", "", `${capability.state || "unknown"} · ${errorCodePattern.test(String(capability.code || "")) ? capability.code : "CAPABILITY_STATE_INVALID"} · prerequisites: ${Array.isArray(capability.prerequisites) && capability.prerequisites.length ? capability.prerequisites.join(", ") : "none"}`)
    );
    if (capability.remediation?.href?.startsWith("/docs/")) {
      const link = document.createElement("a");
      link.href = capability.remediation.href;
      link.textContent = "Open guidance";
      item.append(link);
    }
    list.append(item);
  }
  lifecycleCapability = payload.capabilities.find(item => item.id === "lifecycle-execution") || null;
  capabilityExpiresAt = expires.valueOf();
  const available = lifecycleCapability?.state === "available" && lifecycleCapability?.canMutate === true;
  setOperationsAvailable(available, lifecycleCapability?.code, lifecycleCapability?.state || "unavailable");
  updateSelectedActionControls();
  panelState("capabilities", "available", "Current · Effective Manager capability evidence is authoritative for controls.", payload.generatedAt);
}

function renderOperationsRead(payload) {
  if (payload) {
    renderOperation(payload);
    renderComponentCards();
    refreshInspector();
    panelState("operations", "available", "Current · Durable operation progress restored.", payload.updatedAt || payload.startedAt);
    if (!payload.terminal) scheduleProgress();
    return;
  }
  const available = lifecycleCapability?.state === "available" && lifecycleCapability?.canMutate === true;
  setOperationsAvailable(available, lifecycleCapability?.code, lifecycleCapability?.state || "unavailable");
  updateSelectedActionControls();
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
  const generation = ++refreshGeneration;
  byId("loading").hidden = false;
  const settled = {count: 0, available: 0, unauthorized: false};
  text(byId("refresh-summary"), `0 of ${panels.length} panels settled`);
  const requests = panels.map(async panel => {
    try {
      const payload = await readModel(panel);
      if (generation !== refreshGeneration) return;
      if (payload) panelDocuments.set(panel.name, payload);
      panel.render(payload);
      settled.available += 1;
    } catch (failure) {
      if (generation !== refreshGeneration) return;
      markPanelFailure(panel.name, failure || {kind: "error", code: "READ_FAILED"});
      if (failure?.kind === "unauthorized") settled.unauthorized = true;
    } finally {
      if (generation === refreshGeneration) {
        settled.count += 1;
        text(byId("refresh-summary"), `${settled.count} of ${panels.length} panels settled`);
      }
    }
  });
  await Promise.all(requests);
  if (generation !== refreshGeneration) return;
  byId("loading").hidden = true;
  sessionExpired = settled.unauthorized;
  byId("session-expired").hidden = !settled.unauthorized;
  text(byId("last-refresh"), `Last refresh ${safeDate(new Date().toISOString())}`);
  text(byId("refresh-summary"), `${settled.available} of ${panels.length} panels refreshed${settled.unauthorized ? " · session expired" : ""}`);
  refreshInFlight = false;
  scheduleAutoRefresh();
}

async function mutate(path, body = {}) {
  if (
    lifecycleCapability?.state !== "available"
    || lifecycleCapability?.canMutate !== true
    || capabilityExpiresAt <= Date.now()
  ) {
    failClosedCapabilities(
      capabilityExpiresAt && capabilityExpiresAt <= Date.now()
        ? "CAPABILITY_CONTRACT_STALE"
        : lifecycleCapability?.code
    );
    throw new Error("Operation is unavailable before submission. Refresh Manager capabilities.");
  }
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
  let payload = {};
  try { payload = await response.json(); } catch (_) { payload = {}; }
  if (response.status === 401 || response.status === 403) {
    sessionExpired = true;
    byId("session-expired").hidden = false;
    panelState("operations", "unauthorized", "Unauthorized · AUTHENTICATION_REQUIRED. Sign in again; no additional permissions are required.");
    throw new Error("Session expired. Sign in again to continue.");
  }
  if (!response.ok) {
    const code = errorCodePattern.test(String(payload.code || "")) ? payload.code : `HTTP_${response.status}`;
    panelState("operations", response.status === 503 ? "unavailable" : "error", `Unavailable · ${code}. Refresh prerequisites and review the safe manager guidance.`);
    throw new Error(`Operation request failed (${code})`);
  }
  panelState("operations", "available", "Available · The manager accepted the typed request.");
  return payload;
}

function operationRequest() {
  return {
    action: byId("operation").value,
    component: byId("operation-components").value || null
  };
}

function selectedActionReadiness() {
  const action = byId("operation").value;
  const readinessKey = action === "deploy" ? "deployment" : action;
  const evidence = preflightReadiness?.[readinessKey];
  const current = preflightGeneratedAt > 0 && Date.now() - preflightGeneratedAt <= 300000;
  return {
    ready: current && evidence?.ready === true,
    code: current
      ? (Array.isArray(evidence?.blockers) && evidence.blockers[0]) || "ACTION_NOT_READY"
      : "PREFLIGHT_EVIDENCE_STALE_OR_UNAVAILABLE"
  };
}

function updateSelectedActionControls() {
  const submit = byId("operation-form").querySelector('button[type="submit"]');
  const lifecycleReady = lifecycleCapability?.state === "available"
    && lifecycleCapability?.canMutate === true
    && capabilityExpiresAt > Date.now();
  const readiness = selectedActionReadiness();
  submit.disabled = !(lifecycleReady && readiness.ready);
  if (!byId("operation-plan").hidden) byId("execute-operation").disabled = !(lifecycleReady && readiness.ready);
  if (lifecycleReady && !readiness.ready) {
    panelState("operations", "unavailable", `Unavailable for selected action · ${readiness.code}. Refresh and follow preflight remediation.`, panelDocuments.get("preflight")?.generatedAt);
  }
}

byId("operation").addEventListener("change", updateSelectedActionControls);

byId("operation-form").addEventListener("submit", async event => {
  event.preventDefault();
  try {
    if (!selectedActionReadiness().ready) throw new Error("Selected action is not ready. Refresh preflight evidence and resolve its blockers.");
    selectedPlan = await mutate("/api/v1alpha1/lab/plans", operationRequest());
    text(byId("plan-risk"), `${selectedPlan.risk} risk`);
    text(byId("plan-impact"), `${selectedPlan.impact} ${selectedPlan.dependencyImpact.length ? `Automatic expansion: ${selectedPlan.dependencyImpact.join(", ")}.` : "No automatic expansion."} Estimated duration: up to ${selectedPlan.estimatedDurationSeconds}s.`);
    const list = byId("plan-steps");
    list.replaceChildren();
    selectedPlan.steps.forEach(step => list.append(documentNode("li", "", `${step.operation} ${step.component} · ${step.recoveryClass} · timeout ${step.timeoutSeconds}s · ${step.verificationChecks.length} health checks`)));
    text(byId("plan-impact"), `${byId("plan-impact").textContent} Data boundary: PVCs, databases, configuration, licenses, Kubernetes resources, MicroK8s, EC2, and Manager access are preserved. Cancellation boundary: ${selectedPlan.cancellationBoundary}`);
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
    if (!selectedActionReadiness().ready) throw new Error("Selected action readiness changed. Refresh and review a new plan.");
    const request = {operation: selectedPlan.operation, components: selectedPlan.requestedTargets};
    if (selectedPlan.approvalRequired) {
      const approval = await mutate("/api/v1alpha1/approvals", request);
      const approved = await mutate(`/api/v1alpha1/approvals/${approval.id}/approve`, {
        confirmation: selectedPlan.risk === "high" ? byId("high-risk-confirmation").value : null
      });
      request.approvalId = approved.id;
    }
    const operation = await mutate("/api/v1alpha1/lab/operations", {
      action: selectedPlan.action,
      component: selectedPlan.selectedComponent || null,
      approvalId: request.approvalId
    });
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
  const mutationAvailable = lifecycleCapability?.state === "available"
    && lifecycleCapability?.canMutate === true
    && capabilityExpiresAt > Date.now();
  byId("cancel-operation").disabled = !mutationAvailable;
  byId("retry-operation").disabled = !mutationAvailable;
  if (operation.terminal) {
    clearTimeout(progressTimer);
    sessionStorage.removeItem("fortifylab.activeOperation");
  }
  renderComponentCards();
  refreshInspector();
}

async function refreshOperation() {
  try {
    const operation = await readModel({
      path: `/api/v1alpha1/operations/${activeOperationId}`
    });
    renderOperation(operation);
    panelDocuments.set("operations", operation);
    panelState("operations", "available", "Current · Durable operation progress refreshed.", operation.updatedAt || operation.startedAt);
    if (!operation.terminal) scheduleProgress();
  } catch (failure) {
    if (failure?.kind === "unauthorized") {
      sessionExpired = true;
      byId("session-expired").hidden = false;
      panelState("operations", "unauthorized", "Unauthorized · AUTHENTICATION_REQUIRED. Sign in again to resume operation progress.");
      showOperationMessage("Session expired. Sign in again to resume.", true);
      return;
    }
    markPanelFailure("operations", failure || {kind: "error", code: "READ_FAILED"});
    showOperationMessage(
      failure?.kind === "timed-out"
        ? "Operation progress timed out. Retained progress remains visible."
        : "Operation progress is unavailable. Retained progress remains visible.",
      true
    );
  }
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
for (const id of ["component-search", "health-filter", "state-filter", "updates-filter", "operations-filter"]) {
  byId(id).addEventListener(id === "component-search" ? "input" : "change", renderComponentCards);
}
byId("clear-component-filters").addEventListener("click", () => {
  byId("component-search").value = "";
  byId("health-filter").value = "";
  byId("state-filter").value = "";
  byId("updates-filter").checked = false;
  byId("operations-filter").checked = false;
  renderComponentCards();
  byId("component-search").focus();
});
byId("close-component-inspector").addEventListener("click", () => byId("component-inspector").close());
byId("component-inspector").addEventListener("close", () => {
  selectedComponentId = null;
  const url = new URL(window.location.href);
  url.searchParams.delete("component");
  history.replaceState(null, "", url);
  renderComponentCards();
  if (componentOpener?.isConnected) componentOpener.focus();
  componentOpener = null;
});
byId("auto-refresh").addEventListener("change", scheduleAutoRefresh);
document.addEventListener("visibilitychange", () => {
  if (document.hidden) {
    activeReadControllers.forEach(controller => controller.abort("hidden"));
    scheduleAutoRefresh();
  } else if (byId("auto-refresh").checked && !sessionExpired) load();
});
byId("logout").addEventListener("click", async () => {
  await fetch("/api/v1alpha1/session", {method: "DELETE"});
  window.location.assign("/");
});
failClosedCapabilities("CAPABILITY_CONTRACT_PENDING");
load();
