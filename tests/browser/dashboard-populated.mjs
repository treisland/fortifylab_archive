import assert from "node:assert/strict";
import fs from "node:fs";
import vm from "node:vm";

const asset = process.argv[2];
if (!asset) throw new Error("usage: node dashboard-populated.mjs <dashboard.js>");

class Element {
  constructor(tagName = "div", id = "") {
    this.tagName = tagName.toUpperCase();
    this.id = id;
    this.children = [];
    this.hidden = false;
    this.checked = id === "auto-refresh";
    this.value = "";
    this.textContent = "";
    this.className = "";
    this.disabled = false;
    this.previousElementSibling = {hidden: false};
    this.dataset = {};
    this.classList = {add() {}, toggle() {}};
    this.elements = id === "operation-form" ? [new Element("button")] : [];
  }
  addEventListener() {}
  append(...children) { this.children.push(...children); }
  replaceChildren(...children) { this.children = [...children]; }
  querySelector() { return this.elements[0] || new Element("button"); }
  setAttribute(name, value) { this[name] = String(value); }
  focus() {}
  showModal() { this.hidden = false; }
  close() { this.hidden = true; }
}

const elements = new Map();
const browserDocument = {
  hidden: false,
  createElement: tag => new Element(tag),
  getElementById(id) {
    if (!elements.has(id)) elements.set(id, new Element("div", id));
    return elements.get(id);
  },
  addEventListener() {}
};
browserDocument.getElementById("operation").value = "start";
browserDocument.getElementById("component-inspector-content");

const now = new Date(Date.now() - 1000).toISOString();
const expires = new Date(Date.now() + 60000).toISOString();
const payloads = {
  "/api/v1alpha1/components": {
    generatedAt: now,
    observation: {state: "available", node: "lab-node", kubernetesVersion: "1.28", ageSeconds: 1},
    items: [{
      identity: {id: "ssc", displayName: "SSC"},
      profile: {id: "fortify-24.4", maturity: "tested", productVersion: "24.4"},
      version: {chart: "1.0", images: {}},
      dependencies: [],
      workloads: [],
      observedResources: [],
      supportedOperations: [],
      ingress: [],
      storage: []
    }]
  },
  "/api/v1alpha1/health": {
    generatedAt: now,
    state: "degraded",
    evidence: {source: "live"},
    items: [{
      id: "ssc",
      displayName: "SSC",
      state: "degraded",
      evidence: [{state: "degraded", summary: "Readiness pending"}],
      remediation: {summary: "Open health guidance", href: "/docs/health-checks.html#ssc"}
    }]
  },
  "/api/v1alpha1/availability": {
    items: [{
      id: "ssc-ui",
      componentId: "ssc",
      displayName: "SSC",
      url: "https://ssc.lab.example/",
      state: "reachable",
      dns: "matched",
      tls: "trusted",
      http: "200",
      latencyMs: 12,
      checkedAt: now,
      summary: "Reachable"
    }]
  },
  "/api/v1alpha1/preflight": {
    generatedAt: now,
    ready: true,
    readiness: {start: {ready: true, blockers: []}},
    summary: {blocker: 0, warning: 1},
    profile: {id: "fortify-24.4", maturity: "tested"},
    evidence: {source: "live"},
    items: [{
      id: "dns",
      status: "warning",
      summary: "Confirm client DNS",
      remediation: {summary: "Open DNS guidance", href: "/docs/deployment-preflight.html#dns"}
    }]
  },
  "/api/v1alpha1/history": {
    items: [{
      id: "operation-1",
      occurredAt: now,
      kind: "Operation",
      subject: "SSC",
      summary: "SSC start completed",
      state: "completed"
    }]
  },
  "/api/v1alpha1/capabilities": {
    apiVersion: "fortifylab.io/v1alpha1",
    kind: "ManagerCapabilities",
    contractVersion: "1.0",
    generatedAt: now,
    expiresAt: expires,
    refreshAfterSeconds: 30,
    capabilities: [{
      id: "lifecycle-execution",
      state: "available",
      presentationState: "available",
      severity: "info",
      category: "mutation",
      responsibleBoundary: "lifecycle-service-boundary",
      evidenceAt: now,
      canMutate: true,
      code: "AVAILABLE",
      prerequisites: [],
      remediation: {summary: "No action required; current evidence supports this capability.", href: "/docs/operations/lifecycle-engine.html"}
    }]
  }
};

globalThis.document = browserDocument;
globalThis.window = {location: {href: "https://lab.example/", search: "", assign() {}}};
globalThis.history = {replaceState() {}};
globalThis.sessionStorage = {getItem() { return null; }, setItem() {}, removeItem() {}};
globalThis.fetch = async path => ({
  ok: true,
  status: 200,
  async json() { return structuredClone(payloads[path]); }
});
globalThis.setTimeout = () => 1;
globalThis.clearTimeout = () => {};

vm.runInThisContext(fs.readFileSync(asset, "utf8"), {filename: asset});
for (let index = 0; index < 10; index += 1) await new Promise(resolve => setImmediate(resolve));

assert.equal(elements.get("history-list").children.length, 1, "populated history must render a row");
assert.equal(elements.get("history-list").children[0].children.length, 5, "history row must render five cells");
assert.equal(elements.get("capability-list").children.length, 1, "capability must render");
const capabilityCards = elements.get("capability-list").children[0].children.at(-1);
assert.equal(capabilityCards.children[0].children.at(-1).href, "/docs/operations/lifecycle-engine.html");
assert.match(capabilityCards.children[0].children[0].children[0].textContent, /lifecycle execution/i);
const serviceLink = elements.get("availability-list").children[0].children.at(-1);
assert.equal(serviceLink.href, "https://ssc.lab.example/");
assert.equal(serviceLink.target, "_blank");
assert.equal(serviceLink.rel, "noopener noreferrer");
assert.equal(elements.get("operation-form").elements[0].disabled, false, "valid capability must not disable operations");
for (const panel of ["components", "health", "availability", "preflight", "history", "capabilities"]) {
  assert.doesNotMatch(elements.get(`${panel}-panel-state`).textContent, /READ_FAILED/);
}
