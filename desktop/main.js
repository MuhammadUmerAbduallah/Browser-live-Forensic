// main.js
// Electron main process.
// - Runs the local-only listener on http://localhost:9000/log
// - Persists every event to the local store (SQLite or JSONL fallback)
// - Streams live events to the dashboard
// - Answers dashboard queries (history, search, stats, cases) over IPC
// No cloud, no external APIs, no telemetry.

const { app, BrowserWindow, ipcMain, dialog } = require("electron");
const path = require("path");
const fs = require("fs");
const express = require("express");
const { createStore } = require("./db");
const browsers = require("./browsers");
const acquire = require("./acquire");

// --- quiet the GPU disk-cache noise seen in the POC ---
app.disableHardwareAcceleration();
app.commandLine.appendSwitch("disable-gpu");
app.commandLine.appendSwitch("disable-gpu-shader-disk-cache");

// Keep all data inside the app folder so it is easy to find and fully local.
const dataDir = path.join(__dirname, "..", "data");
const legacyLogPath = path.join(__dirname, "..", "logs", "events.jsonl");

let store;
let win;

// One-time import of any pre-existing JSONL log into the store (deduped by id).
function importLegacyLog() {
  if (!fs.existsSync(legacyLogPath)) return;
  let imported = 0;
  for (const line of fs.readFileSync(legacyLogPath, "utf8").split("\n")) {
    const t = line.trim();
    if (!t) continue;
    try { if (store.insert(JSON.parse(t))) imported++; } catch { /* skip */ }
  }
  if (imported) console.log(`[import] loaded ${imported} events from legacy log`);
}

/* ------------------------------ HTTP listener ----------------------------- */

const server = express();
server.use(express.json({ limit: "2mb" }));

// Only accept connections from this machine.
server.use((req, res, next) => {
  const ip = req.socket.remoteAddress || "";
  if (ip === "127.0.0.1" || ip === "::1" || ip === "::ffff:127.0.0.1") return next();
  res.sendStatus(403);
});

server.get("/health", (_req, res) => res.json({ ok: true, backend: store.backend }));

server.post("/log", (req, res) => {
  const event = {
    id: `evt_${Date.now()}_${Math.random().toString(16).slice(2)}`,
    receivedAt: new Date().toISOString(),
    ...req.body,
  };
  let stored;
  try {
    stored = store.insert(event);
  } catch (err) {
    console.error("[store] insert failed:", err.message);
    return res.sendStatus(500);
  }
  if (win && !win.isDestroyed()) win.webContents.send("log-event", stored);
  scheduleDetect();
  res.sendStatus(200);
});

/* ----------------------- incremental detection scheduler ------------------ */
// Detection runs at most once per debounce window, scanning only recently
// active sessions — never a full rescan of the database per event.
let detectTimer = null;
function scheduleDetect() {
  if (detectTimer) return;
  detectTimer = setTimeout(() => {
    detectTimer = null;
    try {
      const r = store.detectIncremental();
      store.graphIngestIncremental();
      if (win && !win.isDestroyed()) {
        if (r.changed) win.webContents.send("findings-updated", store.findingsMeta());
        win.webContents.send("graph-updated", store.graphStats());
      }
    } catch (err) {
      console.error("[detect] incremental scan failed:", err.message);
    }
  }, 2000);
}

/* --------------------------------- IPC ------------------------------------ */

function registerIpc() {
  ipcMain.handle("q:recent", (_e, limit) => store.recent(limit));
  ipcMain.handle("q:search", (_e, filters) => store.search(filters));
  ipcMain.handle("q:stats", () => store.stats());
  ipcMain.handle("q:cookies", (_e, limit) => store.cookieSummary(limit));
  ipcMain.handle("q:domains", (_e, limit) => store.domainSummary(limit));
  ipcMain.handle("q:cases", () => store.cases());
  ipcMain.handle("q:case", (_e, id) => store.caseDetail(id));
  ipcMain.handle("q:investigate", (_e, domain) => store.investigate(domain));
  ipcMain.handle("q:sessions", () => store.sessions());
  ipcMain.handle("q:session", (_e, id) => store.sessionDetail(id));
  ipcMain.handle("q:findings", (_e, filter) => store.findings(filter || {}));
  ipcMain.handle("q:finding", (_e, id) => store.finding(id));
  ipcMain.handle("q:findingsMeta", () => store.findingsMeta());
  ipcMain.handle("detect:run", () => store.detectAll());
  ipcMain.handle("ioc:list", () => store.iocList());
  ipcMain.handle("ioc:add", (_e, { category, value }) => store.iocAdd(category, value));

  // Relationship graph & evidence correlation.
  ipcMain.handle("graph:view", (_e, opts) => store.graphView(opts || {}));
  ipcMain.handle("graph:neighborhood", (_e, { id, depth, cap }) => store.graphNeighborhood(id, depth, cap));
  ipcMain.handle("graph:paths", (_e, { id, opts }) => store.graphPaths(id, opts || {}));
  ipcMain.handle("graph:path", (_e, { from, to }) => store.graphPath(from, to));
  ipcMain.handle("graph:clusters", (_e, opts) => store.graphClusters(opts || {}));
  ipcMain.handle("graph:stats", () => store.graphStats());
  ipcMain.handle("graph:rebuild", () => store.graphRebuild());
  ipcMain.handle("graph:export", async (_e, { format } = {}) => {
    const fmt = format || "json";
    const ext = fmt === "graphml" ? "graphml" : fmt === "html" ? "html" : "json";
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export relationship graph",
      defaultPath: `relationship_graph.${ext}`,
      filters: [{ name: ext.toUpperCase(), extensions: [ext] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = fmt === "html"
      ? renderGraphReport(store.graphExportData(), store.graphClusters({ limit: 25 }))
      : store.graphSerialize(fmt);
    fs.writeFileSync(filePath, content, "utf8");
    return { ok: true, filePath };
  });
  ipcMain.handle("case:create", (_e, spec) => store.createCase(spec));
  ipcMain.handle("data:clear", () => { store.clear(); return true; });
  ipcMain.handle("data:clearScope", (_e, scopes) => store.clearScope(scopes || {}));
  ipcMain.handle("data:prune", () => store.prune());
  ipcMain.handle("meta", () => ({ backend: store.backend, dataDir }));

  /* ----------------------- browser acquisition (read-only) ---------------- */

  // Enumerate installed browsers + profiles on this host.
  ipcMain.handle("acq:browsers", () => browsers.discover());

  // Run a read-only acquisition for one { browserId, profilePath } and persist
  // it to the acquisitions sidecar. Heavy file IO runs off the main flow.
  ipcMain.handle("acq:run", async (_e, spec = {}) => {
    const target = browsers.resolveTarget(spec.browserId, spec.profilePath);
    if (!target) return { ok: false, error: "Unknown browser or profile" };
    try {
      const result = await Promise.resolve().then(() =>
        acquire.acquireProfile(target, { artifactTypes: spec.artifactTypes || null }));
      const summary = store.acqSaveRun(result);
      if (win && !win.isDestroyed()) win.webContents.send("acq-updated", store.acqStats());
      return { ok: true, summary };
    } catch (err) {
      console.error("[acquire] run failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle("acq:list", () => store.acqList());
  ipcMain.handle("acq:detail", (_e, id) => store.acqDetail(id));
  ipcMain.handle("acq:records", (_e, { id, filter } = {}) => store.acqRecords(id, filter || {}));
  ipcMain.handle("acq:stats", () => store.acqStats());
  ipcMain.handle("acq:remove", (_e, id) => store.acqRemove(id));

  // Export an acquisition as a standalone HTML or JSON report.
  ipcMain.handle("acq:export", async (_e, { id, format } = {}) => {
    const detail = store.acqDetail(id);
    if (!detail) return { ok: false, error: "Acquisition not found" };
    const full = { ...detail, records: store.acqRecords(id, { limit: 5000 }).rows };
    const safeName = `${detail.run.browser}_${(detail.run.profile || "profile")}`
      .replace(/[^a-z0-9]+/gi, "_").slice(0, 50);
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export acquisition report",
      defaultPath: `acquisition_${safeName}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(full, null, 2)
      : renderAcquisitionReport(full);
    fs.writeFileSync(filePath, content, "utf8");
    store.integrityRecordExport({ sourceEngine: "acquisition", format: filePath.endsWith(".json") ? "JSON" : "HTML", filePath, content, relatedEvidenceIds: id ? [id] : [] });
    return { ok: true, filePath };
  });

  /* ----------------------- timeline reconstruction ----------------------- */

  // Build (or rebuild) the unified forensic timeline from live events,
  // findings and acquisition records. Heavy work runs off the main flow.
  ipcMain.handle("timeline:build", async () => {
    try {
      const meta = await Promise.resolve().then(() => store.timelineBuild());
      if (win && !win.isDestroyed()) win.webContents.send("timeline-updated", meta);
      return { ok: true, meta };
    } catch (err) {
      console.error("[timeline] build failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle("timeline:list", (_e, filter = {}) => {
    const result = store.timelineQuery(filter);
    return { ...result, filters: store.timelineFilters(), stats: store.timelineStats() };
  });

  ipcMain.handle("timeline:detail", (_e, id) => store.timelineDetail(id));

  // Export the (optionally filtered) timeline as a standalone HTML or JSON report.
  ipcMain.handle("timeline:export", async (_e, { format, filter } = {}) => {
    const data = store.timelineExport(filter || {});
    if (!data || !data.meta || !data.meta.built) return { ok: false, error: "Timeline not built yet" };
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export timeline report",
      defaultPath: `timeline_${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(data, null, 2)
      : renderTimelineReport(data);
    fs.writeFileSync(filePath, content, "utf8");
    store.integrityRecordExport({ sourceEngine: "timeline", format: filePath.endsWith(".json") ? "JSON" : "HTML", filePath, content });
    return { ok: true, filePath };
  });

  /* ------------------------- extension forensics ------------------------- */

  // Scan acquired extension artifacts + timeline + findings into extension
  // profiles and risk findings. Uses existing acquisition data — no reacquire.
  ipcMain.handle("ext:scan", async () => {
    try {
      const meta = await Promise.resolve().then(() => store.extScan());
      if (win && !win.isDestroyed()) win.webContents.send("extensions-updated", meta);
      return { ok: true, meta };
    } catch (err) {
      console.error("[extensions] scan failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle("ext:list", (_e, filter = {}) => {
    const result = store.extList(filter);
    return { ...result, filters: store.extFilters(), stats: store.extStats() };
  });

  ipcMain.handle("ext:detail", (_e, { extensionId, key } = {}) => store.extDetail(extensionId, key));

  ipcMain.handle("ext:findings", (_e, filter = {}) => store.extFindings(filter));

  // Export the (optionally filtered) extension forensics report as HTML or JSON.
  ipcMain.handle("ext:export", async (_e, { format, filter } = {}) => {
    const data = store.extExport(filter || {});
    if (!data || !data.meta || !data.meta.scanned) return { ok: false, error: "Extensions not scanned yet" };
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export extension forensics report",
      defaultPath: `extensions_${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(data, null, 2)
      : renderExtensionReport(data);
    fs.writeFileSync(filePath, content, "utf8");
    store.integrityRecordExport({ sourceEngine: "extension", format: filePath.endsWith(".json") ? "JSON" : "HTML", filePath, content });
    return { ok: true, filePath };
  });

  /* --------------------------- cache forensics --------------------------- */

  // Scan acquired cache artifacts (+ permitted metadata-only on-disk reads) into
  // cache profiles and risk findings. Heavy work runs off the main flow.
  ipcMain.handle("cache:scan", async () => {
    try {
      const meta = await Promise.resolve().then(() => store.cacheScan());
      if (win && !win.isDestroyed()) win.webContents.send("cache-updated", meta);
      return { ok: true, meta };
    } catch (err) {
      console.error("[cache] scan failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle("cache:list", (_e, filter = {}) => {
    const result = store.cacheList(filter);
    return { ...result, filters: store.cacheFilters(), stats: store.cacheStats() };
  });

  ipcMain.handle("cache:detail", (_e, id) => store.cacheDetail(id));

  ipcMain.handle("cache:findings", (_e, filter = {}) => store.cacheFindings(filter));

  // Export the (optionally filtered) cache forensics report as HTML or JSON.
  ipcMain.handle("cache:export", async (_e, { format, filter } = {}) => {
    const data = store.cacheExport(filter || {});
    if (!data || !data.meta || !data.meta.scanned) return { ok: false, error: "Cache not scanned yet" };
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export cache forensics report",
      defaultPath: `cache_${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(data, null, 2)
      : renderCacheReport(data);
    fs.writeFileSync(filePath, content, "utf8");
    store.integrityRecordExport({ sourceEngine: "cache", format: filePath.endsWith(".json") ? "JSON" : "HTML", filePath, content });
    return { ok: true, filePath };
  });

  /* --------------------------- evidence integrity ------------------------ */

  ipcMain.handle("integrity:list", (_e, filter = {}) => {
    const result = store.integrityList(filter);
    return { ...result, filters: store.integrityFilters(), stats: store.integrityStats() };
  });

  ipcMain.handle("integrity:detail", (_e, id) => store.integrityDetail(id));

  ipcMain.handle("integrity:verify", async (_e, id) => {
    try {
      const res = store.integrityVerify(id);
      if (win && !win.isDestroyed()) win.webContents.send("integrity-updated", store.integrityStats());
      return res;
    } catch (err) {
      console.error("[integrity] verify failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle("integrity:verifyAll", async () => {
    try {
      const stats = await Promise.resolve().then(() => store.integrityVerifyAll());
      if (win && !win.isDestroyed()) win.webContents.send("integrity-updated", stats);
      return { ok: true, stats };
    } catch (err) {
      console.error("[integrity] verifyAll failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  // Export the (optionally filtered) integrity report; the export file is itself
  // registered as evidence (chain-of-custody: created + exported).
  ipcMain.handle("integrity:export", async (_e, { format, filter } = {}) => {
    const data = store.integrityExport(filter || {});
    if (!data || !data.meta || !data.meta.built) return { ok: false, error: "No integrity baseline yet" };
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export evidence integrity report",
      defaultPath: `integrity_${new Date().toISOString().slice(0, 10)}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(data, null, 2)
      : renderIntegrityReport(data);
    fs.writeFileSync(filePath, content, "utf8");
    store.integrityRecordExport({ sourceEngine: "integrity", format: filePath.endsWith(".json") ? "JSON" : "HTML", filePath, content });
    if (win && !win.isDestroyed()) win.webContents.send("integrity-updated", store.integrityStats());
    return { ok: true, filePath };
  });

  /* ------------------------------ reporting ------------------------------ */

  ipcMain.handle("report:list", (_e, filter = {}) => {
    const result = store.reportList(filter);
    return { ...result, stats: store.reportStats() };
  });

  ipcMain.handle("report:detail", (_e, id) => store.reportDetail(id));

  ipcMain.handle("report:create", async (_e, options = {}) => {
    try {
      const record = await Promise.resolve().then(() => store.reportCreate(options));
      if (win && !win.isDestroyed()) win.webContents.send("reports-updated", store.reportStats());
      return { ok: true, report: record };
    } catch (err) {
      console.error("[report] create failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  // Export a stored report as HTML, JSON or a real (Chromium-rendered) PDF. The
  // written file is registered as evidence in the Integrity Engine.
  ipcMain.handle("report:export", async (_e, { reportId, format } = {}) => {
    const record = store.reportExportData(reportId);
    if (!record) return { ok: false, error: "Unknown report" };
    const fmt = String(format || "html").toLowerCase();
    const ext = fmt === "pdf" ? "pdf" : (fmt === "json" ? "json" : "html");
    const stamp = new Date().toISOString().slice(0, 10);
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export forensic report",
      defaultPath: `${record.reportType}_report_${stamp}.${ext}`,
      filters: [
        { name: "PDF report", extensions: ["pdf"] },
        { name: "HTML report", extensions: ["html"] },
        { name: "JSON", extensions: ["json"] },
      ],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    try {
      if (filePath.endsWith(".json")) {
        fs.writeFileSync(filePath, JSON.stringify(record, null, 2), "utf8");
      } else if (filePath.endsWith(".pdf")) {
        const pdf = await htmlToPdf(renderReportHtml(record));
        fs.writeFileSync(filePath, pdf);
      } else {
        fs.writeFileSync(filePath, renderReportHtml(record), "utf8");
      }
      store.integrityRecordExport({
        sourceEngine: "report", format: ext.toUpperCase(), filePath,
        relatedEvidenceIds: [record.reportId],
      });
      if (win && !win.isDestroyed()) win.webContents.send("integrity-updated", store.integrityStats());
      return { ok: true, filePath };
    } catch (err) {
      console.error("[report] export failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  /* -------------------------- threat hunting ----------------------------- */

  ipcMain.handle("hunt:scan", async () => {
    try {
      const meta = await Promise.resolve().then(() => store.huntScan());
      if (win && !win.isDestroyed()) win.webContents.send("hunting-updated", meta);
      return { ok: true, meta };
    } catch (err) {
      console.error("[hunt] scan failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  ipcMain.handle("hunt:list", (_e, filter = {}) => {
    const result = store.huntList(filter);
    return { ...result, filters: store.huntFilters(), stats: store.huntStats() };
  });

  ipcMain.handle("hunt:detail", (_e, id) => store.huntDetail(id));

  ipcMain.handle("hunt:chains", (_e, filter = {}) => {
    const result = store.huntChains(filter);
    return { ...result, stats: store.huntStats() };
  });

  // Export the (optionally filtered) threat-hunting report as HTML, JSON or a
  // real (Chromium-rendered) PDF. The written file is registered as evidence.
  ipcMain.handle("hunt:export", async (_e, { format, filter } = {}) => {
    const data = store.huntExportData(filter || {});
    if (!data || !data.meta || !data.meta.scanned) return { ok: false, error: "No hunt results yet" };
    const fmt = String(format || "html").toLowerCase();
    const ext = fmt === "pdf" ? "pdf" : (fmt === "json" ? "json" : "html");
    const stamp = new Date().toISOString().slice(0, 10);
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export threat hunting report",
      defaultPath: `threat_hunt_${stamp}.${ext}`,
      filters: [
        { name: "PDF report", extensions: ["pdf"] },
        { name: "HTML report", extensions: ["html"] },
        { name: "JSON", extensions: ["json"] },
      ],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    try {
      if (filePath.endsWith(".json")) {
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
      } else if (filePath.endsWith(".pdf")) {
        const pdf = await htmlToPdf(renderHuntReport(data));
        fs.writeFileSync(filePath, pdf);
      } else {
        fs.writeFileSync(filePath, renderHuntReport(data), "utf8");
      }
      store.integrityRecordExport({ sourceEngine: "hunting", format: ext.toUpperCase(), filePath });
      if (win && !win.isDestroyed()) win.webContents.send("integrity-updated", store.integrityStats());
      return { ok: true, filePath };
    } catch (err) {
      console.error("[hunt] export failed:", err.message);
      return { ok: false, error: err.message };
    }
  });

  // Export findings: a single finding, all findings, or by severity. HTML/JSON.
  ipcMain.handle("findings:export", async (_e, optsIn = {}) => {
    const scope = optsIn.scope || "all";
    let payload, defaultName, htmlBuilder;
    if (scope === "one") {
      const detail = store.finding(optsIn.id);
      if (!detail) return { ok: false, error: "Finding not found" };
      payload = detail;
      defaultName = `finding_${(detail.finding.rule || "f").toLowerCase()}`;
      htmlBuilder = () => renderFindingHtml(detail);
    } else {
      const filter = scope === "severity" ? { severity: optsIn.severity } : {};
      const list = store.findings(filter);
      payload = { scope, severity: optsIn.severity || null, count: list.length, findings: list };
      defaultName = scope === "severity" ? `findings_${(optsIn.severity || "all").toLowerCase()}` : "findings_all";
      const heading = scope === "severity" ? `${optsIn.severity} findings` : "All findings";
      htmlBuilder = () => renderFindingsHtml(list, heading);
    }
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export findings report",
      defaultPath: `${defaultName}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json") ? JSON.stringify(payload, null, 2) : htmlBuilder();
    fs.writeFileSync(filePath, content, "utf8");
    return { ok: true, filePath };
  });

  // Export a reconstructed session as a standalone HTML/JSON report.
  ipcMain.handle("session:export", async (_e, id) => {
    const detail = store.sessionDetail(id);
    if (!detail) return { ok: false, error: "Session not found" };
    const safeName = (detail.primaryDomain || "session").replace(/[^a-z0-9]+/gi, "_").slice(0, 40);
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export session report",
      defaultPath: `session_${safeName}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(detail, null, 2)
      : renderSessionReport(detail);
    fs.writeFileSync(filePath, content, "utf8");
    return { ok: true, filePath };
  });

  // Export an investigation as a standalone HTML report.
  ipcMain.handle("investigation:export", async (_e, domain) => {
    const detail = store.investigate(domain);
    if (!detail || !detail.domain) return { ok: false, error: "No domain" };
    const safeName = detail.domain.replace(/[^a-z0-9]+/gi, "_").slice(0, 40);
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export investigation report",
      defaultPath: `investigation_${safeName}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(detail, null, 2)
      : renderInvestigationReport(detail);
    fs.writeFileSync(filePath, content, "utf8");
    return { ok: true, filePath };
  });

  // Export a case as a standalone HTML evidence report the user can keep/share.
  ipcMain.handle("case:export", async (_e, id) => {
    const detail = store.caseDetail(id);
    if (!detail) return { ok: false, error: "Case not found" };
    const safeName = (detail.case.title || "case").replace(/[^a-z0-9]+/gi, "_").slice(0, 40);
    const { canceled, filePath } = await dialog.showSaveDialog(win, {
      title: "Export evidence report",
      defaultPath: `${safeName}.html`,
      filters: [{ name: "HTML report", extensions: ["html"] }, { name: "JSON", extensions: ["json"] }],
    });
    if (canceled || !filePath) return { ok: false, error: "Cancelled" };
    const content = filePath.endsWith(".json")
      ? JSON.stringify(detail, null, 2)
      : renderReport(detail);
    fs.writeFileSync(filePath, content, "utf8");
    return { ok: true, filePath };
  });
}

/* --------------------------- evidence report HTML ------------------------- */

function renderReport(detail) {
  const { case: c, events, summary } = detail;
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const rows = events.map((e) => `
    <tr class="r-${e.risk}">
      <td>${fmt(e.ts)}</td><td>${esc(e.type)}</td><td>${esc(e.detail)}</td>
      <td>${esc(e.domain)}</td><td><b>${e.risk}</b></td>
      <td>${esc(e.reasons.join("; "))}</td>
    </tr>`).join("");
  const typeRows = Object.entries(summary.byType)
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("");
  const domainRows = summary.topDomains
    .map((d) => `<li>${esc(d.domain)} — ${d.c}</li>`).join("");

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Evidence Report — ${esc(c.title)}</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} .muted{color:#667085}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:16px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc} .r-HIGH td:nth-child(5){color:#c0392b}
  .r-MEDIUM td:nth-child(5){color:#b9770e} .r-INFO td:nth-child(5){color:#2a6fb0}
  ul{margin:6px 0;padding-left:18px}
</style></head><body>
<h1>Evidence Report</h1>
<div class="muted">${esc(c.id)} · generated ${new Date().toLocaleString()}</div>
<h2>${esc(c.title)}</h2>
${c.notes ? `<p>${esc(c.notes)}</p>` : ""}
<div class="grid">
  <div class="card"><b>Time range</b><br>${fmt(summary.since)}<br>→ ${fmt(summary.until)}</div>
  <div class="card"><b>Events</b><br>${summary.total} total<br>
    <span style="color:#c0392b">HIGH ${summary.byRisk.HIGH}</span> ·
    <span style="color:#b9770e">MED ${summary.byRisk.MEDIUM}</span> ·
    <span style="color:#2a6fb0">INFO ${summary.byRisk.INFO}</span></div>
  <div class="card"><b>By type</b><ul>${typeRows || "<li>none</li>"}</ul></div>
  <div class="card"><b>Top domains</b><ul>${domainRows || "<li>none</li>"}</ul></div>
</div>
<table><thead><tr><th>Time</th><th>Type</th><th>Detail</th><th>Domain</th><th>Risk</th><th>Reasons</th></tr></thead>
<tbody>${rows || '<tr><td colspan="6">No events matched this case.</td></tr>'}</tbody></table>
<p class="muted" style="margin-top:24px">Generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* ----------------------- investigation report HTML ------------------------ */

function renderInvestigationReport(detail) {
  const { domain, summary, riskOverview, trackers, relatedDomains, timeline, chains } = detail;
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

  const typeRows = Object.entries(summary.byType)
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";
  const reasonRows = riskOverview.topReasons
    .map((r) => `<li>${esc(r.reason)} — ${r.count}</li>`).join("") || "<li>none</li>";
  const trackerRows = trackers.map((t) => `
    <tr class="r-${t.risk}">
      <td>${esc(t.domain)}</td><td>${t.count}</td>
      <td>${t.analytics ? "analytics" : "tracker"}</td>
      <td><b>${t.risk}</b></td><td>${fmt(t.last)}</td>
    </tr>`).join("") || `<tr><td colspan="5">No trackers observed.</td></tr>`;
  const relatedRows = relatedDomains.map((r) => `
    <tr><td>${esc(r.domain)}${r.tracker ? " · tracker" : ""}</td>
    <td>${r.count}</td><td>${r.asParent}</td><td>${r.asChild}</td></tr>`).join("")
    || `<tr><td colspan="4">No related domains.</td></tr>`;
  const timelineRows = timeline.map((e) => `
    <tr class="r-${e.risk}">
      <td>${fmt(e.ts)}</td><td>${esc(e.type)}</td><td>${esc(e.detail)}</td>
      <td><b>${e.risk}</b></td></tr>`).join("")
    || `<tr><td colspan="4">No events.</td></tr>`;
  const chainRows = chains.map((ch) => `
    <div class="chain r-${ch.risk}">
      <b>${esc(ch.label)}</b> · <span class="muted">${fmt(ch.since)} → ${fmt(ch.until)} (${Math.round(ch.span / 1000)}s)</span>
      <ul>${ch.steps.map((s) => `<li>[${esc(s.type)}] ${esc(s.detail)} <span class="muted">${esc(s.domain)}</span></li>`).join("")}</ul>
    </div>`).join("") || `<p class="muted">No correlation chains.</p>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Investigation — ${esc(domain)}</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} .muted{color:#667085}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  .r-HIGH td:last-child,.r-HIGH b{color:#c0392b}
  .r-MEDIUM td:last-child,.r-MEDIUM b{color:#b9770e}
  .r-INFO td:last-child,.r-INFO b{color:#2a6fb0}
  ul{margin:6px 0;padding-left:18px}
  .chain{border:1px solid #e3e8ef;border-left:4px solid #999;border-radius:8px;padding:10px 14px;margin:8px 0}
  .chain.r-HIGH{border-left-color:#c0392b}.chain.r-MEDIUM{border-left-color:#b9770e}.chain.r-INFO{border-left-color:#2a6fb0}
  h2{margin-top:28px}
</style></head><body>
<h1>Investigation Report</h1>
<div class="muted">${esc(domain)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>Activity</b><br>${summary.total} events<br>
    ${fmt(summary.firstSeen)}<br>→ ${fmt(summary.lastSeen)}</div>
  <div class="card"><b>Risk</b><br>peak <b>${riskOverview.maxRisk}</b> (score ${riskOverview.maxScore})<br>
    <span style="color:#c0392b">HIGH ${riskOverview.byRisk.HIGH}</span> ·
    <span style="color:#b9770e">MED ${riskOverview.byRisk.MEDIUM}</span> ·
    <span style="color:#2a6fb0">INFO ${riskOverview.byRisk.INFO}</span><br>
    ${riskOverview.isTracker ? "⚠ known tracker<br>" : ""}${riskOverview.suspiciousTld ? "⚠ suspicious TLD" : ""}</div>
  <div class="card"><b>By type</b><ul>${typeRows}</ul></div>
  <div class="card"><b>Top reasons</b><ul>${reasonRows}</ul></div>
</div>
<h2>Tracker intelligence</h2>
<table><thead><tr><th>Endpoint</th><th>Hits</th><th>Kind</th><th>Risk</th><th>Last</th></tr></thead>
<tbody>${trackerRows}</tbody></table>
<h2>Related domains</h2>
<table><thead><tr><th>Domain</th><th>Links</th><th>As parent</th><th>As child</th></tr></thead>
<tbody>${relatedRows}</tbody></table>
<h2>Correlation chains</h2>
${chainRows}
<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Type</th><th>Detail</th><th>Risk</th></tr></thead>
<tbody>${timelineRows}</tbody></table>
<p class="muted" style="margin-top:24px">Generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* -------------------------- session report HTML --------------------------- */

function renderSessionReport(detail) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const dur = (ms) => {
    if (!ms) return "0s";
    const s = Math.round(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60);
    return h ? `${h}h ${m % 60}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
  };

  const visited = detail.visitedDomains.map((d) => `<li>${esc(d)}</li>`).join("") || "<li>none</li>";
  const trackers = detail.trackerDomains.map((d) => `<li>${esc(d)}</li>`).join("") || "<li>none</li>";
  const perms = detail.permissionsRequested
    .map((p) => `<tr class="r-${p.risk}"><td>${fmt(p.ts)}</td><td>${esc(p.permission)}</td><td>${esc(p.domain)}</td></tr>`)
    .join("") || `<tr><td colspan="3">No permission requests.</td></tr>`;
  const dls = detail.downloads
    .map((d) => `<tr class="r-${d.risk}"><td>${fmt(d.ts)}</td><td>${esc(d.filename || d.url)}</td><td>${esc(d.domain)}</td></tr>`)
    .join("") || `<tr><td colspan="3">No downloads.</td></tr>`;
  const related = detail.relatedDomains
    .map((r) => `<tr><td>${esc(r.domain)}${r.tracker ? " · tracker" : ""}</td><td>${r.count}</td><td>${r.asParent}</td><td>${r.asChild}</td></tr>`)
    .join("") || `<tr><td colspan="4">No related domains.</td></tr>`;
  const timeline = detail.timeline
    .map((e) => `<tr class="r-${e.risk}"><td>${fmt(e.ts)}</td><td>${esc(e.type)}</td><td>${esc(e.detail)}</td><td>${esc(e.domain)}</td><td><b>${e.risk}</b></td></tr>`)
    .join("") || `<tr><td colspan="5">No events.</td></tr>`;
  const phaseBlocks = detail.phases.map((p) => `
    <div class="phase"><b>${esc(p.phase)}</b> <span class="muted">(${p.count})</span>
      <ul>${p.events.map((e) => `<li>${fmt(e.ts)} — ${esc(e.detail)} <span class="muted">${esc(e.domain)}</span></li>`).join("") || "<li>none</li>"}</ul>
    </div>`).join("");

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Session Report — ${esc(detail.primaryDomain)}</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  .r-HIGH td:last-child,.r-HIGH b{color:#c0392b}
  .r-MEDIUM td:last-child,.r-MEDIUM b{color:#b9770e}
  .r-INFO td:last-child,.r-INFO b{color:#2a6fb0}
  ul{margin:6px 0;padding-left:18px}
  .phase{border:1px solid #e3e8ef;border-radius:8px;padding:10px 14px;margin:8px 0}
</style></head><body>
<h1>Session Report</h1>
<div class="muted">${esc(detail.sessionId)} · generated ${new Date().toLocaleString()}</div>
<h2>${esc(detail.primaryDomain || "Session")}</h2>
<div class="grid">
  <div class="card"><b>Window</b><br>${fmt(detail.startTime)}<br>→ ${fmt(detail.endTime)}<br><span class="muted">${dur(detail.duration)}</span></div>
  <div class="card"><b>Risk</b><br>session <b>${detail.risk}</b><br>cumulative score ${detail.riskScore}<br><span class="muted">peak event ${detail.peakRisk}</span></div>
  <div class="card"><b>Footprint</b><br>${detail.eventCount} events<br>${detail.cookiesCreated} cookies · ${detail.storageWrites} storage<br>${detail.permissionsRequested.length} permissions · ${detail.downloads.length} downloads</div>
  <div class="card"><b>Domains visited (${detail.visitedDomains.length})</b><ul>${visited}</ul></div>
  <div class="card"><b>Trackers (${detail.trackerDomains.length})</b><ul>${trackers}</ul></div>
</div>
<h2>Activity chain</h2>
${phaseBlocks}
<h2>Permissions</h2>
<table><thead><tr><th>Time</th><th>Permission</th><th>Domain</th></tr></thead><tbody>${perms}</tbody></table>
<h2>Downloads</h2>
<table><thead><tr><th>Time</th><th>File</th><th>Domain</th></tr></thead><tbody>${dls}</tbody></table>
<h2>Related domains</h2>
<table><thead><tr><th>Domain</th><th>Links</th><th>As parent</th><th>As child</th></tr></thead><tbody>${related}</tbody></table>
<h2>Timeline</h2>
<table><thead><tr><th>Time</th><th>Type</th><th>Detail</th><th>Domain</th><th>Risk</th></tr></thead><tbody>${timeline}</tbody></table>
<p class="muted" style="margin-top:24px">Generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* -------------------------- findings report HTML -------------------------- */

const FINDINGS_REPORT_CSS = `
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  .sev{font-weight:700} .s-CRITICAL{color:#a11630} .s-HIGH{color:#c0392b}
  .s-MEDIUM{color:#b9770e} .s-LOW{color:#2a6fb0}
  .finding{border:1px solid #e3e8ef;border-left:5px solid #999;border-radius:8px;padding:14px 16px;margin:12px 0}
  .finding.CRITICAL{border-left-color:#a11630}.finding.HIGH{border-left-color:#c0392b}
  .finding.MEDIUM{border-left-color:#b9770e}.finding.LOW{border-left-color:#2a6fb0}
  ul,ol{margin:6px 0;padding-left:18px}`;

function fHtmlHelpers() {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  return { esc, fmt };
}

function renderFindingsHtml(list, heading) {
  const { esc, fmt } = fHtmlHelpers();
  const rows = list.map((f) => `
    <tr>
      <td class="sev s-${f.severity}">${f.severity}</td>
      <td>${esc(f.title)}</td>
      <td>${Math.round((f.confidence || 0) * 100)}%</td>
      <td>${esc((f.affectedDomains || []).slice(0, 3).join(", "))}</td>
      <td>${esc((f.affectedSessions || []).join(", "))}</td>
      <td>${fmt(f.lastSeen)}</td>
    </tr>`).join("") || `<tr><td colspan="6">No findings.</td></tr>`;
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Findings — ${esc(heading)}</title><style>${FINDINGS_REPORT_CSS}</style></head><body>
<h1>Forensic Findings</h1>
<div class="muted">${esc(heading)} · ${list.length} finding(s) · generated ${new Date().toLocaleString()}</div>
<table><thead><tr><th>Severity</th><th>Title</th><th>Confidence</th><th>Domains</th><th>Sessions</th><th>Last seen</th></tr></thead>
<tbody>${rows}</tbody></table>
<p class="muted" style="margin-top:24px">Generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

function renderFindingHtml(detail) {
  const { esc, fmt } = fHtmlHelpers();
  const f = detail.finding;
  const evidence = f.evidence.map((s, i) => `
    <li><b>${i + 1}.</b> [${esc(s.type)}] ${esc(s.detail)} <span class="muted">${esc(s.domain)} · ${fmt(s.ts)} · ${s.risk}</span></li>`).join("");
  const events = detail.relatedEvents.map((e) => `
    <tr><td>${fmt(e.ts)}</td><td>${esc(e.type)}</td><td>${esc(e.detail)}</td><td>${esc(e.domain)}</td><td>${e.risk}</td></tr>`).join("")
    || `<tr><td colspan="5">None.</td></tr>`;
  const sessions = detail.relatedSessions.map((s) => `
    <tr><td>${esc(s.sessionId)}</td><td>${esc(s.primaryDomain)}</td><td>${s.risk}</td><td>${s.riskScore}</td><td>${s.eventCount}</td></tr>`).join("")
    || `<tr><td colspan="5">None.</td></tr>`;
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Finding — ${esc(f.title)}</title><style>${FINDINGS_REPORT_CSS}</style></head><body>
<h1>Forensic Finding</h1>
<div class="muted">${esc(f.id)} · generated ${new Date().toLocaleString()}</div>
<div class="finding ${f.severity}">
  <h2 style="margin-top:0">${esc(f.title)} <span class="sev s-${f.severity}">[${f.severity}]</span></h2>
  <p>${esc(f.description)}</p>
  <p class="muted">Confidence ${Math.round((f.confidence || 0) * 100)}% · ${fmt(f.firstSeen)} → ${fmt(f.lastSeen)}</p>
  <p><b>Detection logic:</b> ${esc(detail.logic)}</p>
  <p><b>Affected domains:</b> ${esc((f.affectedDomains || []).join(", ") || "none")}</p>
  <p><b>Affected sessions:</b> ${esc((f.affectedSessions || []).join(", ") || "none")}</p>
</div>
<h2>Evidence chain</h2><ol>${evidence || "<li>none</li>"}</ol>
<h2>Related events</h2>
<table><thead><tr><th>Time</th><th>Type</th><th>Detail</th><th>Domain</th><th>Risk</th></tr></thead><tbody>${events}</tbody></table>
<h2>Related sessions</h2>
<table><thead><tr><th>Session</th><th>Primary domain</th><th>Risk</th><th>Score</th><th>Events</th></tr></thead><tbody>${sessions}</tbody></table>
<p class="muted" style="margin-top:24px">Generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* ---------------------------- graph report HTML --------------------------- */

function renderGraphReport(graphData, clusters) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const s = graphData.stats;
  const typeRows = Object.entries(s.byType)
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";
  const edgeRows = Object.entries(s.byEdge)
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";
  const topNodes = [...graphData.nodes]
    .sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 30)
    .map((n) => `<tr class="r-${n.risk}"><td>${esc(n.type)}</td><td>${esc(n.label)}</td><td><b>${n.risk}</b></td><td>${n.score || 0}</td></tr>`)
    .join("") || `<tr><td colspan="4">No nodes.</td></tr>`;
  const clusterRows = clusters.map((c) => `
    <tr class="${c.highRisk ? "r-HIGH" : ""}">
      <td>${esc(c.label)}</td><td>${c.size}</td><td>${c.trackers}</td>
      <td>${c.permissions}</td><td>${c.findings}</td><td>${c.downloads}</td>
      <td><b>${c.maxRisk}</b></td><td>${c.highRisk ? "⚠ HIGH-RISK" : ""}</td></tr>`).join("")
    || `<tr><td colspan="8">No clusters.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Relationship Graph Report</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  .r-HIGH td:nth-child(7),.r-HIGH b{color:#c0392b}
  .r-CRITICAL b{color:#a11630} .r-MEDIUM b{color:#b9770e} .r-INFO b{color:#2a6fb0}
  ul{margin:6px 0;padding-left:18px}
</style></head><body>
<h1>Relationship Graph Report</h1>
<div class="muted">generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>Size</b><br>${s.nodes} nodes<br>${s.edges} edges</div>
  <div class="card"><b>Risk mix</b><br>
    <span style="color:#a11630">CRIT ${s.byRisk.CRITICAL || 0}</span> ·
    <span style="color:#c0392b">HIGH ${s.byRisk.HIGH || 0}</span> ·
    <span style="color:#b9770e">MED ${s.byRisk.MEDIUM || 0}</span> ·
    <span style="color:#2a6fb0">INFO ${s.byRisk.INFO || 0}</span></div>
  <div class="card"><b>Node types</b><ul>${typeRows}</ul></div>
  <div class="card"><b>Edge types</b><ul>${edgeRows}</ul></div>
</div>
<h2>High-risk clusters</h2>
<table><thead><tr><th>Cluster</th><th>Size</th><th>Trackers</th><th>Perms</th><th>Findings</th><th>Downloads</th><th>Risk</th><th>Flag</th></tr></thead>
<tbody>${clusterRows}</tbody></table>
<h2>Top nodes by score</h2>
<table><thead><tr><th>Type</th><th>Label</th><th>Risk</th><th>Score</th></tr></thead>
<tbody>${topNodes}</tbody></table>
<p class="muted" style="margin-top:24px">Generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* ------------------------ acquisition report HTML ------------------------- */

function renderAcquisitionReport(detail) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const r = detail.run;
  const arts = detail.artifacts || [];
  const records = detail.records || [];

  const artRows = arts.map((a) => `
    <tr class="${a.errors && a.errors.length ? "bad" : "ok"}">
      <td>${esc(a.artifactType)}</td>
      <td>${a.recordCount || 0}</td>
      <td>${a.locked ? "yes" : "no"}</td>
      <td>${a.copied ? "yes" : "no"}</td>
      <td class="hash">${esc((a.sha256 || "").slice(0, 16))}${a.sha256 ? "…" : ""}</td>
      <td>${esc(a.hashScope || "")}</td>
      <td>${esc(a.sourcePath || "")}</td>
      <td>${a.errors && a.errors.length ? esc(a.errors.join("; ")) : "—"}</td>
    </tr>`).join("") || `<tr><td colspan="8">No artifacts.</td></tr>`;

  const byType = detail.summary && detail.summary.byType ? detail.summary.byType : {};
  const typeRows = Object.entries(byType)
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";

  const sample = records.slice(0, 500).map((e) => `
    <tr>
      <td>${fmt(e.ts)}</td><td>${esc(e.type)}</td>
      <td>${esc(e.domain)}</td><td>${esc(e.detail)}</td>
    </tr>`).join("") || `<tr><td colspan="4">No normalized records.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Acquisition — ${esc(r.browser)} / ${esc(r.profile)}</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:220px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  tr.bad td:first-child{color:#c0392b} tr.ok td:first-child{color:#1f9d55}
  .hash{font-family:ui-monospace,Menlo,Consolas,monospace}
  ul{margin:6px 0;padding-left:18px}
  code{font-family:ui-monospace,Menlo,Consolas,monospace;background:#f3f5f8;padding:1px 5px;border-radius:4px}
</style></head><body>
<h1>Browser Acquisition Report</h1>
<div class="muted">${esc(r.runId)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>Source</b><br>${esc(r.browser)} (${esc(r.browserFamily)})<br>
    version ${esc(r.browserVersion || "?")} <span class="muted">(${esc(r.versionSource)})</span><br>
    profile <b>${esc(r.profile)}</b></div>
  <div class="card"><b>Provenance</b><br>host ${esc(r.host)} · ${esc(r.platform)}<br>
    started ${fmt(r.startedAt)}<br>finished ${fmt(r.finishedAt)}</div>
  <div class="card"><b>Profile hash</b><br><code class="hash">${esc(r.profileHash)}</code><br>
    <span class="muted">sha256(browser|profilePath|version)</span></div>
  <div class="card"><b>Records by type</b><ul>${typeRows}</ul></div>
</div>
<h2>Artifacts</h2>
<table><thead><tr><th>Artifact</th><th>Records</th><th>Locked</th><th>Copied</th><th>SHA-256</th><th>Scope</th><th>Source path</th><th>Errors</th></tr></thead>
<tbody>${artRows}</tbody></table>
<h2>Normalized records (first 500)</h2>
<table><thead><tr><th>Time</th><th>Type</th><th>Domain</th><th>Detail</th></tr></thead><tbody>${sample}</tbody></table>
<p class="muted" style="margin-top:24px">Read-only acquisition · credentials never decrypted · generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* -------------------------- timeline report HTML -------------------------- */

function renderTimelineReport(data) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const meta = data.meta || {};
  const entries = data.entries || [];

  const sevClass = (s) => `sev-${esc(s)}`;
  const srcLabel = { live: "Live", finding: "Finding", acquired: "Acquired" };

  const sourceRows = Object.entries(meta.bySource || {})
    .map(([k, v]) => `<li>${esc(srcLabel[k] || k)}: ${v}</li>`).join("") || "<li>none</li>";
  const sevRows = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    .filter((s) => (meta.bySeverity || {})[s])
    .map((s) => `<li>${esc(s)}: ${meta.bySeverity[s]}</li>`).join("") || "<li>none</li>";
  const corrRows = Object.entries(meta.correlationsByType || {})
    .sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";

  const rows = entries.map((e) => `
    <tr class="${sevClass(e.severity)}">
      <td>${fmt(e.ts)}${e.approxTs ? ' <span class="muted">~</span>' : ""}</td>
      <td>${esc(srcLabel[e.sourceType] || e.sourceType)}</td>
      <td>${esc(e.category)}${e.artifactType ? ` <span class="muted">(${esc(e.artifactType)})</span>` : ""}</td>
      <td><b>${esc(e.severity)}</b></td>
      <td>${esc(e.title)}<div class="muted">${esc(e.detail)}</div></td>
      <td>${esc(e.domain)}</td>
      <td>${e.correlationType ? `${esc(e.correlationType)} <span class="muted">${Math.round((e.confidenceScore || 0) * 100)}%</span><br><span class="muted">${(e.relatedTimelineIds || []).length} link(s)</span>` : "—"}</td>
    </tr>`).join("") || `<tr><td colspan="7">No timeline entries matched.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Forensic Timeline — ${entries.length} entries</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085;font-size:12px}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  ul{margin:6px 0;padding-left:18px}
  .sev-CRITICAL td:nth-child(4){color:#a11630}
  .sev-HIGH td:nth-child(4){color:#c0392b}
  .sev-MEDIUM td:nth-child(4){color:#b9770e}
  .sev-LOW td:nth-child(4){color:#2a6fb0}
  .sev-INFO td:nth-child(4){color:#5b7083}
</style></head><body>
<h1>Forensic Timeline</h1>
<div class="muted">${entries.length} of ${data.total || entries.length} entries · built ${fmt(data.builtAt)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>Time range</b><br>${fmt(meta.since)}<br>→ ${fmt(meta.until)}</div>
  <div class="card"><b>By source</b><ul>${sourceRows}</ul></div>
  <div class="card"><b>By severity</b><ul>${sevRows}</ul></div>
  <div class="card"><b>Correlations</b><br>${meta.correlated || 0} correlated entries<br>${meta.correlationEdges || 0} links<ul>${corrRows}</ul></div>
</div>
<table><thead><tr><th>Time</th><th>Source</th><th>Category</th><th>Severity</th><th>Title / detail</th><th>Domain</th><th>Correlation</th></tr></thead>
<tbody>${rows}</tbody></table>
<p class="muted" style="margin-top:24px">Unified forensic timeline · live events, behavioral findings and read-only acquisition records · timestamps are Unix epoch ms (~ = approximate, placed at acquisition time) · generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* ------------------------ extension forensics HTML ------------------------ */

function renderExtensionReport(data) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const ageStr = (ms) => (ms == null ? "—" : `${Math.max(0, Math.round(ms / 86400000))}d`);
  const meta = data.meta || {};
  const profiles = data.profiles || [];
  const findings = data.findings || [];
  const sevClass = (s) => `sev-${esc(s)}`;

  const findingsByExt = {};
  for (const f of findings) (findingsByExt[f.extensionId] = findingsByExt[f.extensionId] || []).push(f);

  const lvlRows = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    .map((s) => `<li>${esc(s)}: ${(meta.byRiskLevel || {})[s] || 0}</li>`).join("");
  const browserRows = Object.entries(meta.byBrowser || {})
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";

  const rows = profiles.map((p) => {
    const ps = p.permissionsSummary || {};
    const flags = [
      ps.allUrls ? "all_urls" : (ps.wildcardHosts ? "wildcard-host" : ""),
      ps.fileAccess ? "file://" : "",
      (ps.dangerous || []).length ? `${ps.dangerous.length} dangerous` : "",
      p.enabledState === "disabled" ? "disabled" : "",
    ].filter(Boolean).join(" · ");
    const exFindings = (findingsByExt[p.extensionId] || []).map((f) =>
      `<div class="${sevClass(f.severity)}"><b>${esc(f.severity)}</b> ${esc(f.reason)} <span class="muted">${esc(f.evidence)}</span></div>`).join("") ||
      `<div class="muted">no risk findings</div>`;
    return `
    <tr class="${sevClass(p.riskLevel)}">
      <td><b>${esc(p.riskLevel)}</b><div class="muted">score ${p.riskScore}</div></td>
      <td>${esc(p.name)}<div class="muted">${esc(p.extensionId)}</div></td>
      <td>${esc(p.browser)}<div class="muted">${esc(p.profile)}</div></td>
      <td>v${esc(p.version)}<div class="muted">mv${esc(p.manifestVersion)}</div></td>
      <td>${esc(p.enabledState)}</td>
      <td>install ${ageStr(p.installAge)}<div class="muted">update ${ageStr(p.updateAge)}</div></td>
      <td>${(ps.api || []).length} api · ${(ps.host || []).length} host<div class="muted">${esc(flags || "—")}</div></td>
      <td>${(p.relatedTimelineIds || []).length} tl · ${(p.relatedFindingIds || []).length} find</td>
    </tr>
    <tr class="ext-sub"><td></td><td colspan="7">${exFindings}</td></tr>`;
  }).join("") || `<tr><td colspan="8">No extensions found in acquisition data.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Extension Forensics — ${profiles.length} extensions</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085;font-size:12px}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  ul{margin:6px 0;padding-left:18px}
  .ext-sub td{background:#fbfcfe;font-size:11px}
  .sev-CRITICAL td:first-child{color:#a11630}
  .sev-HIGH td:first-child{color:#c0392b}
  .sev-MEDIUM td:first-child{color:#b9770e}
  .sev-INFO td:first-child{color:#5b7083}
  .sev-CRITICAL>b{color:#a11630} .sev-HIGH>b{color:#c0392b} .sev-MEDIUM>b{color:#b9770e} .sev-INFO>b{color:#5b7083}
</style></head><body>
<h1>Extension Forensics</h1>
<div class="muted">${profiles.length} extensions · ${findings.length} risk findings · scanned ${fmt(data.scannedAt)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>By risk level</b><ul>${lvlRows}</ul></div>
  <div class="card"><b>State</b><br>${meta.enabled || 0} enabled · ${meta.disabled || 0} disabled<br>${meta.correlated || 0} correlated</div>
  <div class="card"><b>By browser</b><ul>${browserRows}</ul></div>
</div>
<table><thead><tr><th>Risk</th><th>Extension</th><th>Browser</th><th>Version</th><th>State</th><th>Age</th><th>Permissions</th><th>Links</th></tr></thead>
<tbody>${rows}</tbody></table>
<p class="muted" style="margin-top:24px">Derived from read-only acquisition artifacts and the unified timeline · no browser data was reacquired · generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* --------------------------- cache forensics HTML --------------------------- */

function renderCacheReport(data) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const kb = (n) => (n == null ? "—" : (n < 1024 ? `${n} B` : (n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`)));
  const meta = data.meta || {};
  const profiles = data.profiles || [];
  const findings = data.findings || [];
  const sevClass = (s) => `sev-${esc(s)}`;

  const findingsByCache = {};
  for (const f of findings) (findingsByCache[f.cacheId] = findingsByCache[f.cacheId] || []).push(f);

  const lvlRows = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    .map((s) => `<li>${esc(s)}: ${(meta.byRiskLevel || {})[s] || 0}</li>`).join("");
  const typeRows = Object.entries(meta.byType || {})
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";

  const rows = profiles.map((p) => {
    const cf = (findingsByCache[p.cacheId] || []).map((f) =>
      `<div class="${sevClass(f.severity)}"><b>${esc(f.severity)}</b> ${esc(f.reason)} <span class="muted">${esc(f.evidence)}</span></div>`).join("") ||
      `<div class="muted">no risk findings</div>`;
    return `
    <tr class="${sevClass(p.riskLevel)}">
      <td><b>${esc(p.riskLevel)}</b><div class="muted">score ${p.riskScore}</div></td>
      <td>${esc(p.cacheName)}<div class="muted">${esc(p.cacheType)}${p.scope ? " · " + esc(p.scope) : ""}</div></td>
      <td>${esc(p.browser || "—")}<div class="muted">${esc(p.profile || "")}</div></td>
      <td>${p.entryCount}</td>
      <td>${kb(p.totalSize)}</td>
      <td>${p.domainCount}</td>
      <td>${(p.relatedTimelineIds || []).length} tl · ${(p.relatedExtensionIds || []).length} ext · ${(p.relatedFindingIds || []).length} find</td>
    </tr>
    <tr class="ext-sub"><td></td><td colspan="6">${cf}</td></tr>`;
  }).join("") || `<tr><td colspan="7">No cache stores found.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Cache Forensics — ${profiles.length} stores</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085;font-size:12px}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  ul{margin:6px 0;padding-left:18px}
  .ext-sub td{background:#fbfcfe;font-size:11px}
  .sev-CRITICAL td:first-child{color:#a11630}
  .sev-HIGH td:first-child{color:#c0392b}
  .sev-MEDIUM td:first-child{color:#b9770e}
  .sev-INFO td:first-child{color:#5b7083}
  .sev-CRITICAL>b{color:#a11630} .sev-HIGH>b{color:#c0392b} .sev-MEDIUM>b{color:#b9770e} .sev-INFO>b{color:#5b7083}
</style></head><body>
<h1>Cache Forensics</h1>
<div class="muted">${profiles.length} cache stores · ${meta.entryTotal || 0} entries · ${kb(meta.sizeTotal)} · ${findings.length} risk findings · scanned ${fmt(data.scannedAt)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>By risk level</b><ul>${lvlRows}</ul></div>
  <div class="card"><b>By cache type</b><ul>${typeRows}</ul></div>
  <div class="card"><b>Correlation</b><br>${meta.correlated || 0} correlated stores<br>${meta.diskExtracted || 0} disk metadata entries</div>
</div>
<table><thead><tr><th>Risk</th><th>Cache store</th><th>Browser</th><th>Entries</th><th>Size</th><th>Domains</th><th>Links</th></tr></thead>
<tbody>${rows}</tbody></table>
<p class="muted" style="margin-top:24px">Metadata only · cached page content was never extracted · no deleted-entry recovery · no file carving · derived from read-only acquisition artifacts and the unified timeline · generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* ------------------------ evidence integrity HTML ------------------------- */

function renderIntegrityReport(data) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const meta = data.meta || {};
  const records = data.records || [];
  const custody = data.custody || [];
  const stClass = (s) => `st-${esc(s)}`;

  const custodyByRec = {};
  for (const c of custody) (custodyByRec[c.integrityId] = custodyByRec[c.integrityId] || []).push(c);

  const statusRows = ["VALID", "MODIFIED", "MISSING", "UNKNOWN"]
    .map((s) => `<li>${esc(s)}: ${(meta.byStatus || {})[s] || 0}</li>`).join("");
  const typeRows = Object.entries(meta.byType || {})
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";

  const rows = records.map((r) => {
    const chain = (custodyByRec[r.integrityId] || []).sort((a, b) => a.ts - b.ts)
      .map((c) => `<span class="cust">${esc(c.action)} <span class="muted">${fmt(c.ts)} · ${esc(c.actor)}</span></span>`).join("") ||
      `<span class="muted">none</span>`;
    return `
    <tr class="${stClass(r.verificationStatus)}">
      <td><b>${esc(r.verificationStatus)}</b></td>
      <td>${esc(r.evidenceType)}</td>
      <td>${esc(r.label)}<div class="muted">${esc(r.evidenceId)}</div></td>
      <td class="hash">${esc((r.sha256 || "").slice(0, 16))}…</td>
      <td>${fmt(r.verifiedAt)}</td>
      <td>${(r.relatedEvidenceIds || []).length}</td>
    </tr>
    <tr class="ext-sub"><td></td><td colspan="5">${chain}</td></tr>`;
  }).join("") || `<tr><td colspan="6">No evidence registered.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Evidence Integrity — ${records.length} items</title>
<style>
  body{font:14px/1.5 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:28px} .muted{color:#667085;font-size:12px}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:24px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:12px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:7px 9px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  ul{margin:6px 0;padding-left:18px}
  .hash{font-family:ui-monospace,Menlo,Consolas,monospace}
  .ext-sub td{background:#fbfcfe;font-size:11px}
  .cust{display:inline-block;margin-right:14px}
  .st-VALID td:first-child{color:#1a7f47}
  .st-MODIFIED td:first-child{color:#c0392b}
  .st-MISSING td:first-child{color:#b9770e}
  .st-UNKNOWN td:first-child{color:#5b7083}
</style></head><body>
<h1>Evidence Integrity &amp; Chain of Custody</h1>
<div class="muted">${records.length} evidence items · ${custody.length} custody events · last verified ${fmt(meta.lastVerifiedAt)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>By status</b><ul>${statusRows}</ul></div>
  <div class="card"><b>By evidence type</b><ul>${typeRows}</ul></div>
  <div class="card"><b>Custody</b><br>${custody.length} recorded events<br><span class="muted">created · modified · exported · verified</span></div>
</div>
<table><thead><tr><th>Status</th><th>Type</th><th>Evidence</th><th>SHA256</th><th>Verified</th><th>Links</th></tr></thead>
<tbody>${rows}</tbody></table>
<p class="muted" style="margin-top:24px">SHA256 integrity baselines over canonical evidence content · verification recomputes and compares · chain-of-custody is append-only · generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* --------------------- generic forensic report (HTML/PDF) ----------------- */

function renderReportHtml(record) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const sevClass = (s) => `sev-${esc(s)}`;
  const integ = record.integrityStatus || {};

  const renderSection = (s) => {
    const d = s.data || {};
    let body = "";
    if (s.type === "cards") {
      body = `<div class="rcards">` + (d.items || []).map((c) =>
        `<div class="rcard"><div class="rcard-num">${esc(c.value)}</div><div class="rcard-label">${esc(c.label)}</div>${c.hint ? `<div class="rcard-hint">${esc(c.hint)}</div>` : ""}</div>`).join("") + `</div>`;
    } else if (s.type === "keyval") {
      body = `<table class="kv">` + (d.pairs || []).map(([k, v]) =>
        `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("") + `</table>`;
    } else if (s.type === "table") {
      const head = (d.columns || []).map((c) => `<th>${esc(c)}</th>`).join("");
      const rows = (d.rows || []).map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("") ||
        `<tr><td colspan="${(d.columns || []).length || 1}" class="muted">none</td></tr>`;
      body = `<table><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`;
    } else if (s.type === "list") {
      body = (d.items || []).map((it) =>
        `<div class="ritem ${sevClass(it.severity)}"><span class="rsev">${esc(it.severity || "")}</span> <b>${esc(it.title || "")}</b>${it.meta ? ` <span class="muted">${esc(it.meta)}</span>` : ""}${it.detail ? `<div class="muted">${esc(it.detail)}</div>` : ""}</div>`).join("") ||
        `<div class="muted">none</div>`;
    } else if (s.type === "text") {
      body = `<p>${esc(d.body || "")}</p>`;
    }
    return `<section class="rsection"><h2>${esc(s.title)}</h2>${s.note ? `<div class="muted">${esc(s.note)}</div>` : ""}${body}</section>`;
  };

  return `<!doctype html><html><head><meta charset="utf-8">
<title>${esc(record.title)} — ${esc(record.reportId)}</title>
<style>
  body{font:13px/1.55 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 2px;font-size:24px} h2{margin:0 0 8px;font-size:16px}
  .muted{color:#667085;font-size:11px}
  .meta{color:#475467;font-size:12px;margin-bottom:18px}
  .banner{display:flex;gap:18px;flex-wrap:wrap;border:1px solid #e3e8ef;border-radius:10px;padding:14px 18px;margin:14px 0 22px;background:#f8fafc}
  .banner div b{display:block;font-size:11px;color:#667085;text-transform:uppercase;letter-spacing:.5px}
  .rsection{margin:22px 0;page-break-inside:avoid}
  table{border-collapse:collapse;width:100%;font-size:11px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:6px 8px;text-align:left;vertical-align:top}
  th{background:#f7f9fc}
  table.kv{width:auto} table.kv th{background:none;color:#667085;font-weight:600;padding-right:18px}
  .rcards{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px}
  .rcard{border:1px solid #e3e8ef;border-radius:8px;padding:10px 16px;min-width:90px}
  .rcard-num{font-size:20px;font-weight:700} .rcard-label{font-size:10px;color:#667085;text-transform:uppercase;letter-spacing:.5px}
  .rcard-hint{font-size:10px;color:#98a2b3}
  .ritem{padding:6px 0;border-bottom:1px solid #f2f4f7}
  .rsev{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:9px;font-weight:700;padding:1px 6px;border-radius:3px;background:#eef1f5}
  .sev-CRITICAL .rsev{color:#a11630} .sev-HIGH .rsev{color:#c0392b} .sev-MEDIUM .rsev{color:#b9770e} .sev-LOW .rsev{color:#2a6fb0} .sev-INFO .rsev{color:#5b7083}
  .integ-VERIFIED{color:#1a7f47} .integ-COMPROMISED{color:#c0392b} .integ-INCOMPLETE{color:#b9770e} .integ-UNVERIFIED{color:#5b7083}
  footer{margin-top:30px;border-top:1px solid #e3e8ef;padding-top:12px}
</style></head><body>
<h1>${esc(record.title)}</h1>
<div class="meta">${esc(record.reportTypeLabel || record.reportType)} · ${esc(record.reportId)}</div>
<div class="banner">
  <div><b>Created</b>${fmt(record.createdAt)}</div>
  <div><b>Generated by</b>${esc(record.generatedBy)}</div>
  <div><b>Scope</b>${esc(record.reportScope)}</div>
  <div><b>Evidence count</b>${esc(record.evidenceCount)}</div>
  <div><b>Integrity</b><span class="integ-${esc(integ.overall || "UNVERIFIED")}">${esc(integ.overall || "UNVERIFIED")}</span> (${esc(integ.valid || 0)} valid · ${esc(integ.modified || 0)} modified · ${esc(integ.missing || 0)} missing)</div>
</div>
${(record.sections || []).map(renderSection).join("")}
<footer class="muted">${esc(record.summary || "")}<br>Generated locally by Browser Forensics. SHA256 integrity status sourced from the Evidence Integrity Engine. No data left this machine.</footer>
</body></html>`;
}

// Render HTML to a real PDF using Chromium's print engine via an offscreen
// window (no third-party PDF dependency; this is not HTML renamed to .pdf).
async function htmlToPdf(html) {
  const w = new BrowserWindow({
    show: false,
    webPreferences: { offscreen: true, sandbox: true, javascript: false },
  });
  try {
    await w.loadURL("data:text/html;charset=utf-8," + encodeURIComponent(html));
    const pdf = await w.webContents.printToPDF({
      printBackground: true,
      pageSize: "A4",
      margins: { top: 0.4, bottom: 0.4, left: 0.4, right: 0.4 },
    });
    return pdf;
  } finally {
    if (!w.isDestroyed()) w.destroy();
  }
}

/* ------------------------- threat hunting report HTML --------------------- */

function renderHuntReport(data) {
  const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
  const fmt = (ts) => (ts ? new Date(ts).toLocaleString() : "—");
  const pct = (c) => `${Math.round((c || 0) * 100)}%`;
  const meta = data.meta || {};
  const findings = data.findings || [];
  const chains = data.chains || [];
  const sevClass = (s) => `sev-${esc(s)}`;
  const integ = meta.integrity || {};

  const sevRows = ["CRITICAL", "HIGH", "MEDIUM", "INFO"]
    .map((s) => `<li>${esc(s)}: ${(meta.bySeverity || {})[s] || 0}</li>`).join("");
  const huntRows = Object.entries(meta.byHunt || {})
    .map(([k, v]) => `<li>${esc(k)}: ${v}</li>`).join("") || "<li>none</li>";

  const chainRows = chains.map((c) => `
    <tr class="${sevClass(c.severity)}">
      <td><b>${esc(c.severity)}</b><div class="muted">${pct(c.confidenceScore)}</div></td>
      <td>${esc(c.title)}<div class="muted">${(c.huntTypes || []).join(" → ")}</div></td>
      <td>${esc(c.domain)}</td>
      <td>${fmt(c.startTs)}<div class="muted">${fmt(c.endTs)}</div></td>
      <td>${(c.indicators || []).length} ind · ${(c.relatedTimelineIds || []).length} tl · ${(c.relatedExtensions || []).length} ext</td>
    </tr>`).join("") || `<tr><td colspan="5">No multi-stage threat chains.</td></tr>`;

  const findingRows = findings.map((f) => `
    <tr class="${sevClass(f.severity)}">
      <td><b>${esc(f.severity)}</b><div class="muted">${pct(f.confidenceScore)}</div></td>
      <td>${esc(f.huntType)}</td>
      <td>${esc(f.title)}<div class="muted">${esc(f.evidence)}</div></td>
      <td>${esc((f.relatedDomains || []).slice(0, 3).join(", "))}</td>
      <td class="muted">${fmt(f.ts)}</td>
    </tr>
    <tr class="ext-sub"><td></td><td colspan="4"><b>Recommendation:</b> ${esc(f.recommendation)}</td></tr>`).join("") ||
    `<tr><td colspan="5">No threat findings.</td></tr>`;

  return `<!doctype html><html><head><meta charset="utf-8">
<title>Threat Hunting — ${findings.length} findings · ${chains.length} chains</title>
<style>
  body{font:13px/1.55 system-ui,Segoe UI,Arial;color:#1a1f26;margin:40px;background:#fff}
  h1{margin:0 0 4px} h2{margin-top:26px;font-size:16px} .muted{color:#667085;font-size:11px}
  .grid{display:flex;gap:32px;flex-wrap:wrap;margin:20px 0}
  .card{border:1px solid #e3e8ef;border-radius:10px;padding:16px;min-width:200px}
  table{border-collapse:collapse;width:100%;font-size:11px;margin-top:8px}
  th,td{border-bottom:1px solid #eef1f5;padding:6px 8px;text-align:left;vertical-align:top}
  th{background:#f7f9fc} ul{margin:6px 0;padding-left:18px}
  .ext-sub td{background:#fbfcfe}
  .sev-CRITICAL td:first-child{color:#a11630} .sev-HIGH td:first-child{color:#c0392b}
  .sev-MEDIUM td:first-child{color:#b9770e} .sev-INFO td:first-child{color:#5b7083}
  .integ-VERIFIED{color:#1a7f47}.integ-COMPROMISED{color:#c0392b}.integ-INCOMPLETE{color:#b9770e}.integ-UNVERIFIED{color:#5b7083}
</style></head><body>
<h1>Advanced Threat Hunting</h1>
<div class="muted">${findings.length} threat findings · ${chains.length} multi-stage chains · max severity ${esc(meta.maxSeverity || "INFO")} · scanned ${fmt(data.scannedAt)} · generated ${new Date().toLocaleString()}</div>
<div class="grid">
  <div class="card"><b>By severity</b><ul>${sevRows}</ul></div>
  <div class="card"><b>By hunt</b><ul>${huntRows}</ul></div>
  <div class="card"><b>Evidence integrity</b><br><span class="integ-${esc(integ.overall || "UNVERIFIED")}">${esc(integ.overall || "UNVERIFIED")}</span><br><span class="muted">${esc(integ.valid || 0)} valid · ${esc(integ.modified || 0)} modified · ${esc(integ.missing || 0)} missing</span></div>
</div>
<h2>Multi-stage threat chains</h2>
<table><thead><tr><th>Severity</th><th>Chain</th><th>Domain</th><th>Window</th><th>Correlation</th></tr></thead><tbody>${chainRows}</tbody></table>
<h2>Threat findings</h2>
<table><thead><tr><th>Severity</th><th>Hunt</th><th>Finding</th><th>Domains</th><th>When</th></tr></thead><tbody>${findingRows}</tbody></table>
<p class="muted" style="margin-top:24px">Proactive metadata-only threat hunting across live events, timeline, extensions, cache, findings, sessions and graph relationships · integrity status sourced from the Evidence Integrity Engine · generated locally by Browser Forensics. No data left this machine.</p>
</body></html>`;
}

/* -------------------------------- window ---------------------------------- */

function createWindow() {
  win = new BrowserWindow({
    width: 1400,
    height: 900,
    backgroundColor: "#0e1116",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, "index.html"));
}

app.whenReady().then(() => {
  store = createStore(dataDir);
  importLegacyLog();
  try { store.prune(); } catch (e) { console.warn("[retention] prune failed:", e.message); }
  try { store.detectAll(); } catch (e) { console.warn("[detect] initial scan failed:", e.message); }
  try { if (store.graphStats().nodes === 0) store.graphRebuild(); } catch (e) { console.warn("[graph] initial build failed:", e.message); }
  // Apply retention policy hourly: INFO 30d, MEDIUM 90d, HIGH forever, 100k cap.
  setInterval(() => {
    try { store.prune(); } catch (e) { console.warn("[retention] prune failed:", e.message); }
  }, 3600 * 1000);
  registerIpc();
  server.listen(9000, "127.0.0.1", () => {
    console.log(`Local listener on http://localhost:9000  (store: ${store.backend})`);
  });
  createWindow();
  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  try { if (store && store.graphFlush) store.graphFlush(); } catch { /* ignore */ }
  if (process.platform !== "darwin") app.quit();
});
