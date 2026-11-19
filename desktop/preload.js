// preload.js
// Secure bridge between the dashboard (renderer) and the main process.
// The renderer gets a small, explicit API — no direct Node access.

const { contextBridge, ipcRenderer } = require("electron");

contextBridge.exposeInMainWorld("api", {
  // Live stream of new events.
  onEvent: (cb) => ipcRenderer.on("log-event", (_e, data) => cb(data)),

  // Queries (all return Promises).
  recent: (limit = 100) => ipcRenderer.invoke("q:recent", limit),
  search: (filters = {}) => ipcRenderer.invoke("q:search", filters),
  stats: () => ipcRenderer.invoke("q:stats"),
  cookies: (limit = 50) => ipcRenderer.invoke("q:cookies", limit),
  domains: (limit = 50) => ipcRenderer.invoke("q:domains", limit),

  // Cases / evidence engine.
  cases: () => ipcRenderer.invoke("q:cases"),
  case: (id) => ipcRenderer.invoke("q:case", id),
  createCase: (spec) => ipcRenderer.invoke("case:create", spec),
  exportCase: (id) => ipcRenderer.invoke("case:export", id),

  // Investigation engine.
  investigate: (domain) => ipcRenderer.invoke("q:investigate", domain),
  exportInvestigation: (domain) => ipcRenderer.invoke("investigation:export", domain),

  // Session reconstruction engine.
  sessions: () => ipcRenderer.invoke("q:sessions"),
  session: (id) => ipcRenderer.invoke("q:session", id),
  exportSession: (id) => ipcRenderer.invoke("session:export", id),

  // IOC & behavioral detection engine.
  findings: (filter = {}) => ipcRenderer.invoke("q:findings", filter),
  finding: (id) => ipcRenderer.invoke("q:finding", id),
  findingsMeta: () => ipcRenderer.invoke("q:findingsMeta"),
  runDetection: () => ipcRenderer.invoke("detect:run"),
  exportFindings: (opts) => ipcRenderer.invoke("findings:export", opts),
  iocList: () => ipcRenderer.invoke("ioc:list"),
  iocAdd: (category, value) => ipcRenderer.invoke("ioc:add", { category, value }),
  onFindings: (cb) => ipcRenderer.on("findings-updated", (_e, meta) => cb(meta)),

  // Relationship graph & evidence correlation.
  graphView: (opts = {}) => ipcRenderer.invoke("graph:view", opts),
  graphNeighborhood: (id, depth = 2, cap = 250) => ipcRenderer.invoke("graph:neighborhood", { id, depth, cap }),
  graphPaths: (id, opts = {}) => ipcRenderer.invoke("graph:paths", { id, opts }),
  graphPath: (from, to) => ipcRenderer.invoke("graph:path", { from, to }),
  graphClusters: (opts = {}) => ipcRenderer.invoke("graph:clusters", opts),
  graphStats: () => ipcRenderer.invoke("graph:stats"),
  graphRebuild: () => ipcRenderer.invoke("graph:rebuild"),
  exportGraph: (format) => ipcRenderer.invoke("graph:export", { format }),
  onGraph: (cb) => ipcRenderer.on("graph-updated", (_e, stats) => cb(stats)),

  clearData: () => ipcRenderer.invoke("data:clear"),
  clearScope: (scopes) => ipcRenderer.invoke("data:clearScope", scopes),
  pruneData: () => ipcRenderer.invoke("data:prune"),
  meta: () => ipcRenderer.invoke("meta"),

  // Browser acquisition engine (read-only forensic captures).
  acqBrowsers: () => ipcRenderer.invoke("acq:browsers"),
  acqRun: (spec) => ipcRenderer.invoke("acq:run", spec),
  acqList: () => ipcRenderer.invoke("acq:list"),
  acqDetail: (id) => ipcRenderer.invoke("acq:detail", id),
  acqRecords: (id, filter = {}) => ipcRenderer.invoke("acq:records", { id, filter }),
  acqStats: () => ipcRenderer.invoke("acq:stats"),
  acqRemove: (id) => ipcRenderer.invoke("acq:remove", id),
  exportAcquisition: (id, format) => ipcRenderer.invoke("acq:export", { id, format }),
  onAcq: (cb) => ipcRenderer.on("acq-updated", (_e, stats) => cb(stats)),

  // Timeline Reconstruction Engine (unified forensic timeline).
  timelineBuild: () => ipcRenderer.invoke("timeline:build"),
  timelineList: (filter = {}) => ipcRenderer.invoke("timeline:list", filter),
  timelineDetail: (id) => ipcRenderer.invoke("timeline:detail", id),
  exportTimeline: (format, filter) => ipcRenderer.invoke("timeline:export", { format, filter }),
  onTimeline: (cb) => ipcRenderer.on("timeline-updated", (_e, meta) => cb(meta)),

  // Extension Forensics Engine.
  extScan: () => ipcRenderer.invoke("ext:scan"),
  extList: (filter = {}) => ipcRenderer.invoke("ext:list", filter),
  extDetail: (extensionId, key) => ipcRenderer.invoke("ext:detail", { extensionId, key }),
  extFindings: (filter = {}) => ipcRenderer.invoke("ext:findings", filter),
  exportExtensions: (format, filter) => ipcRenderer.invoke("ext:export", { format, filter }),
  onExtensions: (cb) => ipcRenderer.on("extensions-updated", (_e, meta) => cb(meta)),

  // Cache Forensics Engine.
  cacheScan: () => ipcRenderer.invoke("cache:scan"),
  cacheList: (filter = {}) => ipcRenderer.invoke("cache:list", filter),
  cacheDetail: (id) => ipcRenderer.invoke("cache:detail", id),
  cacheFindings: (filter = {}) => ipcRenderer.invoke("cache:findings", filter),
  exportCache: (format, filter) => ipcRenderer.invoke("cache:export", { format, filter }),
  onCache: (cb) => ipcRenderer.on("cache-updated", (_e, meta) => cb(meta)),

  // Evidence Integrity Engine.
  integrityList: (filter = {}) => ipcRenderer.invoke("integrity:list", filter),
  integrityDetail: (id) => ipcRenderer.invoke("integrity:detail", id),
  integrityVerify: (id) => ipcRenderer.invoke("integrity:verify", id),
  integrityVerifyAll: () => ipcRenderer.invoke("integrity:verifyAll"),
  exportIntegrity: (format, filter) => ipcRenderer.invoke("integrity:export", { format, filter }),
  onIntegrity: (cb) => ipcRenderer.on("integrity-updated", (_e, meta) => cb(meta)),

  // Reporting Engine.
  reportList: (filter = {}) => ipcRenderer.invoke("report:list", filter),
  reportDetail: (id) => ipcRenderer.invoke("report:detail", id),
  reportCreate: (options = {}) => ipcRenderer.invoke("report:create", options),
  exportReport: (reportId, format) => ipcRenderer.invoke("report:export", { reportId, format }),
  onReports: (cb) => ipcRenderer.on("reports-updated", (_e, meta) => cb(meta)),

  // Advanced Threat Hunting Engine.
  huntScan: () => ipcRenderer.invoke("hunt:scan"),
  huntList: (filter = {}) => ipcRenderer.invoke("hunt:list", filter),
  huntDetail: (id) => ipcRenderer.invoke("hunt:detail", id),
  huntChains: (filter = {}) => ipcRenderer.invoke("hunt:chains", filter),
  exportHunt: (format, filter) => ipcRenderer.invoke("hunt:export", { format, filter }),
  onHunt: (cb) => ipcRenderer.on("hunting-updated", (_e, meta) => cb(meta)),
});
