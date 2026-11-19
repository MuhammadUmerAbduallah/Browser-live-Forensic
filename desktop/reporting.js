// reporting.js
// Reporting Engine.
//
// Generates professional forensic investigation reports from every evidence
// source the platform produces. It is a pure aggregator/formatter: db.js injects
// a bounded, read-only snapshot of all engines (acquisitions, timeline,
// extensions, cache, investigation findings, integrity, sessions, graph) and
// this engine assembles immutable, structured report records. It never
// recomputes integrity hashes or rebuilds the timeline — it consumes the
// existing engines' output, so there is no duplicated logic and no schema
// changes.
//
// Reports are stored as structured "sections" (cards / table / list / keyval /
// text) so the same record renders identically to HTML, JSON and PDF and can be
// consumed later by Threat-Hunting reports, external forensic exports and
// court-ready evidence packages. Persisted to a single JSON sidecar
// (reports.json), mirroring the rest of the project's storage pattern.
//
// Every report record contains: reportId, reportType, createdAt, generatedBy,
// reportScope, evidenceCount, integrityStatus (+ title, summary, sections and
// additive metadata).

const fs = require("fs");
const path = require("path");
const os = require("os");

const SIDECAR = "reports.json";
const FORMAT_VERSION = 1;
const MAX_TABLE_ROWS = 500;       // bound stored table size per section
const MAX_REPORTS = 500;

const REPORT_TYPES = [
  "investigation", "timeline", "acquisition", "extension", "cache",
  "integrity", "findings", "executive", "full-case",
];
const REPORT_LABELS = {
  investigation: "Investigation Report",
  timeline: "Timeline Report",
  acquisition: "Acquisition Report",
  extension: "Extension Report",
  cache: "Cache Report",
  integrity: "Integrity Report",
  findings: "Findings Report",
  executive: "Executive Summary Report",
  "full-case": "Full Case Report",
};

const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_RANK = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
function sevRank(s) { return SEV_RANK[s] != null ? SEV_RANK[s] : 0; }

function defaultActor() {
  try { const u = os.userInfo(); if (u && u.username) return u.username; } catch { /* ignore */ }
  return process.env.USER || process.env.USERNAME || "system";
}
function nowId() {
  return "rpt_" + Date.now().toString(36) + "_" + Math.random().toString(36).slice(2, 8);
}
function fmtScope(scope) {
  if (!scope || !scope.type || scope.type === "all") {
    const parts = [];
    if (scope && scope.since) parts.push("from " + new Date(scope.since).toISOString().slice(0, 10));
    if (scope && scope.until) parts.push("to " + new Date(scope.until).toISOString().slice(0, 10));
    return parts.length ? "all evidence · " + parts.join(" ") : "all evidence";
  }
  return `${scope.type}: ${scope.value || ""}`.trim();
}
function clip(rows) { return rows.length > MAX_TABLE_ROWS ? rows.slice(0, MAX_TABLE_ROWS) : rows; }

/* ------------------------- cross-source summaries ----------------------- */

function integritySummary(sources) {
  const st = (sources.integrity && sources.integrity.stats) || {};
  const by = st.byStatus || {};
  const total = st.total || 0;
  const valid = by.VALID || 0, modified = by.MODIFIED || 0,
    missing = by.MISSING || 0, unknown = by.UNKNOWN || 0;
  let overall = "UNVERIFIED";
  if (total > 0) {
    if (modified > 0 || missing > 0) overall = "COMPROMISED";
    else if (unknown > 0) overall = "INCOMPLETE";
    else overall = "VERIFIED";
  }
  return {
    total, valid, modified, missing, unknown, overall,
    custodyCount: st.custodyCount || 0,
    lastVerifiedAt: st.lastVerifiedAt || 0,
  };
}

function timelineSummary(sources) {
  const st = (sources.timeline && sources.timeline.stats) || {};
  return {
    built: !!st.built,
    total: st.total || (sources.timeline && sources.timeline.total) || 0,
    since: st.since || null, until: st.until || null,
    bySource: st.bySource || {}, bySeverity: st.bySeverity || {},
    byCategory: st.byCategory || {},
    correlated: st.correlated || 0, correlationEdges: st.correlationEdges || 0,
  };
}

function riskSummary(sources) {
  const agg = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  const fm = (sources.findings && sources.findings.meta && sources.findings.meta.bySeverity) || {};
  for (const k of Object.keys(fm)) agg[k] = (agg[k] || 0) + fm[k];
  const ex = (sources.extensions && sources.extensions.stats && sources.extensions.stats.bySeverity) || {};
  for (const k of Object.keys(ex)) agg[k] = (agg[k] || 0) + ex[k];
  const ca = (sources.cache && sources.cache.stats && sources.cache.stats.bySeverity) || {};
  for (const k of Object.keys(ca)) agg[k] = (agg[k] || 0) + ca[k];
  return agg;
}

function evidenceCounts(sources) {
  const acqRuns = (sources.acquisitions && sources.acquisitions.list && sources.acquisitions.list.length) || 0;
  let artifacts = 0;
  for (const r of (sources.acquisitions && sources.acquisitions.runs) || []) artifacts += (r.artifacts || []).length;
  return {
    acquisitions: acqRuns,
    artifacts,
    timeline: (sources.timeline && (sources.timeline.total || (sources.timeline.sample || []).length)) || 0,
    extensionFindings: (sources.extensions && sources.extensions.findings && sources.extensions.findings.length) || 0,
    cacheFindings: (sources.cache && sources.cache.findings && sources.cache.findings.length) || 0,
    investigationFindings: (sources.findings && sources.findings.meta && sources.findings.meta.total) || 0,
    sessions: (sources.sessions && sources.sessions.count) || 0,
    integrityRecords: (sources.integrity && sources.integrity.stats && sources.integrity.stats.total) || 0,
  };
}

function highLevelFindings(sources, limit = 15) {
  const items = [];
  for (const f of (sources.findings && sources.findings.list) || []) {
    items.push({ severity: f.severity, title: f.title || f.rule, detail: f.description || "", source: "investigation", domain: (f.affectedDomains || [])[0] || "" });
  }
  for (const f of (sources.extensions && sources.extensions.findings) || []) {
    items.push({ severity: f.severity, title: `Extension: ${f.reason}`, detail: f.evidence || "", source: "extension", domain: "" });
  }
  for (const f of (sources.cache && sources.cache.findings) || []) {
    items.push({ severity: f.severity, title: `Cache: ${f.reason}`, detail: f.evidence || "", source: "cache", domain: "" });
  }
  items.sort((a, b) => sevRank(b.severity) - sevRank(a.severity));
  return items.slice(0, limit);
}

function topDomains(sources, limit = 20) {
  const counts = new Map();
  const bump = (d, n) => { if (d) counts.set(d, (counts.get(d) || 0) + (n || 1)); };
  for (const e of (sources.timeline && sources.timeline.sample) || []) bump(e.domain, 1);
  for (const p of (sources.cache && sources.cache.profiles) || []) for (const d of (p.domainSample || [])) bump(d, 1);
  for (const p of (sources.extensions && sources.extensions.profiles) || []) {
    const ds = (p.permissionsSummary && p.permissionsSummary.domains) || [];
    for (const d of ds) bump(d, 1);
  }
  return [...counts.entries()].sort((a, b) => b[1] - a[1]).slice(0, limit);
}

/* ----------------------------- scope helpers ---------------------------- */

function inScopeDomain(scope, domain) {
  if (!scope || scope.type !== "domain" || !scope.value) return true;
  return (domain || "").toLowerCase().includes(String(scope.value).toLowerCase());
}
function inScopeBrowser(scope, browser) {
  if (!scope || scope.type !== "browser" || !scope.value) return true;
  return (browser || "") === scope.value;
}
function inScopeTime(scope, ts) {
  if (!scope) return true;
  if (scope.since && ts < scope.since) return false;
  if (scope.until && ts > scope.until) return false;
  return true;
}

/* ----------------------------- section helpers -------------------------- */

const S = {
  cards: (id, title, items, note) => ({ id, type: "cards", title, data: { items }, note }),
  keyval: (id, title, pairs, note) => ({ id, type: "keyval", title, data: { pairs }, note }),
  table: (id, title, columns, rows, note) => ({ id, type: "table", title, data: { columns, rows: clip(rows) }, note: note || (rows.length > MAX_TABLE_ROWS ? `showing ${MAX_TABLE_ROWS} of ${rows.length}` : "") }),
  list: (id, title, items, note) => ({ id, type: "list", title, data: { items: clip(items) }, note }),
  text: (id, title, body) => ({ id, type: "text", title, data: { body } }),
};

function integritySection(sources) {
  const i = integritySummary(sources);
  return S.cards("integrity", "Integrity status", [
    { label: "overall", value: i.overall, hint: `${i.total} evidence items` },
    { label: "valid", value: i.valid },
    { label: "modified", value: i.modified },
    { label: "missing", value: i.missing },
    { label: "unknown", value: i.unknown },
    { label: "custody events", value: i.custodyCount },
  ]);
}

function timelineSummarySection(sources) {
  const t = timelineSummary(sources);
  const range = (t.since && t.until)
    ? `${new Date(t.since).toLocaleString()} → ${new Date(t.until).toLocaleString()}` : "—";
  return S.keyval("timeline-summary", "Timeline summary", [
    ["entries", String(t.total)],
    ["time range", range],
    ["correlated entries", String(t.correlated)],
    ["correlation links", String(t.correlationEdges)],
    ["by source", Object.entries(t.bySource).map(([k, v]) => `${k}:${v}`).join("  ") || "—"],
  ]);
}

function riskSummarySection(sources) {
  const r = riskSummary(sources);
  return S.cards("risk", "Risk summary", SEVERITY_ORDER.map((s) => ({ label: s.toLowerCase(), value: r[s] || 0 })));
}

function evidenceSummarySection(sources) {
  const c = evidenceCounts(sources);
  return S.cards("evidence", "Evidence summary", [
    { label: "acquisitions", value: c.acquisitions },
    { label: "artifacts", value: c.artifacts },
    { label: "timeline entries", value: c.timeline },
    { label: "extension findings", value: c.extensionFindings },
    { label: "cache findings", value: c.cacheFindings },
    { label: "investigation findings", value: c.investigationFindings },
    { label: "sessions", value: c.sessions },
  ]);
}

/* ----------------------------- report builders -------------------------- */

function buildExecutive(sources, scope) {
  const hi = highLevelFindings(sources, 15);
  return {
    title: "Executive Summary",
    sections: [
      evidenceSummarySection(sources),
      riskSummarySection(sources),
      integritySection(sources),
      timelineSummarySection(sources),
      S.list("high-level", "High-level findings", hi.map((f) => ({
        severity: f.severity, title: f.title, detail: f.detail, meta: f.source + (f.domain ? " · " + f.domain : ""),
      }))),
    ],
  };
}

function buildInvestigation(sources, scope) {
  const findings = ((sources.findings && sources.findings.list) || [])
    .filter((f) => (f.affectedDomains || []).some((d) => inScopeDomain(scope, d)) || !scope || scope.type !== "domain");
  const risky = highLevelFindings(sources, 20).filter((f) => sevRank(f.severity) >= sevRank("MEDIUM"));
  const domRows = topDomains(sources, 25).filter(([d]) => inScopeDomain(scope, d)).map(([d, n]) => [d, String(n)]);
  return {
    title: "Investigation Report",
    sections: [
      evidenceSummarySection(sources),
      S.table("domains", "Domains investigated", ["Domain", "Evidence references"], domRows),
      timelineSummarySection(sources),
      S.list("related-findings", "Related findings", findings.slice(0, 100).map((f) => ({
        severity: f.severity, title: f.title || f.rule, detail: f.description || "",
        meta: (f.affectedDomains || []).slice(0, 3).join(", "),
      }))),
      S.list("risk-indicators", "Risk indicators", risky.map((f) => ({
        severity: f.severity, title: f.title, detail: f.detail, meta: f.source,
      }))),
      integritySection(sources),
    ],
  };
}

function buildTimeline(sources, scope) {
  const entries = ((sources.timeline && sources.timeline.sample) || [])
    .filter((e) => inScopeDomain(scope, e.domain) && inScopeTime(scope, e.ts))
    .sort((a, b) => a.ts - b.ts);
  const correlated = entries.filter((e) => (e.relatedTimelineIds || []).length > 0);
  const rows = entries.map((e) => [
    e.ts ? new Date(e.ts).toLocaleString() : "—", e.sourceType, e.category,
    e.severity, e.domain || "—", (e.title || "").slice(0, 80),
  ]);
  const corrRows = correlated.map((e) => [
    e.ts ? new Date(e.ts).toLocaleString() : "—", e.category,
    e.correlationType || "—", String((e.relatedTimelineIds || []).length), e.domain || "—",
  ]);
  return {
    title: "Timeline Report",
    sections: [
      timelineSummarySection(sources),
      S.table("chronological", "Chronological evidence",
        ["Time", "Source", "Category", "Severity", "Domain", "Title"], rows),
      S.table("correlated", "Correlated events",
        ["Time", "Category", "Correlation", "Links", "Domain"], corrRows),
      integritySection(sources),
    ],
  };
}

function buildAcquisition(sources, scope) {
  const runs = ((sources.acquisitions && sources.acquisitions.runs) || [])
    .filter((r) => inScopeBrowser(scope, r.run && r.run.browser));
  const runRows = runs.map((r) => {
    const run = r.run || {}; const s = r.summary || {};
    return [run.browser || "—", run.profile || "—", run.host || "—",
      run.acquiredAt ? new Date(run.acquiredAt).toLocaleString() : "—",
      String(s.artifactCount || (r.artifacts || []).length), String(s.recordCount || 0)];
  });
  const artRows = [];
  for (const r of runs) {
    for (const a of (r.artifacts || [])) {
      artRows.push([(r.run && r.run.browser) || "—", a.artifactType,
        String(a.recordCount || 0), (a.sha256 || a.dirSha || "").slice(0, 16) || "—",
        (a.errors && a.errors.length) ? "errors" : "ok"]);
    }
  }
  return {
    title: "Acquisition Report",
    sections: [
      S.table("runs", "Acquisition runs",
        ["Browser", "Profile", "Host", "Acquired", "Artifacts", "Records"], runRows),
      S.table("artifacts", "Acquired artifacts",
        ["Browser", "Artifact", "Records", "SHA256", "Status"], artRows),
      integritySection(sources),
    ],
  };
}

function buildExtension(sources, scope) {
  const profiles = ((sources.extensions && sources.extensions.profiles) || [])
    .filter((p) => inScopeBrowser(scope, p.browser));
  const st = (sources.extensions && sources.extensions.stats) || {};
  const lvl = st.byRiskLevel || {};
  const profRows = profiles.map((p) => [
    p.riskLevel, p.name, p.browser || "—", p.version || "?",
    String((p.permissionsSummary && (p.permissionsSummary.api || []).length) || 0) + " api / " +
    String((p.permissionsSummary && (p.permissionsSummary.host || []).length) || 0) + " host",
    String((p.relatedTimelineIds || []).length),
  ]);
  const findings = (sources.extensions && sources.extensions.findings) || [];
  return {
    title: "Extension Report",
    sections: [
      S.cards("ext-risk", "Risk analysis", SEVERITY_ORDER.filter((s) => lvl[s]).map((s) => ({ label: s.toLowerCase(), value: lvl[s] }))),
      S.table("ext-perms", "Extensions & permissions",
        ["Risk", "Extension", "Browser", "Version", "Permissions", "Timeline links"], profRows),
      S.list("ext-findings", "Findings summary", findings.slice(0, 150).map((f) => ({
        severity: f.severity, title: f.reason, detail: f.evidence, meta: f.extensionId,
      }))),
      integritySection(sources),
    ],
  };
}

function buildCache(sources, scope) {
  const profiles = (sources.cache && sources.cache.profiles) || [];
  const findings = (sources.cache && sources.cache.findings) || [];
  const suspicious = findings.filter((f) => sevRank(f.severity) >= sevRank("HIGH"));
  const swProfiles = profiles.filter((p) => p.cacheType === "serviceworker");
  const domCounts = new Map();
  for (const p of profiles) for (const d of (p.domainSample || [])) domCounts.set(d, (domCounts.get(d) || 0) + 1);
  const domRows = [...domCounts.entries()].filter(([d]) => inScopeDomain(scope, d))
    .sort((a, b) => b[1] - a[1]).map(([d, n]) => [d, String(n)]);
  return {
    title: "Cache Report",
    sections: [
      S.list("cache-findings", "Cache findings", findings.slice(0, 150).map((f) => ({
        severity: f.severity, title: f.reason, detail: f.evidence, meta: f.cacheId,
      }))),
      S.list("cache-suspicious", "Suspicious artifacts", suspicious.slice(0, 100).map((f) => ({
        severity: f.severity, title: f.reason, detail: f.evidence, meta: "",
      }))),
      S.table("cache-domains", "Related domains", ["Domain", "Cache stores"], domRows),
      S.table("cache-sw", "Related service workers",
        ["Cache", "Scope", "Browser", "Entries"],
        swProfiles.map((p) => [p.cacheName, p.scope || "—", p.browser || "—", String(p.entryCount || 0)])),
      integritySection(sources),
    ],
  };
}

function buildIntegrity(sources, scope) {
  const records = (sources.integrity && sources.integrity.records) || [];
  const custody = (sources.integrity && sources.integrity.custody) || [];
  const i = integritySummary(sources);
  const modified = records.filter((r) => r.verificationStatus === "MODIFIED");
  const missing = records.filter((r) => r.verificationStatus === "MISSING");
  return {
    title: "Integrity Report",
    sections: [
      S.cards("verif", "Verification status", [
        { label: "overall", value: i.overall, hint: `${i.total} items` },
        { label: "valid", value: i.valid }, { label: "modified", value: i.modified },
        { label: "missing", value: i.missing }, { label: "unknown", value: i.unknown },
      ]),
      S.table("modified", "Modified evidence",
        ["Type", "Evidence", "Baseline SHA256", "Verified"],
        modified.map((r) => [r.evidenceType, r.label || r.evidenceId, (r.sha256 || "").slice(0, 16), r.verifiedAt ? new Date(r.verifiedAt).toLocaleString() : "—"])),
      S.table("missing", "Missing evidence",
        ["Type", "Evidence", "Registered", "Verified"],
        missing.map((r) => [r.evidenceType, r.label || r.evidenceId, r.createdAt ? new Date(r.createdAt).toLocaleString() : "—", r.verifiedAt ? new Date(r.verifiedAt).toLocaleString() : "—"])),
      S.table("custody", "Chain of custody",
        ["Action", "Evidence", "When", "Actor", "Hash"],
        custody.slice(0, MAX_TABLE_ROWS).map((c) => [c.action, c.evidenceId, new Date(c.ts).toLocaleString(), c.actor, (c.hash || "").slice(0, 12)])),
    ],
  };
}

function buildFindings(sources, scope) {
  const list = ((sources.findings && sources.findings.list) || [])
    .filter((f) => !scope || scope.type !== "domain" || (f.affectedDomains || []).some((d) => inScopeDomain(scope, d)))
    .sort((a, b) => sevRank(b.severity) - sevRank(a.severity) || (b.lastSeen || 0) - (a.lastSeen || 0));
  const meta = (sources.findings && sources.findings.meta) || {};
  const byRule = new Map();
  for (const f of list) byRule.set(f.rule, (byRule.get(f.rule) || 0) + 1);
  return {
    title: "Findings Report",
    sections: [
      S.cards("sev", "Findings by severity", SEVERITY_ORDER.map((s) => ({ label: s.toLowerCase(), value: (meta.bySeverity || {})[s] || 0 }))),
      S.list("all-findings", "All findings", list.slice(0, 300).map((f) => ({
        severity: f.severity, title: f.title || f.rule, detail: f.description || "",
        meta: (f.affectedDomains || []).slice(0, 3).join(", "),
      }))),
      S.table("by-rule", "Findings by rule", ["Rule", "Count"],
        [...byRule.entries()].sort((a, b) => b[1] - a[1]).map(([r, n]) => [r || "—", String(n)])),
      integritySection(sources),
    ],
  };
}

function buildFullCase(sources, scope) {
  const sections = [];
  sections.push(S.text("overview", "Case overview",
    `Full forensic case report compiling all available evidence sources as of ${new Date().toLocaleString()}. Scope: ${fmtScope(scope)}.`));
  sections.push(evidenceSummarySection(sources));
  sections.push(riskSummarySection(sources));
  sections.push(integritySection(sources));
  // investigation summary
  const inv = buildInvestigation(sources, scope);
  sections.push(...inv.sections.filter((s) => s.id !== "integrity"));
  // timeline
  const tl = buildTimeline(sources, scope);
  sections.push(tl.sections.find((s) => s.id === "chronological"));
  sections.push(tl.sections.find((s) => s.id === "correlated"));
  // acquisitions
  const acq = buildAcquisition(sources, scope);
  sections.push(acq.sections.find((s) => s.id === "runs"));
  sections.push(acq.sections.find((s) => s.id === "artifacts"));
  // extensions + cache findings
  sections.push(...buildExtension(sources, scope).sections.filter((s) => s.id === "ext-perms" || s.id === "ext-findings"));
  sections.push(...buildCache(sources, scope).sections.filter((s) => s.id === "cache-findings" || s.id === "cache-suspicious"));
  // findings
  sections.push(buildFindings(sources, scope).sections.find((s) => s.id === "all-findings"));
  // integrity verification detail
  sections.push(...buildIntegrity(sources, scope).sections.filter((s) => s.id === "modified" || s.id === "missing" || s.id === "custody"));
  return { title: "Full Case Report", sections: sections.filter(Boolean) };
}

const BUILDERS = {
  investigation: buildInvestigation,
  timeline: buildTimeline,
  acquisition: buildAcquisition,
  extension: buildExtension,
  cache: buildCache,
  integrity: buildIntegrity,
  findings: buildFindings,
  executive: buildExecutive,
  "full-case": buildFullCase,
};

/* =============================== engine ================================= */

function createReportingEngine(dataDir, opts = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);
  const GENERATED_BY = opts.generatedBy || defaultActor();

  /** @type {object[]} */ let reports = [];
  let updatedAt = 0;
  let byId = new Map();

  load();

  function load() {
    if (!fs.existsSync(sidecarPath)) return;
    try {
      const saved = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
      reports = Array.isArray(saved.reports) ? saved.reports : [];
      updatedAt = saved.updatedAt || 0;
      reindex();
    } catch { reports = []; updatedAt = 0; byId = new Map(); }
  }
  function reindex() { byId = new Map(); for (const r of reports) byId.set(r.reportId, r); }
  function persist() {
    fs.writeFileSync(sidecarPath, JSON.stringify({
      version: FORMAT_VERSION, updatedAt, reports: reports.slice(0, MAX_REPORTS),
    }, null, 2));
  }

  // sources = bounded snapshot injected by db.js (see collectReportSources).
  function create(options = {}, sources = {}) {
    const reportType = REPORT_TYPES.includes(options.reportType) ? options.reportType : "executive";
    const scope = options.scope || { type: "all" };
    const builder = BUILDERS[reportType];
    const built = builder(sources, scope);

    const counts = evidenceCounts(sources);
    const evidenceCount = counts.acquisitions + counts.artifacts + counts.timeline +
      counts.extensionFindings + counts.cacheFindings + counts.investigationFindings;
    const integrityStatus = integritySummary(sources);

    const record = {
      reportId: nowId(),
      reportType,
      reportTypeLabel: REPORT_LABELS[reportType],
      createdAt: Date.now(),
      generatedBy: options.generatedBy || GENERATED_BY,
      reportScope: fmtScope(scope),
      scope,
      evidenceCount,
      integrityStatus,
      title: built.title,
      summary: built.summary || `${REPORT_LABELS[reportType]} · ${evidenceCount} evidence references · integrity ${integrityStatus.overall}`,
      sections: built.sections,
      sourceCounts: counts,
      formats: ["HTML", "JSON", "PDF"],
      builtAt: sources.generatedAt || Date.now(),
    };

    reports.unshift(record);
    if (reports.length > MAX_REPORTS) reports = reports.slice(0, MAX_REPORTS);
    updatedAt = Date.now();
    reindex();
    persist();
    return slim(record);
  }

  function slim(r) { const { ...rest } = r; return rest; }

  function list(f = {}) {
    let rows = reports.map((r) => ({
      reportId: r.reportId, reportType: r.reportType, reportTypeLabel: r.reportTypeLabel,
      title: r.title, createdAt: r.createdAt, generatedBy: r.generatedBy,
      reportScope: r.reportScope, evidenceCount: r.evidenceCount,
      integrityStatus: r.integrityStatus, sectionCount: (r.sections || []).length,
    }));
    if (f.reportType) rows = rows.filter((r) => r.reportType === f.reportType);
    if (f.q) {
      const q = String(f.q).toLowerCase();
      rows = rows.filter((r) => `${r.title} ${r.reportType} ${r.reportScope} ${r.generatedBy}`.toLowerCase().includes(q));
    }
    rows.sort((a, b) => b.createdAt - a.createdAt);
    const total = rows.length;
    const limit = Math.min(Number(f.limit) || 200, 2000);
    const offset = Number(f.offset) || 0;
    return { rows: rows.slice(offset, offset + limit), total, updatedAt };
  }

  function detail(reportId) {
    const r = byId.get(reportId);
    return r ? slim(r) : null;
  }
  function exportData(reportId) { return detail(reportId); }

  function remove(reportId) {
    const before = reports.length;
    reports = reports.filter((r) => r.reportId !== reportId);
    if (reports.length !== before) { updatedAt = Date.now(); reindex(); persist(); return { ok: true }; }
    return { ok: false };
  }

  function stats() {
    const byType = {};
    for (const r of reports) byType[r.reportType] = (byType[r.reportType] || 0) + 1;
    return { total: reports.length, byType, updatedAt, types: REPORT_TYPES, labels: REPORT_LABELS };
  }

  function clear() {
    reports = []; updatedAt = 0; byId = new Map();
    try { fs.writeFileSync(sidecarPath, JSON.stringify({ version: FORMAT_VERSION, updatedAt: 0, reports: [] }, null, 2)); } catch { /* ignore */ }
    return { ok: true };
  }

  return {
    create, list, detail, exportData, remove, stats, clear,
    types: REPORT_TYPES, labels: REPORT_LABELS, sidecarPath,
  };
}

module.exports = { createReportingEngine, REPORT_TYPES, REPORT_LABELS };
