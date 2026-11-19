// timeline.js
// Timeline Reconstruction Engine.
//
// Builds a single, unified forensic timeline by merging two independent
// datasets the project already produces:
//
//   * LIVE     — events captured by the browser extension / listener and stored
//                in the events table (navigation, requests, cookies, downloads,
//                storage, permissions, …) plus derived behavioral FINDINGS.
//   * ACQUIRED — read-only browser acquisition records (history, downloads,
//                cookies, bookmarks, extensions, logins, localStorage,
//                indexedDB, favicons, topsites, preferences, sessions,
//                serviceWorkers) from acqstore.js.
//
// Storage model mirrors the rest of the project's derived data (findings.json,
// graph.json, acquisitions.json): a single JSON sidecar (timeline.json) in the
// data directory. There are NO database schema changes and NO modifications to
// existing tables or acquisition schemas — this engine is entirely additive and
// reads its inputs through the store, which injects them at build time.
//
// Every timeline entry carries the canonical forensic fields required by the
// spec:
//   timelineId, sourceType, sourceId, runId, artifactId, eventId, ts,
//   category, severity, title, detail, domain, url, tags[]
// plus correlation metadata:
//   relatedTimelineIds[], confidenceScore, correlationType
// and additive facet fields used for filtering & future engines (graph,
// reporting, evidence integrity) — these never replace the canonical fields:
//   artifactType, browser, profile, tsKind, score, severityRank, approxTs
//
// All timestamps are Unix epoch milliseconds. Entries are stored sorted
// chronologically (ascending). Records with no native timestamp fall back to
// the acquisition's acquiredAt and are flagged approxTs:true + tagged
// "approx-ts" so integrity tooling can tell derived placement from source time.

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const risk = require("./risk");

const SIDECAR = "timeline.json";
const FORMAT_VERSION = 1;

// Bounds (keep the sidecar and correlation graph from growing without limit).
const MAX_ACQ_RECORDS = 200000;   // matches acqstore sidecar bound
const MAX_RELATED_PER_ENTRY = 300;
const MAX_EDGES = 250000;
const MAX_EXPORT_ENTRIES = 50000;

// ---- unified severity scale (covers live INFO/MED/HIGH + finding CRIT/HIGH/MED/LOW) ----
const SEVERITY_RANK = { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
function sevRank(s) { return SEVERITY_RANK[s] != null ? SEVERITY_RANK[s] : 0; }
function normSeverity(s) { return SEVERITY_RANK[s] != null ? s : "INFO"; }

// ---- category normalization (cross-source activity classes) ----
const LIVE_CATEGORY = {
  tab: "navigation", navigation: "navigation",
  request: "request", tracker: "request", resource: "request",
  cookie: "cookie", storage: "storage", permission: "permission",
  download: "download", fingerprint: "fingerprint",
};
const ACQ_CATEGORY = {
  history: "navigation", topsite: "navigation",
  download: "download", cookie: "cookie", bookmark: "bookmark",
  extension: "extension", login: "login",
  indexeddb: "storage", localstorage: "storage",
  favicon: "favicon", preference: "preference", serviceworker: "serviceworker",
};

// Priority used to pick an entry's *primary* correlationType when it takes part
// in several correlations of equal confidence.
const CORR_PRIORITY = {
  download: 6, cookie: 5, serviceworker: 4, session: 3, "history-domain": 2,
};

function nd(v) { return risk.normalizeDomain(v) || ""; }

function isTrackerLiveEvent(e) {
  const url = (e.raw && e.raw.requestUrl) || e.url || "";
  return e.type === "tracker" || (e.raw && e.raw.trackerDetected) ||
    risk.isTracker(e.domain) || risk.isAnalytics(url);
}

function baseName(u) {
  if (!u) return "";
  try {
    if (/^[a-z]+:/i.test(u)) {
      const p = new URL(u).pathname;
      return path.basename(p).toLowerCase();
    }
  } catch { /* fall through */ }
  return path.basename(String(u)).toLowerCase();
}

function normUrl(u) {
  if (!u) return "";
  return String(u).trim().toLowerCase();
}

function timelineIdFor(sourceType, eventId) {
  return "tl_" + crypto.createHash("sha256")
    .update(`${sourceType}|${eventId}`).digest("hex").slice(0, 24);
}

/* ============================ entry construction ========================= */

// Each "built" item bundles the public entry with transient correlation keys
// (prefixed `_`) that are stripped before persisting.
function makeLiveEntry(e) {
  const category = LIVE_CATEGORY[e.type] || e.type || "other";
  const severity = normSeverity(e.risk);
  const domain = e.domain || nd(e.url) || "";
  const tracker = isTrackerLiveEvent(e);
  const tags = ["live", e.type, severity];
  if (tracker) tags.push("tracker");
  const entry = {
    timelineId: timelineIdFor("live", e.id),
    sourceType: "live",
    sourceId: e.id,
    runId: null,
    artifactId: null,
    eventId: e.id,
    ts: Number.isFinite(e.ts) ? e.ts : Date.now(),
    category,
    severity,
    title: e.title || `${category}${domain ? " · " + domain : ""}`,
    detail: e.detail || "",
    domain,
    url: e.url || (e.raw && e.raw.requestUrl) || "",
    tags,
    artifactType: null,
    browser: "",
    profile: "",
    tsKind: "live-observed",
    score: e.score || 0,
    severityRank: sevRank(severity),
    approxTs: false,
  };
  return {
    entry, kind: "live", category,
    _d: domain,
    _file: e.type === "download" ? baseName((e.raw && e.raw.filename) || e.url || "") : "",
    _url: e.type === "download" ? normUrl(e.url || (e.raw && e.raw.url) || "") : "",
    _cookie: e.type === "cookie" ? String(e.name || "").toLowerCase() : "",
    _navlike: e.type === "navigation" || e.type === "tab",
  };
}

function makeFindingEntry(f) {
  const severity = normSeverity(f.severity);
  const domain = (f.affectedDomains && f.affectedDomains[0]) || "";
  const ts = Number.isFinite(f.firstSeen) ? f.firstSeen
    : (Number.isFinite(f.lastSeen) ? f.lastSeen : Date.now());
  const tags = ["finding", f.rule || "rule", severity];
  const entry = {
    timelineId: timelineIdFor("finding", f.id),
    sourceType: "finding",
    sourceId: f.id,
    runId: null,
    artifactId: null,
    eventId: f.id,
    ts,
    category: "finding",
    severity,
    title: f.title || "Finding",
    detail: f.description || "",
    domain,
    url: "",
    tags,
    artifactType: null,
    browser: "",
    profile: "",
    tsKind: "finding-firstseen",
    score: Math.round((f.confidence || 0) * 100),
    severityRank: sevRank(severity),
    approxTs: false,
  };
  return { entry, kind: "finding", category: "finding", _d: domain, _file: "", _url: "", _cookie: "", _navlike: false };
}

function makeAcqEntry(rec, run) {
  const category = ACQ_CATEGORY[rec.type] || rec.type || "other";
  const domain = rec.domain || nd(rec.url) || "";
  const native = rec.ts != null && Number.isFinite(rec.ts);
  const ts = native ? rec.ts
    : (Number.isFinite(run.acquiredAt) ? run.acquiredAt
      : (Number.isFinite(run.finishedAt) ? run.finishedAt : Date.now()));
  const attrs = rec.attributes || {};
  const tags = ["acquired", rec.sourceArtifact, rec.type];
  if (run.browser) tags.push(run.browser);
  if (!native) tags.push("approx-ts");
  if (risk.isTracker(domain)) tags.push("tracker");
  const entry = {
    timelineId: timelineIdFor("acquired", rec.eventId),
    sourceType: "acquired",
    sourceId: rec.eventId,
    runId: rec.runId || run.runId || null,
    artifactId: rec.artifactId || null,
    eventId: rec.eventId,
    ts,
    category,
    severity: "INFO",
    title: rec.title || `${rec.type}${domain ? " · " + domain : ""}`,
    detail: rec.detail || "",
    domain,
    url: rec.url || "",
    tags,
    artifactType: rec.sourceArtifact || null,
    browser: run.browser || "",
    profile: run.profile || "",
    tsKind: rec.tsKind || "none",
    score: 0,
    severityRank: 0,
    approxTs: !native,
  };
  const fileName = baseName(attrs.destination || attrs.filename || rec.url || "");
  return {
    entry, kind: "acq", category,
    _d: domain,
    _file: rec.type === "download" ? fileName : "",
    _url: rec.type === "download" ? normUrl(rec.url || attrs.destination || "") : "",
    _cookie: rec.type === "cookie" ? String(attrs.cookieName || rec.title || "").toLowerCase() : "",
    _navlike: false,
    _runId: rec.runId || run.runId || null,
  };
}

// Inventory-only artifacts (e.g. "sessions") emit no normalized records. We
// surface them as a single summary entry so the acquired "sessions" artifact
// still appears on the timeline and can be correlated with live session
// activity. Placed at the acquisition time.
function makeAcqArtifactEntry(a, run) {
  const ts = Number.isFinite(run.acquiredAt) ? run.acquiredAt
    : (Number.isFinite(run.finishedAt) ? run.finishedAt : Date.now());
  const fileCount = a.files ? a.files.length : (a.recordCount || 0);
  const category = ACQ_CATEGORY[a.artifactType] ||
    (a.artifactType === "sessions" ? "session" : (a.artifactType || "other"));
  const tags = ["acquired", a.artifactType, "artifact-summary"];
  if (run.browser) tags.push(run.browser);
  tags.push("approx-ts");
  const entry = {
    timelineId: timelineIdFor("acquired", "artifact:" + a.artifactId),
    sourceType: "acquired",
    sourceId: a.artifactId,
    runId: a.runId || run.runId || null,
    artifactId: a.artifactId || null,
    eventId: "artifact:" + a.artifactId,
    ts,
    category,
    severity: "INFO",
    title: `${a.artifactType} artifact (${fileCount} file${fileCount === 1 ? "" : "s"})`,
    detail: a.sourcePath ? `source ${a.sourcePath}` : `${a.artifactType} acquisition artifact`,
    domain: "",
    url: "",
    tags,
    artifactType: a.artifactType || null,
    browser: run.browser || "",
    profile: run.profile || "",
    tsKind: "artifact-acquired",
    score: 0,
    severityRank: 0,
    approxTs: true,
  };
  return {
    entry, kind: "acqArtifact", category,
    _d: "", _file: "", _url: "", _cookie: "", _navlike: false,
    _runId: a.runId || run.runId || null,
  };
}

/* ============================== correlation ============================== */

function bound(arr, n) { return arr.length > n ? arr.slice(0, n) : arr; }

function createTimelineEngine(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);

  /** @type {object[]} */ let entries = [];
  /** @type {Array<{a:string,b:string,type:string,conf:number}>} */ let edges = [];
  let meta = emptyMeta();
  let builtAt = 0;
  let byId = new Map();

  load();

  function emptyMeta() {
    return {
      built: false, builtAt: 0, total: 0,
      bySource: {}, bySeverity: {}, byCategory: {}, byArtifact: {},
      correlated: 0, correlationEdges: 0, correlationsByType: {},
      since: null, until: null, browsers: [], profiles: [],
    };
  }

  function load() {
    if (!fs.existsSync(sidecarPath)) return;
    try {
      const saved = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
      entries = Array.isArray(saved.entries) ? saved.entries : [];
      edges = Array.isArray(saved.edges) ? saved.edges : [];
      meta = saved.meta || emptyMeta();
      builtAt = saved.builtAt || 0;
      reindex();
    } catch {
      entries = []; edges = []; meta = emptyMeta(); builtAt = 0; byId = new Map();
    }
  }

  function reindex() {
    byId = new Map();
    for (const e of entries) byId.set(e.timelineId, e);
  }

  function persist() {
    const payload = {
      version: FORMAT_VERSION,
      builtAt,
      meta,
      edges: bound(edges, MAX_EDGES),
      entries,
    };
    fs.writeFileSync(sidecarPath, JSON.stringify(payload, null, 2));
  }

  /* ----------------------------- build ---------------------------------- */

  function build(inputs = {}) {
    const liveEvents = inputs.liveEvents || [];
    const findings = inputs.findings || [];
    const runs = inputs.runs || [];

    /** @type {Array} */ const built = [];
    for (const e of liveEvents) built.push(makeLiveEntry(e));
    for (const f of findings) built.push(makeFindingEntry(f));

    // Per-run acquired history domains (for session correlation).
    const runHistoryDomains = new Map(); // runId -> Set(domain)

    let acqCount = 0;
    for (const r of runs) {
      const run = r.run || {};
      const arts = r.artifacts || [];
      const recs = r.records || [];
      const artHasRecords = new Set();
      const histSet = new Set();

      for (const rec of recs) {
        if (acqCount >= MAX_ACQ_RECORDS) break;
        const item = makeAcqEntry(rec, run);
        built.push(item);
        artHasRecords.add(item.entry.artifactId);
        acqCount++;
        if (rec.type === "history" && item._d) histSet.add(item._d);
      }
      if (histSet.size) runHistoryDomains.set(run.runId, histSet);

      // Surface inventory-only artifacts (records-less) — notably "sessions".
      for (const a of arts) {
        if (artHasRecords.has(a.artifactId)) continue;
        const hasFiles = a.files && a.files.length;
        if (!hasFiles && a.artifactType !== "sessions") continue;
        if (a.errors && a.errors.length && !hasFiles) continue;
        built.push(makeAcqArtifactEntry(a, run));
      }
    }

    // De-dupe by timelineId (deterministic ids make rebuilds idempotent).
    const seen = new Set();
    const items = [];
    for (const it of built) {
      if (seen.has(it.entry.timelineId)) continue;
      seen.add(it.entry.timelineId);
      it.entry._related = new Set();
      it.entry._links = [];
      items.push(it);
    }

    const edgeList = [];
    const pairLink = (ai, bi, type, conf) => {
      if (ai === bi) return;
      if (edgeList.length >= MAX_EDGES) return;
      if (ai.entry._related.size < MAX_RELATED_PER_ENTRY) ai.entry._related.add(bi.entry.timelineId);
      if (bi.entry._related.size < MAX_RELATED_PER_ENTRY) bi.entry._related.add(ai.entry.timelineId);
      ai.entry._links.push({ type, conf });
      bi.entry._links.push({ type, conf });
      edgeList.push({ a: ai.entry.timelineId, b: bi.entry.timelineId, type, conf });
    };

    correlate(items, runHistoryDomains, pairLink);

    // Finalize entries: collapse transient correlation state into the schema.
    const out = items.map((it) => {
      const e = it.entry;
      e.relatedTimelineIds = bound([...e._related], MAX_RELATED_PER_ENTRY);
      if (e._links.length) {
        let best = e._links[0];
        for (const l of e._links) {
          if (l.conf > best.conf ||
            (l.conf === best.conf && (CORR_PRIORITY[l.type] || 0) > (CORR_PRIORITY[best.type] || 0))) {
            best = l;
          }
        }
        e.confidenceScore = Math.round(best.conf * 100) / 100;
        e.correlationType = best.type;
      } else {
        e.confidenceScore = 0;
        e.correlationType = null;
      }
      delete e._related; delete e._links;
      return e;
    });

    out.sort((a, b) => (a.ts - b.ts) || (a.timelineId < b.timelineId ? -1 : a.timelineId > b.timelineId ? 1 : 0));

    entries = out;
    edges = edgeList;
    builtAt = Date.now();
    meta = computeMeta(entries, edges, builtAt);
    reindex();
    persist();
    return meta;
  }

  function correlate(items, runHistoryDomains, pairLink) {
    // Bucket helpers.
    const live = items.filter((i) => i.kind === "live");
    const acq = items.filter((i) => i.kind === "acq");
    const acqArtifacts = items.filter((i) => i.kind === "acqArtifact");

    const liveByDomain = new Map();
    const liveNavByDomain = new Map();
    for (const i of live) {
      if (i._d) {
        (liveByDomain.get(i._d) || liveByDomain.set(i._d, []).get(i._d)).push(i);
        if (i._navlike) (liveNavByDomain.get(i._d) || liveNavByDomain.set(i._d, []).get(i._d)).push(i);
      }
    }

    // (1) live downloads <-> acquired downloads
    const acqDl = acq.filter((i) => i.entry.category === "download");
    const acqDlByUrl = new Map();
    const acqDlByFile = new Map();
    const acqDlByDomain = new Map();
    for (const i of acqDl) {
      if (i._url) (acqDlByUrl.get(i._url) || acqDlByUrl.set(i._url, []).get(i._url)).push(i);
      if (i._file) (acqDlByFile.get(i._file) || acqDlByFile.set(i._file, []).get(i._file)).push(i);
      if (i._d) (acqDlByDomain.get(i._d) || acqDlByDomain.set(i._d, []).get(i._d)).push(i);
    }
    const DL_WINDOW = 7 * 86400000;
    for (const lv of live) {
      if (lv.entry.category !== "download") continue;
      let matched = false;
      if (lv._url && acqDlByUrl.has(lv._url)) {
        for (const m of acqDlByUrl.get(lv._url)) pairLink(lv, m, "download", 0.92);
        matched = true;
      }
      if (!matched && lv._file && acqDlByFile.has(lv._file)) {
        for (const m of acqDlByFile.get(lv._file)) pairLink(lv, m, "download", 0.75);
        matched = true;
      }
      if (!matched && lv._d && acqDlByDomain.has(lv._d)) {
        for (const m of bound(acqDlByDomain.get(lv._d), 8)) {
          if (Math.abs((m.entry.ts || 0) - (lv.entry.ts || 0)) <= DL_WINDOW) pairLink(lv, m, "download", 0.5);
        }
      }
    }

    // (2) live cookies <-> acquired cookies  (domain + cookie name)
    const acqCkByKey = new Map();
    for (const i of acq) {
      if (i.entry.category !== "cookie" || !i._d || !i._cookie) continue;
      const k = `${i._d}|${i._cookie}`;
      (acqCkByKey.get(k) || acqCkByKey.set(k, []).get(k)).push(i);
    }
    for (const lv of live) {
      if (lv.entry.category !== "cookie" || !lv._d || !lv._cookie) continue;
      const k = `${lv._d}|${lv._cookie}`;
      if (acqCkByKey.has(k)) for (const m of acqCkByKey.get(k)) pairLink(lv, m, "cookie", 0.85);
    }

    // (3) live domains <-> acquired history
    const acqHistByDomain = new Map();
    for (const i of acq) {
      if (i.entry.artifactType === "history" && i._d) {
        (acqHistByDomain.get(i._d) || acqHistByDomain.set(i._d, []).get(i._d)).push(i);
      }
    }
    for (const [domain, histItems] of acqHistByDomain) {
      const liveItems = liveByDomain.get(domain);
      if (!liveItems || !liveItems.length) continue;
      const liveSlice = bound(liveItems, 12);
      for (const h of bound(histItems, 12)) {
        for (const lv of liveSlice) pairLink(h, lv, "history-domain", 0.6);
      }
    }

    // (4) serviceWorkers <-> visited domains (live navigation + acquired history)
    for (const sw of acq) {
      if (sw.entry.category !== "serviceworker" || !sw._d) continue;
      const navs = liveNavByDomain.get(sw._d) || liveByDomain.get(sw._d) || [];
      for (const lv of bound(navs, 8)) pairLink(sw, lv, "serviceworker", 0.7);
      const hist = acqHistByDomain.get(sw._d) || [];
      for (const h of bound(hist, 8)) pairLink(sw, h, "serviceworker", 0.6);
    }

    // (5) session activity <-> acquired sessions artifact
    for (const sa of acqArtifacts) {
      if (sa.entry.artifactType !== "sessions") continue;
      const domains = runHistoryDomains.get(sa._runId);
      if (!domains || !domains.size) continue;
      for (const d of domains) {
        const navs = liveNavByDomain.get(d) || [];
        for (const lv of bound(navs, 5)) pairLink(sa, lv, "session", 0.45);
      }
    }
  }

  function computeMeta(rows, edgeList, ts) {
    const bySource = {}, bySeverity = {}, byCategory = {}, byArtifact = {};
    const browsers = new Set(), profiles = new Set();
    let correlated = 0;
    let since = null, until = null;
    for (const e of rows) {
      bySource[e.sourceType] = (bySource[e.sourceType] || 0) + 1;
      bySeverity[e.severity] = (bySeverity[e.severity] || 0) + 1;
      byCategory[e.category] = (byCategory[e.category] || 0) + 1;
      if (e.artifactType) byArtifact[e.artifactType] = (byArtifact[e.artifactType] || 0) + 1;
      if (e.browser) browsers.add(e.browser);
      if (e.profile) profiles.add(e.profile);
      if (e.relatedTimelineIds && e.relatedTimelineIds.length) correlated++;
      if (since == null || e.ts < since) since = e.ts;
      if (until == null || e.ts > until) until = e.ts;
    }
    const correlationsByType = {};
    for (const edge of edgeList) correlationsByType[edge.type] = (correlationsByType[edge.type] || 0) + 1;
    return {
      built: true, builtAt: ts, total: rows.length,
      bySource, bySeverity, byCategory, byArtifact,
      correlated, correlationEdges: edgeList.length, correlationsByType,
      since, until,
      browsers: [...browsers].sort(),
      profiles: [...profiles].sort(),
    };
  }

  /* --------------------------- query / filter --------------------------- */

  function matches(e, f) {
    if (f.sourceType && e.sourceType !== f.sourceType) return false;
    if (f.artifactType && e.artifactType !== f.artifactType) return false;
    if (f.category && e.category !== f.category) return false;
    if (f.severity && e.severity !== f.severity) return false;
    if (f.minSeverity && sevRank(e.severity) < sevRank(f.minSeverity)) return false;
    if (f.browser && e.browser !== f.browser) return false;
    if (f.profile && e.profile !== f.profile) return false;
    if (f.domain && !(e.domain || "").toLowerCase().includes(String(f.domain).toLowerCase())) return false;
    if (f.since != null && e.ts < Number(f.since)) return false;
    if (f.until != null && e.ts > Number(f.until)) return false;
    if (f.correlatedOnly && !(e.relatedTimelineIds && e.relatedTimelineIds.length)) return false;
    if (f.q) {
      const q = String(f.q).toLowerCase();
      const hay = `${e.title} ${e.detail} ${e.domain} ${e.url} ${(e.tags || []).join(" ")}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function filtered(f = {}) {
    return entries.filter((e) => matches(e, f));
  }

  function query(f = {}) {
    const rows = filtered(f);
    const order = f.order === "asc" ? "asc" : "desc";
    rows.sort((a, b) => order === "asc" ? a.ts - b.ts : b.ts - a.ts);
    const total = rows.length;
    const limit = Math.min(Number(f.limit) || 500, 5000);
    const offset = Number(f.offset) || 0;
    return { rows: rows.slice(offset, offset + limit), total, built: meta.built, builtAt };
  }

  function detail(timelineId) {
    const e = byId.get(timelineId);
    if (!e) return null;
    const related = (e.relatedTimelineIds || [])
      .map((id) => byId.get(id))
      .filter(Boolean)
      .sort((a, b) => a.ts - b.ts);
    const correlations = edges
      .filter((edge) => edge.a === timelineId || edge.b === timelineId)
      .map((edge) => ({
        type: edge.type,
        confidence: edge.conf,
        with: edge.a === timelineId ? edge.b : edge.a,
      }));
    return { entry: e, related, correlations };
  }

  function filters() {
    return {
      sourceTypes: Object.keys(meta.bySource).sort(),
      artifactTypes: Object.keys(meta.byArtifact).sort(),
      categories: Object.keys(meta.byCategory).sort(),
      severities: SEVERITY_ORDER.filter((s) => meta.bySeverity[s]),
      browsers: meta.browsers || [],
      profiles: meta.profiles || [],
      since: meta.since,
      until: meta.until,
      total: meta.total,
      built: meta.built,
      builtAt,
    };
  }

  function exportData(f = {}) {
    const rows = filtered(f).sort((a, b) => a.ts - b.ts);
    const capped = bound(rows, MAX_EXPORT_ENTRIES);
    return {
      meta,
      builtAt,
      generatedAt: Date.now(),
      filter: f || {},
      count: capped.length,
      total: rows.length,
      entries: capped,
    };
  }

  function stats() { return { ...meta, builtAt }; }

  function clear() {
    entries = []; edges = []; meta = emptyMeta(); builtAt = 0; byId = new Map();
    try { fs.writeFileSync(sidecarPath, JSON.stringify({ version: FORMAT_VERSION, builtAt: 0, meta, edges: [], entries: [] }, null, 2)); } catch { /* ignore */ }
    return { ok: true };
  }

  return {
    build, query, detail, filters, exportData, stats, clear,
    sidecarPath,
  };
}

module.exports = { createTimelineEngine, SEVERITY_RANK, SEVERITY_ORDER };
