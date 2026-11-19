// acqstore.js
// Persistent store for browser acquisition runs.
//
// Storage model mirrors the rest of the project's derived data (findings.json,
// graph.json, ioc.json): a single JSON sidecar in the data directory. There are
// NO database schema changes and NO modifications to existing tables — the
// acquisition feature is entirely additive and self-contained here.
//
// A run is the full result returned by acquire.acquireProfile():
//   { run, artifacts, records }
// plus a derived `summary` for fast listing. Records are stored in full so the
// acquisition detail view, exports and any future timeline/graph ingestion can
// read them back without re-running acquisition.

const fs = require("fs");
const path = require("path");

const SIDECAR = "acquisitions.json";
const FORMAT_VERSION = 1;
const MAX_RECORDS_PER_RUN = 200000; // hard bound on sidecar growth

function summarize(result) {
  const { run, artifacts, records } = result;
  const byArtifact = {};
  const byType = {};
  let ok = 0;
  let failed = 0;
  let totalRecords = 0;

  for (const a of artifacts) {
    byArtifact[a.artifactType] = {
      recordCount: a.recordCount || 0,
      locked: !!a.locked,
      copied: !!a.copied,
      errors: a.errors || [],
      ok: !(a.errors && a.errors.length),
    };
    if (a.errors && a.errors.length) failed += 1; else ok += 1;
    totalRecords += a.recordCount || 0;
  }
  for (const r of records || []) {
    byType[r.type] = (byType[r.type] || 0) + 1;
  }

  return {
    runId: run.runId,
    browser: run.browser,
    browserFamily: run.browserFamily,
    browserVersion: run.browserVersion,
    versionSource: run.versionSource,
    profile: run.profile,
    profilePath: run.profilePath,
    profileHash: run.profileHash,
    platform: run.platform,
    host: run.host,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    acquiredAt: run.acquiredAt,
    artifactCount: artifacts.length,
    artifactsOk: ok,
    artifactsFailed: failed,
    recordCount: totalRecords,
    storedRecordCount: Math.min((records || []).length, MAX_RECORDS_PER_RUN),
    byArtifact,
    byType,
  };
}

function createAcquisitionStore(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);

  /** @type {Array<{run:object, artifacts:object[], records:object[], summary:object}>} */
  let runs = [];

  if (fs.existsSync(sidecarPath)) {
    try {
      const saved = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
      if (saved && Array.isArray(saved.runs)) {
        runs = saved.runs.map((r) => ({
          run: r.run,
          artifacts: r.artifacts || [],
          records: r.records || [],
          summary: r.summary || summarize(r),
        }));
      }
    } catch { runs = []; }
  }

  function persist() {
    const payload = {
      version: FORMAT_VERSION,
      updatedAt: Date.now(),
      runs: runs.map((r) => ({
        run: r.run,
        artifacts: r.artifacts,
        records: r.records.slice(0, MAX_RECORDS_PER_RUN),
        summary: r.summary,
      })),
    };
    fs.writeFileSync(sidecarPath, JSON.stringify(payload, null, 2));
  }

  function saveRun(result) {
    if (!result || !result.run || !result.run.runId) {
      throw new Error("saveRun: invalid acquisition result");
    }
    const summary = summarize(result);
    const entry = {
      run: result.run,
      artifacts: result.artifacts || [],
      records: (result.records || []).slice(0, MAX_RECORDS_PER_RUN),
      summary,
    };
    // De-dupe by runId (re-save replaces).
    runs = runs.filter((r) => r.run.runId !== result.run.runId);
    runs.unshift(entry);
    persist();
    return summary;
  }

  function list() {
    return runs
      .map((r) => r.summary)
      .sort((a, b) => (b.acquiredAt || 0) - (a.acquiredAt || 0));
  }

  function detail(runId) {
    const r = runs.find((x) => x.run.runId === runId);
    if (!r) return null;
    // Records can be large — return the run, artifacts and summary plus a bounded
    // sample. Full record pages are served by recordsForRun().
    return {
      run: r.run,
      summary: r.summary,
      artifacts: r.artifacts,
      sampleRecords: r.records.slice(0, 200),
      recordCount: r.records.length,
    };
  }

  function recordsForRun(runId, filter = {}) {
    const r = runs.find((x) => x.run.runId === runId);
    if (!r) return { rows: [], total: 0 };
    let rows = r.records;
    if (filter.type) rows = rows.filter((x) => x.type === filter.type);
    if (filter.artifactType) rows = rows.filter((x) => x.sourceArtifact === filter.artifactType);
    if (filter.domain) {
      const d = String(filter.domain).toLowerCase();
      rows = rows.filter((x) => (x.domain || "").toLowerCase().includes(d));
    }
    if (filter.q) {
      const q = String(filter.q).toLowerCase();
      rows = rows.filter((x) =>
        `${x.url} ${x.domain} ${x.title} ${x.detail}`.toLowerCase().includes(q));
    }
    const total = rows.length;
    const limit = Math.min(Number(filter.limit) || 500, 5000);
    const offset = Number(filter.offset) || 0;
    // Stable order: newest timestamp first, then by type.
    const sorted = [...rows].sort((a, b) => (b.ts || 0) - (a.ts || 0));
    return { rows: sorted.slice(offset, offset + limit), total };
  }

  function stats() {
    const totalRuns = runs.length;
    let totalArtifacts = 0;
    let totalRecords = 0;
    const byBrowser = {};
    for (const r of runs) {
      totalArtifacts += r.artifacts.length;
      totalRecords += r.summary.recordCount || 0;
      byBrowser[r.run.browser] = (byBrowser[r.run.browser] || 0) + 1;
    }
    return { totalRuns, totalArtifacts, totalRecords, byBrowser };
  }

  function removeRun(runId) {
    const before = runs.length;
    runs = runs.filter((r) => r.run.runId !== runId);
    const removed = runs.length !== before;
    if (removed) persist();
    return { removed };
  }

  function clear() {
    runs = [];
    persist();
    return { ok: true };
  }

  return {
    saveRun,
    list,
    detail,
    recordsForRun,
    stats,
    removeRun,
    clear,
    sidecarPath,
  };
}

module.exports = { createAcquisitionStore, summarize };
