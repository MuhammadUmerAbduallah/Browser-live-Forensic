// integrity.js
// Evidence Integrity Engine.
//
// Forensic evidence integrity verification and chain-of-custody tracking for all
// evidence the platform produces. It is purely additive: it reads the current
// state of every other engine (acquisitions, timeline, extension findings, cache
// findings, investigation findings, exports), computes a deterministic SHA256
// over a CANONICAL serialization of each evidence item, and records:
//
//   * an integrity record per evidence item (baseline hash + verification state)
//   * a chain-of-custody event log (created / modified / exported / verified)
//
// Verification recomputes the canonical hash from the current evidence and
// compares it to the recorded baseline:
//   VALID    - recomputed hash matches the baseline
//   MODIFIED - evidence still present but hash differs from the baseline
//   MISSING  - evidence (or an exported file) is no longer present
//   UNKNOWN  - registered but not yet verified
//
// Storage mirrors the rest of the project's derived data (a single JSON sidecar,
// integrity.json). No database schema changes; no modifications to acquisition,
// timeline, extension or cache schemas. Records are designed to be consumed by a
// future Reporting Engine, Advanced Threat Hunting and external forensic exports
// (stable ids, canonical hashes, explicit relatedEvidenceIds[]).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const os = require("os");

const SIDECAR = "integrity.json";
const FORMAT_VERSION = 1;

const ACTIONS = ["created", "modified", "exported", "verified"];
const STATUSES = ["VALID", "MODIFIED", "MISSING", "UNKNOWN"];
const VERIFIABLE_TYPES = new Set([
  "acquisition", "artifact", "timeline", "extension-finding",
  "cache-finding", "investigation-finding",
]);
const MAX_RELATED = 100;

function defaultActor() {
  try {
    const u = os.userInfo();
    if (u && u.username) return u.username;
  } catch { /* ignore */ }
  return process.env.USER || process.env.USERNAME || "system";
}

function sha256(input) {
  return crypto.createHash("sha256").update(input).digest("hex");
}

// Deterministic JSON: object keys sorted recursively so the hash is stable.
function stableStringify(value) {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return "[" + value.map(stableStringify).join(",") + "]";
  const keys = Object.keys(value).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(value[k])).join(",") + "}";
}
function hashContent(content) { return sha256(stableStringify(content)); }

function integrityIdFor(evidenceType, evidenceId) {
  return "int_" + sha256(`${evidenceType}|${evidenceId}`).slice(0, 20);
}
function custodyIdFor(evidenceType, evidenceId, action, ts) {
  return "cust_" + sha256(`${evidenceType}|${evidenceId}|${action}|${ts}|${Math.random()}`).slice(0, 20);
}
function evKey(type, id) { return `${type}\u241F${id}`; }

/* ----------------------- evidence descriptor builders -------------------- */
// Each builder returns { evidenceType, evidenceId, label, source, content,
// related[] }. `content` is the canonical, hash-stable subset of the evidence.

function describeAcquisition(run, summary) {
  const s = summary || {};
  return {
    evidenceType: "acquisition",
    evidenceId: run.runId,
    label: `${run.browser || "?"} acquisition${run.profile ? " · " + run.profile : ""}`,
    source: run.host || "",
    content: {
      runId: run.runId, browser: run.browser, browserFamily: run.browserFamily,
      browserVersion: run.browserVersion, profile: run.profile, profileHash: run.profileHash,
      platform: run.platform, host: run.host, acquiredAt: run.acquiredAt,
      artifactCount: s.artifactCount, recordCount: s.recordCount,
    },
  };
}

function describeArtifact(a, run) {
  return {
    evidenceType: "artifact",
    evidenceId: a.artifactId,
    label: `${a.artifactType} artifact`,
    source: run ? run.runId : (a.runId || ""),
    content: {
      artifactId: a.artifactId, runId: a.runId || (run && run.runId), artifactType: a.artifactType,
      recordCount: a.recordCount || 0,
      sha256: a.sha256 || a.dirSha || "",
      hashScope: a.hashScope || "",
      errorCount: (a.errors || []).length,
    },
  };
}

function describeTimeline(e) {
  return {
    evidenceType: "timeline",
    evidenceId: e.timelineId,
    label: `${e.category} · ${e.domain || e.title || ""}`.slice(0, 120),
    source: e.sourceType,
    content: {
      timelineId: e.timelineId, sourceType: e.sourceType, sourceId: e.sourceId,
      runId: e.runId, artifactId: e.artifactId, eventId: e.eventId, ts: e.ts,
      category: e.category, severity: e.severity, title: e.title, detail: e.detail,
      domain: e.domain, url: e.url,
    },
    related: [e.runId, e.artifactId].filter(Boolean),
  };
}

function describeExtFinding(f) {
  return {
    evidenceType: "extension-finding",
    evidenceId: f.findingId,
    label: `ext: ${f.reason}`,
    source: f.extensionId,
    content: {
      findingId: f.findingId, extensionId: f.extensionId, severity: f.severity,
      reason: f.reason, evidence: f.evidence, ts: f.ts,
    },
    related: (f.relatedTimelineIds || []).slice(0, MAX_RELATED),
  };
}

function describeCacheFinding(f) {
  return {
    evidenceType: "cache-finding",
    evidenceId: f.findingId,
    label: `cache: ${f.reason}`,
    source: f.cacheId,
    content: {
      findingId: f.findingId, cacheId: f.cacheId, severity: f.severity,
      reason: f.reason, evidence: f.evidence, ts: f.ts,
    },
    related: (f.relatedTimelineIds || []).slice(0, MAX_RELATED),
  };
}

function describeInvFinding(f) {
  return {
    evidenceType: "investigation-finding",
    evidenceId: f.id,
    label: f.title || f.rule || f.id,
    source: f.rule || "",
    content: {
      id: f.id, rule: f.rule, severity: f.severity, title: f.title,
      description: f.description,
      affectedDomains: [...(f.affectedDomains || [])].sort(),
      firstSeen: f.firstSeen, lastSeen: f.lastSeen,
    },
  };
}

/* =============================== engine ================================= */

function createIntegrityEngine(dataDir, opts = {}) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);
  const ACTOR = opts.actor || defaultActor();

  /** @type {object[]} */ let records = [];
  /** @type {object[]} */ let custody = [];
  let meta = emptyMeta();
  let updatedAt = 0;
  let byKey = new Map();
  let byIntegrityId = new Map();

  load();

  function emptyMeta() {
    return {
      built: false, updatedAt: 0, total: 0, custodyCount: 0,
      byStatus: { VALID: 0, MODIFIED: 0, MISSING: 0, UNKNOWN: 0 },
      byType: {}, lastVerifiedAt: 0,
    };
  }

  function load() {
    if (!fs.existsSync(sidecarPath)) return;
    try {
      const saved = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
      records = Array.isArray(saved.records) ? saved.records : [];
      custody = Array.isArray(saved.custody) ? saved.custody : [];
      meta = saved.meta || emptyMeta();
      updatedAt = saved.updatedAt || 0;
      reindex();
    } catch {
      records = []; custody = []; meta = emptyMeta(); updatedAt = 0;
      byKey = new Map(); byIntegrityId = new Map();
    }
  }

  function reindex() {
    byKey = new Map();
    byIntegrityId = new Map();
    for (const r of records) {
      byKey.set(evKey(r.evidenceType, r.evidenceId), r);
      byIntegrityId.set(r.integrityId, r);
    }
  }

  function persist() {
    fs.writeFileSync(sidecarPath, JSON.stringify({
      version: FORMAT_VERSION, updatedAt, meta, records, custody,
    }, null, 2));
  }

  function addCustody(rec, action, hash, actor, note) {
    const ts = Date.now();
    const ev = {
      custodyId: custodyIdFor(rec.evidenceType, rec.evidenceId, action, ts),
      evidenceId: rec.evidenceId,
      evidenceType: rec.evidenceType,
      integrityId: rec.integrityId,
      action,
      ts,
      actor: actor || ACTOR,
      hash: hash || "",
      note: note || "",
    };
    custody.push(ev);
    rec.custodyCount = (rec.custodyCount || 0) + 1;
    rec.lastAction = action;
    rec.lastActor = ev.actor;
    return ev;
  }

  /* --------------------------- descriptor pass -------------------------- */

  function buildDescriptors(inputs) {
    const out = [];
    const tlByRun = new Map();
    const tlByArtifact = new Map();

    for (const e of (inputs.timelineEntries || [])) {
      const d = describeTimeline(e);
      out.push(d);
      if (e.runId) (tlByRun.get(e.runId) || tlByRun.set(e.runId, []).get(e.runId)).push(e.timelineId);
      if (e.artifactId) (tlByArtifact.get(e.artifactId) || tlByArtifact.set(e.artifactId, []).get(e.artifactId)).push(e.timelineId);
    }

    for (const acq of (inputs.acquisitions || [])) {
      const run = acq.run || {};
      const runDesc = describeAcquisition(run, acq.summary);
      const artIds = (acq.artifacts || []).map((a) => a.artifactId).filter(Boolean);
      const tlIds = tlByRun.get(run.runId) || [];
      runDesc.related = [...artIds, ...tlIds].slice(0, MAX_RELATED);
      out.push(runDesc);
      for (const a of (acq.artifacts || [])) {
        const d = describeArtifact(a, run);
        d.related = [run.runId, ...(tlByArtifact.get(a.artifactId) || [])].filter(Boolean).slice(0, MAX_RELATED);
        out.push(d);
      }
    }

    for (const f of (inputs.extensionFindings || [])) out.push(describeExtFinding(f));
    for (const f of (inputs.cacheFindings || [])) out.push(describeCacheFinding(f));
    for (const f of (inputs.investigationFindings || [])) out.push(describeInvFinding(f));

    return out;
  }

  // Register/refresh integrity records from current evidence. New evidence gets a
  // baseline hash + a "created" custody event. Existing records keep their
  // baseline (so divergence is detectable) but refresh currentSha256/related.
  function register(inputs, actor) {
    const descriptors = buildDescriptors(inputs);
    const now = Date.now();
    let created = 0;

    for (const d of descriptors) {
      if (!d.evidenceId) continue;
      const hash = hashContent(d.content);
      const key = evKey(d.evidenceType, d.evidenceId);
      let rec = byKey.get(key);
      if (!rec) {
        rec = {
          integrityId: integrityIdFor(d.evidenceType, d.evidenceId),
          evidenceId: d.evidenceId,
          evidenceType: d.evidenceType,
          label: d.label || "",
          source: d.source || "",
          sha256: hash,             // baseline
          currentSha256: hash,
          createdAt: now,
          baselineAt: now,
          verifiedAt: null,
          verificationStatus: "UNKNOWN",
          relatedEvidenceIds: d.related || [],
          size: null,
          custodyCount: 0,
          lastAction: null,
          lastActor: null,
        };
        records.push(rec);
        byKey.set(key, rec);
        byIntegrityId.set(rec.integrityId, rec);
        addCustody(rec, "created", hash, actor, "baseline registered");
        created++;
      } else {
        rec.currentSha256 = hash;
        rec.label = d.label || rec.label;
        rec.source = d.source || rec.source;
        if (d.related && d.related.length) {
          rec.relatedEvidenceIds = [...new Set([...(rec.relatedEvidenceIds || []), ...d.related])].slice(0, MAX_RELATED);
        }
      }
    }

    updatedAt = now;
    recomputeMeta();
    return { created, total: records.length };
  }

  /* ------------------------------ verify -------------------------------- */

  function currentEvidenceMap(inputs) {
    const map = new Map();
    for (const d of buildDescriptors(inputs)) {
      map.set(evKey(d.evidenceType, d.evidenceId), hashContent(d.content));
    }
    return map;
  }

  function verifyRecord(rec, curMap, actor) {
    let status, curHash = null;
    if (rec.evidenceType === "export") {
      const fileHash = hashExportFile(rec.source);
      if (fileHash == null) status = "MISSING";
      else { curHash = fileHash; status = (fileHash === rec.sha256) ? "VALID" : "MODIFIED"; }
    } else {
      curHash = curMap.get(evKey(rec.evidenceType, rec.evidenceId));
      if (curHash == null) status = "MISSING";
      else status = (curHash === rec.sha256) ? "VALID" : "MODIFIED";
    }
    const prevStatus = rec.verificationStatus;
    rec.verificationStatus = status;
    rec.verifiedAt = Date.now();
    if (curHash != null) rec.currentSha256 = curHash;
    // record a "modified" custody event the first time divergence is observed
    if (status === "MODIFIED" && prevStatus !== "MODIFIED") {
      addCustody(rec, "modified", curHash || "", actor, "hash diverged from baseline");
    }
    addCustody(rec, "verified", curHash || rec.sha256, actor, `status ${status}`);
    return status;
  }

  function hashExportFile(filePath) {
    try {
      if (!filePath || !fs.existsSync(filePath)) return null;
      return sha256(fs.readFileSync(filePath));
    } catch { return null; }
  }

  function verifyAll(inputs, actor) {
    register(inputs, actor);
    const curMap = currentEvidenceMap(inputs);
    for (const rec of records) verifyRecord(rec, curMap, actor);
    updatedAt = Date.now();
    meta.lastVerifiedAt = updatedAt;
    recomputeMeta();
    persist();
    return stats();
  }

  function verify(integrityId, inputs, actor) {
    const rec = byIntegrityId.get(integrityId);
    if (!rec) return { ok: false, error: "Unknown evidence" };
    // ensure newest evidence is registered so a single verify is accurate
    register(inputs, actor);
    const curMap = currentEvidenceMap(inputs);
    const status = verifyRecord(rec, curMap, actor);
    updatedAt = Date.now();
    meta.lastVerifiedAt = updatedAt;
    recomputeMeta();
    persist();
    return { ok: true, integrityId, verificationStatus: status, record: slim(rec) };
  }

  /* ------------------------------ exports ------------------------------- */

  // Register an export file as evidence (chain-of-custody: created + exported).
  // Called by main.js after any engine writes an export to disk.
  function recordExport(info, actor) {
    const filePath = info.filePath || info.source || "";
    let hash = info.sha256;
    let size = info.size;
    if (!hash) {
      try { const buf = fs.readFileSync(filePath); hash = sha256(buf); size = buf.length; } catch { hash = ""; }
    }
    const now = Date.now();
    const evidenceId = "exp_" + sha256(`${filePath}|${now}`).slice(0, 20);
    const rec = {
      integrityId: integrityIdFor("export", evidenceId),
      evidenceId,
      evidenceType: "export",
      label: `${info.sourceEngine || "report"} ${info.format || ""} export`.trim(),
      source: filePath,
      sha256: hash,
      currentSha256: hash,
      createdAt: now,
      baselineAt: now,
      verifiedAt: now,
      verificationStatus: hash ? "VALID" : "UNKNOWN",
      relatedEvidenceIds: (info.relatedEvidenceIds || []).slice(0, MAX_RELATED),
      size: size != null ? size : null,
      custodyCount: 0,
      lastAction: null,
      lastActor: null,
    };
    records.push(rec);
    byKey.set(evKey("export", evidenceId), rec);
    byIntegrityId.set(rec.integrityId, rec);
    addCustody(rec, "created", hash, actor, "export baseline registered");
    addCustody(rec, "exported", hash, actor, `exported to ${path.basename(filePath)}`);
    updatedAt = now;
    recomputeMeta();
    persist();
    return slim(rec);
  }

  /* --------------------------- query / detail --------------------------- */

  function recomputeMeta() {
    const byStatus = { VALID: 0, MODIFIED: 0, MISSING: 0, UNKNOWN: 0 };
    const byType = {};
    for (const r of records) {
      byStatus[r.verificationStatus] = (byStatus[r.verificationStatus] || 0) + 1;
      byType[r.evidenceType] = (byType[r.evidenceType] || 0) + 1;
    }
    meta = {
      built: records.length > 0,
      updatedAt,
      total: records.length,
      custodyCount: custody.length,
      byStatus, byType,
      lastVerifiedAt: meta.lastVerifiedAt || 0,
    };
  }

  function slim(r) {
    const { ...rest } = r;
    return rest;
  }

  function matches(r, f) {
    if (f.evidenceType && r.evidenceType !== f.evidenceType) return false;
    if (f.verificationStatus && r.verificationStatus !== f.verificationStatus) return false;
    if (f.q) {
      const q = String(f.q).toLowerCase();
      const hay = `${r.label} ${r.evidenceId} ${r.source} ${r.evidenceType} ${r.sha256}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function list(f = {}) {
    let rows = records.filter((r) => matches(r, f));
    rows.sort((a, b) => (b.verifiedAt || b.createdAt || 0) - (a.verifiedAt || a.createdAt || 0));
    const total = rows.length;
    const limit = Math.min(Number(f.limit) || 500, 5000);
    const offset = Number(f.offset) || 0;
    return { rows: rows.slice(offset, offset + limit).map(slim), total, built: meta.built, updatedAt };
  }

  function detail(integrityId) {
    const r = byIntegrityId.get(integrityId);
    if (!r) return null;
    const chain = custody.filter((c) => c.integrityId === integrityId)
      .sort((a, b) => a.ts - b.ts);
    const related = (r.relatedEvidenceIds || [])
      .map((eid) => records.find((x) => x.evidenceId === eid))
      .filter(Boolean)
      .map((x) => ({ integrityId: x.integrityId, evidenceId: x.evidenceId, evidenceType: x.evidenceType, label: x.label, verificationStatus: x.verificationStatus }));
    return { record: slim(r), custody: chain, related };
  }

  function listCustody(f = {}) {
    let rows = [...custody];
    if (f.evidenceId) rows = rows.filter((c) => c.evidenceId === f.evidenceId);
    if (f.integrityId) rows = rows.filter((c) => c.integrityId === f.integrityId);
    if (f.action) rows = rows.filter((c) => c.action === f.action);
    rows.sort((a, b) => b.ts - a.ts);
    const limit = Math.min(Number(f.limit) || 1000, 10000);
    return { rows: rows.slice(0, limit), total: rows.length };
  }

  function exportData(f = {}) {
    const rows = records.filter((r) => matches(r, f));
    const ids = new Set(rows.map((r) => r.integrityId));
    const chain = custody.filter((c) => ids.has(c.integrityId));
    return { meta, updatedAt, generatedAt: Date.now(), filter: f || {}, records: rows, custody: chain };
  }

  function stats() { return { ...meta, updatedAt }; }
  function filters() {
    return {
      evidenceTypes: Object.keys(meta.byType).sort(),
      statuses: STATUSES.filter((s) => meta.byStatus[s]),
      total: meta.total, built: meta.built, updatedAt,
      lastVerifiedAt: meta.lastVerifiedAt || 0,
    };
  }

  function clear() {
    records = []; custody = []; meta = emptyMeta(); updatedAt = 0;
    byKey = new Map(); byIntegrityId = new Map();
    try { fs.writeFileSync(sidecarPath, JSON.stringify({ version: FORMAT_VERSION, updatedAt: 0, meta, records: [], custody: [] }, null, 2)); } catch { /* ignore */ }
    return { ok: true };
  }

  return {
    register, verify, verifyAll, recordExport,
    list, detail, listCustody, exportData, stats, filters, clear,
    actor: ACTOR, sidecarPath,
  };
}

module.exports = { createIntegrityEngine, ACTIONS, STATUSES };
