// cache.js
// Cache Forensics Engine.
//
// Transforms browser cache artifacts into a dedicated forensic investigation
// capability. The PRIMARY data source is the existing acquisition output:
//   * acquired "serviceworker" records  -> Service Worker cache analysis
//   * acquired "favicon" records         -> cached-resource (favicon) analysis
// In addition, when an acquisition run's profile path is still present on this
// host, the engine performs METADATA-ONLY extraction of the on-disk HTTP /
// Code / GPU / Service-Worker caches (Chromium Simple Cache entry headers and
// Firefox cache2 entry keys). This reads cache keys/URLs, response headers,
// status codes, timestamps, sizes and source paths only. It never extracts
// cached page content, never recovers deleted entries and never performs file
// carving. If the path is gone, analysis proceeds from acquisition artifacts.
//
// Storage mirrors the rest of the project's derived data (findings.json,
// graph.json, acquisitions.json, timeline.json, extensions.json): a single JSON
// sidecar (cache.json) in the data directory. No database schema changes, no
// modifications to existing tables or acquisition/timeline/extension schemas.
//
// Every Cache Finding contains: findingId, cacheId, severity, reason, evidence, ts.
// Every Cache Profile contains: cacheId, riskScore, riskLevel, entryCount,
// totalSize, domainCount, findingCount (+ additive fields and the correlation
// stores relatedTimelineIds[] / relatedFindingIds[]).
//
// Cache entries are designed for forward compatibility: each carries sourcePath,
// size and sha256/hashScope placeholders (for a future Evidence Integrity
// Engine), deterministic ids (for the Reporting Engine) and domain/ioc tags
// (for Advanced Threat Hunting).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const risk = require("./risk");

const SIDECAR = "cache.json";
const FORMAT_VERSION = 1;

const DAY = 86400000;
const MAX_RELATED = 200;
const MAX_SNAPSHOT = 60;
const MAX_ENTRIES_STORED = 500;       // per-profile stored entry snapshot
const MAX_ENTRIES_PER_DIR = 4000;     // bound disk scan per cache directory
const HEADER_SCAN_BYTES = 65536;      // bounded read window for keys/headers
const MAX_KEY_LEN = 8192;

// ---- severity scale (matches findings/timeline/extension vocabulary) ----
const SEVERITY_RANK = { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];
const SCORE_WEIGHT = { INFO: 1, MEDIUM: 5, HIGH: 15, CRITICAL: 40 };
function sevRank(s) { return SEVERITY_RANK[s] != null ? SEVERITY_RANK[s] : 0; }
function maxSeverity(a, b) { return sevRank(a) >= sevRank(b) ? a : b; }

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const EXECUTABLE_CT = new Set([
  "application/x-msdownload", "application/x-msdos-program", "application/octet-stream",
  "application/vnd.microsoft.portable-executable", "application/x-executable",
  "application/x-dosexec", "application/java-archive", "application/x-sh",
]);
const SCRIPT_CT = new Set([
  "application/javascript", "text/javascript", "application/x-javascript",
  "module", "application/ecmascript", "text/ecmascript",
]);

const EXT_CT = {
  js: "application/javascript", mjs: "application/javascript", json: "application/json",
  css: "text/css", html: "text/html", htm: "text/html",
  png: "image/png", jpg: "image/jpeg", jpeg: "image/jpeg", gif: "image/gif",
  webp: "image/webp", svg: "image/svg+xml", ico: "image/x-icon",
  woff: "font/woff", woff2: "font/woff2", ttf: "font/ttf",
  wasm: "application/wasm", mp4: "video/mp4", webm: "video/webm",
  exe: "application/x-msdownload", dll: "application/x-msdownload",
  msi: "application/x-msdownload", crx: "application/x-chrome-extension",
  xpi: "application/x-xpinstall", jar: "application/java-archive",
  zip: "application/zip", pdf: "application/pdf",
};

function nd(v) { return risk.normalizeDomain(v) || ""; }
function lc(s) { return String(s == null ? "" : s).toLowerCase(); }

function extOf(u) {
  const m = lc(u).match(/\.([a-z0-9]+)(?:[?#]|$)/);
  return m ? m[1] : "";
}
function ctFromUrl(u) { return EXT_CT[extOf(u)] || ""; }

function cacheIdFor(parts) {
  return "cache_" + crypto.createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 20);
}
function entryIdFor(cacheId, key) {
  return "ce_" + crypto.createHash("sha256").update(`${cacheId}|${key}`).digest("hex").slice(0, 20);
}
function cacheFindingId(cacheId, reason) {
  return "cf_" + crypto.createHash("sha256").update(`${cacheId}|${reason}`).digest("hex").slice(0, 20);
}

/* ---------------------- on-disk metadata extraction --------------------- */
// All reads here are METADATA ONLY: cache keys/URLs, response header blocks,
// status codes, timestamps and sizes. No cached body bytes are emitted.

const SIMPLE_MAGIC_LO = 0xa7725c30;   // low 32 bits of 0xfcfb6d1ba7725c30
const SIMPLE_MAGIC_HI = 0xfcfb6d1b;   // high 32 bits

function statSafe(p) { try { return fs.statSync(p); } catch { return null; } }

function readChunk(fd, position, length) {
  const buf = Buffer.allocUnsafe(length);
  try {
    const n = fs.readSync(fd, buf, 0, length, position);
    return buf.subarray(0, n);
  } catch { return Buffer.alloc(0); }
}

// Extract the resource URL from a Chromium cache key (which may be double-keyed,
// e.g. "_dk_https://top https://resource" or "1/0/https://resource").
function urlFromCacheKey(key) {
  if (!key) return "";
  const matches = key.match(/https?:\/\/[^\s\0]+/gi);
  if (matches && matches.length) return matches[matches.length - 1];
  return "";
}

// Parse a serialized HTTP response header block (status line + NUL/CRLF
// separated header lines) from a bounded buffer. Returns null if not found.
function parseResponseHeaders(buf) {
  const text = buf.toString("latin1");
  const idx = text.search(/HTTP\/\d\.\d\s+\d{3}/);
  if (idx < 0) return null;
  // header strings are separated by NUL in the chromium pickle, or CRLF on disk
  const region = text.slice(idx, idx + 8192);
  const parts = region.split(/\0|\r\n/).map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return null;
  const statusM = parts[0].match(/HTTP\/\d\.\d\s+(\d{3})/);
  const statusCode = statusM ? Number(statusM[1]) : null;
  const headers = {};
  const want = new Set(["content-type", "content-length", "location", "date",
    "expires", "last-modified", "cache-control", "etag", "server", "content-encoding"]);
  for (let i = 1; i < parts.length && i < 60; i++) {
    const c = parts[i].indexOf(":");
    if (c <= 0) continue;
    const name = parts[i].slice(0, c).trim().toLowerCase();
    const value = parts[i].slice(c + 1).trim();
    if (want.has(name) && headers[name] == null) headers[name] = value.slice(0, 400);
  }
  return { statusCode, headers };
}

function httpDateToMs(v) {
  if (!v) return null;
  const t = Date.parse(v);
  return Number.isFinite(t) ? t : null;
}

// Read one Chromium Simple Cache entry file (metadata only).
function readSimpleEntry(filePath, st) {
  let fd = null;
  try {
    fd = fs.openSync(filePath, "r");
    const head = readChunk(fd, 0, Math.min(st.size, HEADER_SCAN_BYTES));
    if (head.length < 24) return null;
    if (head.readUInt32LE(0) !== SIMPLE_MAGIC_LO || head.readUInt32LE(4) !== SIMPLE_MAGIC_HI) {
      return null; // not a simple-cache entry
    }
    const keyLen = head.readUInt32LE(12);
    if (keyLen <= 0 || keyLen > MAX_KEY_LEN) return null;
    const keyEnd = 20 + keyLen;
    let key;
    if (keyEnd <= head.length) key = head.subarray(20, keyEnd).toString("latin1");
    else key = readChunk(fd, 20, Math.min(keyLen, MAX_KEY_LEN)).toString("latin1");
    key = key.replace(/\0+$/, "");

    // Response headers (stream 0) live near the end of the file.
    let resp = null;
    const tailLen = Math.min(st.size, HEADER_SCAN_BYTES);
    const tail = readChunk(fd, Math.max(0, st.size - tailLen), tailLen);
    resp = parseResponseHeaders(tail);

    const url = urlFromCacheKey(key);
    const headers = (resp && resp.headers) || {};
    const contentType = (headers["content-type"] || "").split(";")[0].trim() || ctFromUrl(url);
    return {
      url, key,
      contentType,
      statusCode: resp ? resp.statusCode : null,
      headers,
      requestTime: null,
      responseTime: httpDateToMs(headers["date"]),
      cacheTime: Math.round(st.mtimeMs),
      expireTime: httpDateToMs(headers["expires"]),
      size: st.size,
      sourcePath: filePath,
    };
  } catch {
    return null;
  } finally {
    if (fd != null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
}

// Firefox cache2 entry: [data][metadata]. The original URL key lives in the
// metadata trailer. Read a bounded tail and recover the key (metadata only).
function readCache2Entry(filePath, st) {
  let fd = null;
  try {
    fd = fs.openSync(filePath, "r");
    const tailLen = Math.min(st.size, HEADER_SCAN_BYTES);
    const tail = readChunk(fd, Math.max(0, st.size - tailLen), tailLen);
    const text = tail.toString("latin1");
    const m = text.match(/https?:\/\/[^\s\0]+/i);
    const url = m ? m[0].replace(/[^\x20-\x7e].*$/, "") : "";
    const resp = parseResponseHeaders(tail);
    const headers = (resp && resp.headers) || {};
    const contentType = (headers["content-type"] || "").split(";")[0].trim() || ctFromUrl(url);
    return {
      url, key: url || path.basename(filePath),
      contentType,
      statusCode: resp ? resp.statusCode : null,
      headers,
      requestTime: null,
      responseTime: httpDateToMs(headers["date"]),
      cacheTime: Math.round(st.mtimeMs),
      expireTime: httpDateToMs(headers["expires"]),
      size: st.size,
      sourcePath: filePath,
    };
  } catch {
    return null;
  } finally {
    if (fd != null) { try { fs.closeSync(fd); } catch { /* ignore */ } }
  }
}

// Walk a cache directory, returning metadata entries (bounded). `kind` selects
// the per-file parser. Files that are not parseable entries are still counted
// (size/path) so totals stay meaningful — no body content is read.
function scanCacheDir(dir, kind) {
  const out = [];
  const stRoot = statSafe(dir);
  if (!stRoot || !stRoot.isDirectory()) return out;
  let names = [];
  try { names = fs.readdirSync(dir); } catch { return out; }
  for (const name of names) {
    if (out.length >= MAX_ENTRIES_PER_DIR) break;
    if (name === "index" || name === "index-dir" || name === "the-real-index") continue;
    const fp = path.join(dir, name);
    const st = statSafe(fp);
    if (!st || !st.isFile()) continue;
    let entry = null;
    if (kind === "simple") entry = readSimpleEntry(fp, st);
    else if (kind === "cache2") entry = readCache2Entry(fp, st);
    if (!entry) {
      // inventory-only fallback (size/path/mtime), no content read
      entry = {
        url: "", key: name, contentType: ctFromUrl(name), statusCode: null, headers: {},
        requestTime: null, responseTime: null, cacheTime: Math.round(st.mtimeMs),
        expireTime: null, size: st.size, sourcePath: fp,
      };
    }
    out.push(entry);
  }
  return out;
}

// Resolve the on-disk cache directories for an acquisition run's profile path.
function cacheDirsFor(run) {
  const base = run && run.profilePath;
  if (!base || !statSafe(base)) return [];
  const family = run.browserFamily === "gecko" ? "gecko" : "chromium";
  const dirs = [];
  const add = (cacheType, rel, kind) => {
    const p = path.join(base, ...rel.split("/"));
    if (statSafe(p)) dirs.push({ cacheType, dir: p, kind });
  };
  if (family === "gecko") {
    add("http", "cache2/entries", "cache2");
  } else {
    add("http", "Cache/Cache_Data", "simple");
    add("http", "Cache", "simple");
    add("code", "Code Cache/js", "simple");
    add("code", "Code Cache/wasm", "simple");
    add("gpu", "GPUCache", "simple");
    add("serviceworker", "Service Worker/ScriptCache", "simple");
  }
  // De-dupe (Cache vs Cache/Cache_Data may both resolve).
  const seen = new Set();
  return dirs.filter((d) => (seen.has(d.dir) ? false : (seen.add(d.dir), true)));
}

/* =============================== engine ================================= */

function createCacheEngine(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);

  /** @type {object[]} */ let profiles = [];
  /** @type {object[]} */ let findings = [];
  let meta = emptyMeta();
  let scannedAt = 0;
  let byId = new Map();

  load();

  function emptyMeta() {
    return {
      scanned: false, scannedAt: 0,
      total: 0, findingCount: 0, entryTotal: 0, sizeTotal: 0,
      byRiskLevel: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 },
      byType: {}, byBrowser: {}, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 },
      correlated: 0, diskExtracted: 0,
    };
  }

  function load() {
    if (!fs.existsSync(sidecarPath)) return;
    try {
      const saved = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
      profiles = Array.isArray(saved.profiles) ? saved.profiles : [];
      findings = Array.isArray(saved.findings) ? saved.findings : [];
      meta = saved.meta || emptyMeta();
      scannedAt = saved.scannedAt || 0;
      reindex();
    } catch {
      profiles = []; findings = []; meta = emptyMeta(); scannedAt = 0; byId = new Map();
    }
  }
  function reindex() { byId = new Map(); for (const p of profiles) byId.set(p.cacheId, p); }

  function persist() {
    fs.writeFileSync(sidecarPath, JSON.stringify({
      version: FORMAT_VERSION, scannedAt, meta, profiles, findings,
    }, null, 2));
  }

  /* ------------------------------ scan ---------------------------------- */
  // inputs = { runs:[{run, swRecords, faviconRecords}], timelineEntries,
  //            findings, extensions, ioc }
  function scan(inputs = {}) {
    const runs = inputs.runs || [];
    const timelineEntries = inputs.timelineEntries || [];
    const behavioral = inputs.findings || [];
    const exts = inputs.extensions || [];
    const ioc = inputs.ioc || null;

    const iocExecutable = (u) => ioc ? ioc.isExecutable(u) : (risk.EXECUTABLE_RE.test(lc(u)));
    const iocTracker = (d) => ioc ? ioc.isTracker(d) : risk.isTracker(d);
    const iocSuspDomain = (d) => ioc ? ioc.isSuspiciousDomain(d) : false;
    const iocSuspTld = (d) => ioc ? ioc.isSuspiciousTld(d) : risk.suspiciousTld(d);
    const iocMatch = (d) => ioc ? ioc.matchDomain(d) : [];

    // Build the cache stores (profiles + entries) from each run.
    const stores = [];
    let diskExtracted = 0;

    for (const r of runs) {
      const run = r.run || {};
      const swRecords = r.swRecords || [];
      const faviconRecords = r.faviconRecords || [];
      const tag = { browser: run.browser || "", browserFamily: run.browserFamily || "",
        profile: run.profile || "", host: run.host || "", runId: run.runId || "",
        acquiredAt: run.acquiredAt != null ? run.acquiredAt : run.finishedAt };

      // (a) Service Worker caches (primary, from acquisition records)
      const swByScope = new Map();
      for (const rec of swRecords) {
        const a = rec.attributes || {};
        const scope = a.scope || rec.title || rec.domain || "";
        const key = scope || rec.eventId;
        const bucket = swByScope.get(key) || { scope, swRecords: [] };
        bucket.swRecords.push(rec);
        swByScope.set(key, bucket);
      }
      for (const [scope, bucket] of swByScope) {
        const cacheId = cacheIdFor([tag.runId, "serviceworker", scope]);
        const entries = [];
        const relatedSwEventIds = [];
        let updTs = null;
        for (const rec of bucket.swRecords) {
          const a = rec.attributes || {};
          if (rec.eventId) relatedSwEventIds.push(rec.eventId);
          if (a.lastUpdateTime != null) updTs = Math.max(updTs || 0, a.lastUpdateTime);
          else if (rec.ts != null) updTs = Math.max(updTs || 0, rec.ts);
          const scriptUrl = a.scriptUrl || rec.url || "";
          entries.push(mkEntry(cacheId, {
            url: scriptUrl, key: `sw:${scope}`, contentType: "application/javascript",
            statusCode: null, headers: {}, cacheTime: rec.ts, responseTime: a.lastUpdateTime || rec.ts,
            expireTime: null, size: 0, sourcePath: a.sourcePath || "", origin: "serviceworker",
          }));
        }
        // optional on-disk CacheStorage inventory for this run (resources)
        stores.push({
          tag, cacheType: "serviceworker", cacheName: scope, scope,
          cacheId, entries, relatedSwEventIds, updateTime: updTs,
        });
      }

      // CacheStorage directory (all SW cache names) — disk inventory if present
      if (run.profilePath && run.browserFamily !== "gecko") {
        const csRoot = path.join(run.profilePath, "Service Worker", "CacheStorage");
        if (statSafe(csRoot)) {
          let originDirs = [];
          try { originDirs = fs.readdirSync(csRoot); } catch { originDirs = []; }
          for (const od of originDirs.slice(0, 200)) {
            const odPath = path.join(csRoot, od);
            const stOd = statSafe(odPath);
            if (!stOd || !stOd.isDirectory()) continue;
            const cacheId = cacheIdFor([tag.runId, "serviceworker-storage", od]);
            const entries = scanCacheDir(odPath, "simple")
              .map((e) => mkEntry(cacheId, { ...e, origin: "serviceworker" }));
            if (entries.length) {
              diskExtracted += entries.length;
              stores.push({ tag, cacheType: "serviceworker", cacheName: `CacheStorage/${od}`, scope: "", cacheId, entries, relatedSwEventIds: [], updateTime: null });
            }
          }
        }
      }

      // (b) Favicon cache (primary, from acquisition records)
      if (faviconRecords.length) {
        const cacheId = cacheIdFor([tag.runId, "favicon", "favicons"]);
        const entries = faviconRecords.map((rec) => {
          const a = rec.attributes || {};
          const iconUrl = a.iconUrl || rec.url || "";
          return mkEntry(cacheId, {
            url: iconUrl, key: iconUrl || rec.url || rec.eventId,
            contentType: ctFromUrl(iconUrl) || "image/x-icon", statusCode: null,
            headers: a.width ? { "x-dimensions": `${a.width}x${a.height || ""}` } : {},
            cacheTime: rec.ts, responseTime: rec.ts, expireTime: null,
            size: 0, sourcePath: "", origin: "favicon",
          });
        });
        stores.push({ tag, cacheType: "favicon", cacheName: "favicons", scope: "", cacheId, entries, relatedSwEventIds: [], updateTime: null });
      }

      // (c) On-disk HTTP / Code / GPU caches (metadata-only extraction)
      for (const cd of cacheDirsFor(run)) {
        const cacheId = cacheIdFor([tag.runId, cd.cacheType, cd.dir]);
        const raw = scanCacheDir(cd.dir, cd.kind);
        if (!raw.length) continue;
        diskExtracted += raw.length;
        const entries = raw.map((e) => mkEntry(cacheId, { ...e, origin: cd.cacheType }));
        stores.push({ tag, cacheType: cd.cacheType, cacheName: path.basename(cd.dir), scope: "", cacheId, entries, relatedSwEventIds: [], updateTime: null, sourcePath: cd.dir });
      }
    }

    // Pre-index correlation sources.
    const tlByDomain = new Map();
    const tlSwByDomain = new Map();
    for (const e of timelineEntries) {
      if (e.domain) (tlByDomain.get(e.domain) || tlByDomain.set(e.domain, []).get(e.domain)).push(e);
      if (e.category === "serviceworker" && e.domain) {
        (tlSwByDomain.get(e.domain) || tlSwByDomain.set(e.domain, []).get(e.domain)).push(e);
      }
    }
    const extByDomain = new Map();
    for (const x of exts) {
      const ds = (x.permissionsSummary && x.permissionsSummary.domains) || [];
      for (const d of ds) (extByDomain.get(d) || extByDomain.set(d, []).get(d)).push(x);
    }

    const allProfiles = [];
    const allFindings = [];

    for (const store of stores) {
      const assessed = assess(store, { iocExecutable, iocTracker, iocSuspDomain, iocSuspTld, iocMatch });
      const prof = assessed.profile;
      for (const f of assessed.findings) allFindings.push(f);

      // ----- correlation -----
      const domains = prof.domains || [];
      const domSet = new Set(domains);
      const relatedTimeline = new Set();
      const relatedSw = new Set();
      const snapshot = [];

      for (const d of domains) {
        for (const e of (tlSwByDomain.get(d) || [])) {
          relatedTimeline.add(e.timelineId); relatedSw.add(e.timelineId);
          pushSnap(snapshot, e, "serviceworker");
        }
        for (const e of (tlByDomain.get(d) || [])) {
          if (relatedTimeline.size >= MAX_RELATED) break;
          relatedTimeline.add(e.timelineId);
          pushSnap(snapshot, e, "domain");
        }
      }

      const relatedExt = new Set();
      const extSnap = [];
      for (const d of domains) {
        for (const x of (extByDomain.get(d) || [])) {
          relatedExt.add(x.extensionId);
          if (extSnap.length < MAX_SNAPSHOT) extSnap.push({ extensionId: x.extensionId, name: x.name, riskLevel: x.riskLevel });
        }
      }
      // chrome-extension:// cache keys -> extension id
      for (const e of prof.entries) {
        const m = lc(e.url || e.key).match(/chrome-extension:\/\/([a-p]{32})/);
        if (m) {
          relatedExt.add(m[1]);
          if (extSnap.length < MAX_SNAPSHOT && !extSnap.some((s) => s.extensionId === m[1])) {
            extSnap.push({ extensionId: m[1], name: "(by cache key)", riskLevel: "INFO" });
          }
        }
      }

      const relatedFindings = new Set();
      const findingSnap = [];
      for (const f of behavioral) {
        const affected = f.affectedDomains || [];
        if (affected.some((d) => domSet.has(nd(d)) || domSet.has(d))) {
          relatedFindings.add(f.id);
          if (findingSnap.length < MAX_SNAPSHOT) findingSnap.push({ id: f.id, severity: f.severity, title: f.title, lastSeen: f.lastSeen });
        }
      }

      prof.relatedTimelineIds = [...relatedTimeline].slice(0, MAX_RELATED);
      prof.relatedServiceWorkerIds = [...relatedSw];
      prof.relatedExtensionIds = [...relatedExt];
      prof.relatedFindingIds = [...relatedFindings];
      prof.relatedTimeline = snapshot.slice(0, MAX_SNAPSHOT);
      prof.relatedExtensions = extSnap;
      prof.relatedFindings = findingSnap;
      prof.correlation = {
        domains, timelineLinks: prof.relatedTimelineIds.length,
        serviceWorkerLinks: prof.relatedServiceWorkerIds.length,
        extensionLinks: prof.relatedExtensionIds.length,
        findingLinks: prof.relatedFindingIds.length,
      };

      allProfiles.push(prof);
    }

    allProfiles.sort((a, b) =>
      (sevRank(b.riskLevel) - sevRank(a.riskLevel)) || (b.riskScore - a.riskScore) ||
      (b.entryCount - a.entryCount));
    allFindings.sort((a, b) =>
      (sevRank(b.severity) - sevRank(a.severity)) || (b.ts || 0) - (a.ts || 0));

    profiles = allProfiles;
    findings = allFindings;
    scannedAt = Date.now();
    meta = computeMeta(profiles, findings, scannedAt, diskExtracted);
    reindex();
    persist();
    return meta;
  }

  function mkEntry(cacheId, e) {
    const url = e.url || "";
    const domain = nd(url) || nd(e.key) || "";
    const key = e.key || url;
    return {
      entryId: entryIdFor(cacheId, key),
      cacheId,
      origin: e.origin || "",
      url,
      key,
      domain,
      contentType: e.contentType || "",
      statusCode: e.statusCode != null ? e.statusCode : null,
      headers: e.headers || {},
      requestTime: e.requestTime != null ? e.requestTime : null,
      responseTime: e.responseTime != null ? e.responseTime : null,
      cacheTime: e.cacheTime != null ? e.cacheTime : null,
      expireTime: e.expireTime != null ? e.expireTime : null,
      size: Number(e.size) || 0,
      sourcePath: e.sourcePath || "",
      // forward-compat: Evidence Integrity hashing hooks (computed by that engine)
      sha256: null,
      hashScope: "none",
      tags: [],
    };
  }

  function pushSnap(arr, e, relation) {
    if (arr.length >= MAX_SNAPSHOT) return;
    arr.push({
      timelineId: e.timelineId, ts: e.ts, sourceType: e.sourceType,
      category: e.category, severity: e.severity, title: e.title, domain: e.domain, relation,
    });
  }

  /* --------------------------- risk assessment -------------------------- */

  function assess(store, helpers) {
    const { iocExecutable, iocTracker, iocSuspDomain, iocSuspTld, iocMatch } = helpers;
    const entries = store.entries || [];
    const ref = store.tag.acquiredAt || Date.now();
    const out = [];
    const have = new Set();
    const add = (reason, severity, evidence, ts) => {
      if (have.has(reason)) {
        // keep the highest severity / earliest evidence per reason
        const prev = out.find((f) => f.reason === reason);
        if (prev && sevRank(severity) > sevRank(prev.severity)) { prev.severity = severity; prev.evidence = evidence; }
        return;
      }
      have.add(reason);
      out.push({
        findingId: cacheFindingId(store.cacheId, reason),
        cacheId: store.cacheId, severity, reason,
        evidence: evidence || "", ts: ts != null ? ts : ref,
      });
    };

    const domains = new Set();
    let totalSize = 0;
    let redirectCount = 0;
    const redirectByDomain = new Map();
    let trackerCount = 0;

    for (const e of entries) {
      totalSize += e.size || 0;
      if (e.domain) domains.add(e.domain);
      const url = e.url || e.key || "";
      const ct = lc(e.contentType);
      const ext = extOf(url);
      const dom = e.domain;
      const iocHits = dom ? iocMatch(dom) : [];

      // tracker cache artifact
      if (dom && iocTracker(dom)) { trackerCount++; e.tags.push("tracker"); }

      // known IOC cache artifact
      if (dom && (iocHits.length || iocSuspDomain(dom))) {
        e.tags.push("ioc");
        add("known-ioc-cache-artifact",
          iocSuspDomain(dom) ? "CRITICAL" : "HIGH",
          `cached resource from flagged domain ${dom}${iocHits.length ? " [" + iocHits.join(",") + "]" : ""}`,
          e.cacheTime);
      }

      // suspicious cached executable
      if (iocExecutable(url) || EXECUTABLE_CT.has(ct)) {
        e.tags.push("executable");
        const susp = dom && (iocSuspDomain(dom) || iocSuspTld(dom));
        add("suspicious-cached-executable", susp ? "CRITICAL" : "HIGH",
          `executable cache entry ${url || e.key} (${ct || ext || "?"})`, e.cacheTime);
      }

      // suspicious script caching
      const isScript = SCRIPT_CT.has(ct) || ext === "js" || ext === "mjs";
      if (isScript && dom && (iocTracker(dom) || iocSuspTld(dom) || iocSuspDomain(dom))) {
        add("suspicious-script-caching", iocSuspDomain(dom) ? "HIGH" : "MEDIUM",
          `script cached from ${dom}: ${url}`, e.cacheTime);
      }

      // suspicious content types / mismatch
      if (ct === "application/java-archive" || ct === "application/x-shockwave-flash") {
        add("suspicious-content-type", "HIGH", `dangerous content-type ${ct}: ${url}`, e.cacheTime);
      } else if (ext && ct) {
        const expected = EXT_CT[ext];
        if (expected && expected.split("/")[0] !== ct.split("/")[0] &&
          !(expected === "application/javascript" && ct.startsWith("text/"))) {
          add("suspicious-content-type", "MEDIUM",
            `content-type ${ct} mismatches .${ext}: ${url}`, e.cacheTime);
        }
      }

      // suspicious update URL
      if (/(update|upgrade|\/dl\/|installer|setup)/i.test(url) &&
        (ext === "exe" || ext === "crx" || ext === "xpi" || ext === "msi" ||
          (dom && (iocSuspTld(dom) || iocSuspDomain(dom)))) ) {
        add("suspicious-update-url", dom && iocSuspDomain(dom) ? "CRITICAL" : "HIGH",
          `update/installer URL cached: ${url}`, e.cacheTime);
      }

      // redirect accounting
      if (e.statusCode != null && REDIRECT_STATUS.has(e.statusCode)) {
        redirectCount++;
        if (dom) redirectByDomain.set(dom, (redirectByDomain.get(dom) || 0) + 1);
      }
    }

    // excessive redirect chains
    let maxDomRedirect = 0; let maxDom = "";
    for (const [d, c] of redirectByDomain) if (c > maxDomRedirect) { maxDomRedirect = c; maxDom = d; }
    if (maxDomRedirect >= 5) {
      add("excessive-redirect-chain", "MEDIUM",
        `${maxDomRedirect} cached redirects for ${maxDom}`, ref);
    } else if (redirectCount >= 12) {
      add("excessive-redirect-chain", "MEDIUM",
        `${redirectCount} cached redirect responses`, ref);
    }

    // tracker volume escalation
    if (trackerCount >= 1) {
      add("tracker-cache-artifact", trackerCount >= 10 ? "MEDIUM" : "INFO",
        `${trackerCount} tracker/analytics cache artifact(s)`, ref);
    }

    // service worker persistence indicators
    if (store.cacheType === "serviceworker") {
      const scope = store.scope || store.cacheName || "";
      const sdom = nd(scope);
      const broad = /^https?:\/\/[^/]+\/?$/.test(scope) || scope === "" || /\/$/.test(scope);
      const persistent = entries.length > 0; // a registered/cached worker persists across sessions
      if (persistent) {
        const susp = sdom && (iocSuspDomain(sdom) || iocSuspTld(sdom) || iocTracker(sdom));
        add("service-worker-persistence-indicator", susp ? "HIGH" : (broad ? "MEDIUM" : "INFO"),
          `persistent service worker cache${scope ? " scope " + scope : ""}${broad ? " (broad scope)" : ""}`,
          store.updateTime || ref);
      }
    }

    // ----- score & level -----
    let score = 0; let level = "INFO";
    for (const f of out) { score += SCORE_WEIGHT[f.severity] || 0; level = maxSeverity(level, f.severity); }
    if (level !== "CRITICAL" && score >= 60) level = "CRITICAL";
    else if (sevRank(level) < sevRank("HIGH") && score >= 20) level = "HIGH";
    else if (sevRank(level) < sevRank("MEDIUM") && score >= 6) level = "MEDIUM";

    const domainList = [...domains];
    const storedEntries = entries.slice(0, MAX_ENTRIES_STORED);

    const profile = {
      cacheId: store.cacheId,
      cacheType: store.cacheType,
      cacheName: store.cacheName || store.cacheType,
      scope: store.scope || "",
      browser: store.tag.browser,
      browserFamily: store.tag.browserFamily,
      profile: store.tag.profile,
      host: store.tag.host,
      runId: store.tag.runId,
      sourcePath: store.sourcePath || "",
      acquiredAt: store.tag.acquiredAt,
      updateTime: store.updateTime || null,
      riskScore: score,
      riskLevel: level,
      entryCount: entries.length,
      totalSize,
      domainCount: domainList.length,
      domains: domainList,
      findingCount: out.length,
      relatedSwEventIds: store.relatedSwEventIds || [],
      entries: storedEntries,
      storedEntryCount: storedEntries.length,
      // correlation stores (filled by scan)
      relatedTimelineIds: [],
      relatedFindingIds: [],
    };
    return { profile, findings: out };
  }

  function computeMeta(profs, fnds, ts, diskExtracted) {
    const byRiskLevel = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
    const byType = {}; const byBrowser = {};
    let entryTotal = 0, sizeTotal = 0, correlated = 0;
    for (const p of profs) {
      byRiskLevel[p.riskLevel] = (byRiskLevel[p.riskLevel] || 0) + 1;
      byType[p.cacheType] = (byType[p.cacheType] || 0) + 1;
      if (p.browser) byBrowser[p.browser] = (byBrowser[p.browser] || 0) + 1;
      entryTotal += p.entryCount; sizeTotal += p.totalSize;
      if ((p.relatedTimelineIds || []).length || (p.relatedFindingIds || []).length ||
        (p.relatedExtensionIds || []).length) correlated++;
    }
    for (const f of fnds) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    return {
      scanned: true, scannedAt: ts,
      total: profs.length, findingCount: fnds.length, entryTotal, sizeTotal,
      byRiskLevel, bySeverity, byType, byBrowser, correlated, diskExtracted,
    };
  }

  /* --------------------------- query / detail --------------------------- */

  function matchesProfile(p, f) {
    if (f.riskLevel && p.riskLevel !== f.riskLevel) return false;
    if (f.cacheType && p.cacheType !== f.cacheType) return false;
    if (f.browser && p.browser !== f.browser) return false;
    if (f.correlatedOnly && !((p.relatedTimelineIds || []).length || (p.relatedFindingIds || []).length || (p.relatedExtensionIds || []).length)) return false;
    if (f.q) {
      const q = lc(f.q);
      const hay = lc(`${p.cacheName} ${p.cacheType} ${p.scope} ${(p.domains || []).join(" ")}`);
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function list(f = {}) {
    let rows = profiles.filter((p) => matchesProfile(p, f));
    if (f.minRisk) rows = rows.filter((p) => sevRank(p.riskLevel) >= sevRank(f.minRisk));
    const total = rows.length;
    const limit = Math.min(Number(f.limit) || 500, 5000);
    const offset = Number(f.offset) || 0;
    // Slim rows for the table (drop heavy entry arrays).
    const slim = rows.slice(offset, offset + limit).map(slimProfile);
    return { rows: slim, total, scanned: meta.scanned, scannedAt };
  }

  function slimProfile(p) {
    const { entries, relatedTimeline, relatedExtensions, relatedFindings, domains, ...rest } = p;
    return { ...rest, domainSample: (domains || []).slice(0, 8) };
  }

  function detail(cacheId) {
    const p = byId.get(cacheId);
    if (!p) return null;
    const cf = findings.filter((x) => x.cacheId === cacheId)
      .sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.ts || 0) - (a.ts || 0));
    return {
      profile: p,
      findings: cf,
      entries: (p.entries || []).slice(0, MAX_ENTRIES_STORED),
      relatedTimeline: p.relatedTimeline || [],
      relatedExtensions: p.relatedExtensions || [],
      relatedFindings: p.relatedFindings || [],
    };
  }

  function listFindings(f = {}) {
    let rows = [...findings];
    if (f.severity) rows = rows.filter((x) => x.severity === f.severity);
    if (f.cacheId) rows = rows.filter((x) => x.cacheId === f.cacheId);
    if (f.reason) rows = rows.filter((x) => x.reason.includes(f.reason));
    rows.sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.ts || 0) - (a.ts || 0));
    return { rows, total: rows.length };
  }

  function exportData(f = {}) {
    let rows = profiles.filter((p) => matchesProfile(p, f));
    if (f.minRisk) rows = rows.filter((p) => sevRank(p.riskLevel) >= sevRank(f.minRisk));
    const ids = new Set(rows.map((p) => p.cacheId));
    const fnds = findings.filter((x) => ids.has(x.cacheId));
    return { meta, scannedAt, generatedAt: Date.now(), filter: f || {}, profiles: rows, findings: fnds };
  }

  function stats() { return { ...meta, scannedAt }; }
  function filters() {
    return {
      browsers: Object.keys(meta.byBrowser).sort(),
      cacheTypes: Object.keys(meta.byType).sort(),
      riskLevels: SEVERITY_ORDER.filter((s) => meta.byRiskLevel[s]),
      total: meta.total, scanned: meta.scanned, scannedAt,
    };
  }

  function clear() {
    profiles = []; findings = []; meta = emptyMeta(); scannedAt = 0; byId = new Map();
    try { fs.writeFileSync(sidecarPath, JSON.stringify({ version: FORMAT_VERSION, scannedAt: 0, meta, profiles: [], findings: [] }, null, 2)); } catch { /* ignore */ }
    return { ok: true };
  }

  return {
    scan, list, detail, listFindings, exportData, stats, filters, clear,
    sidecarPath,
  };
}

module.exports = { createCacheEngine, SEVERITY_RANK, SEVERITY_ORDER };
