// acquire.js
// Read-only forensic acquisition engine.
//
// Guarantees (enforced throughout this file):
//   * READ-ONLY. Source browser files are never modified. SQLite databases are
//     copied to a temporary directory first (together with -wal/-shm/-journal
//     siblings); only the copy is opened, and only with SELECT / PRAGMA query_only.
//   * NEVER DECRYPT. Credential and cookie secret material is never read or
//     decrypted. For logins we record only the presence and byte-length of the
//     encrypted field; for cookies we record only the length of the value.
//   * SOFT-FAILURE. Each artifact is acquired independently inside a try/catch.
//     If one artifact fails, its error is recorded and acquisition continues.
//
// SQLite access uses the same strategy as the rest of the project: Node's
// built-in node:sqlite DatabaseSync. If that runtime is unavailable, SQLite
// artifacts soft-fail (recorded as an error) while JSON/inventory artifacts
// still succeed.
//
// All emitted timestamps are Unix epoch MILLISECONDS.

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const risk = require("./risk");

let DatabaseSync = null;
let sqliteLoadError = "";
try {
  ({ DatabaseSync } = require("node:sqlite"));
} catch (err) {
  sqliteLoadError = (err && err.message) || "node:sqlite unavailable";
}

/* --------------------------- time normalization --------------------------- */
// Chrome/WebKit time: microseconds since 1601-01-01. Firefox PRTime:
// microseconds since 1970-01-01. Some Firefox columns are seconds or ms.

const CHROME_EPOCH_OFFSET_MS = 11644473600000; // 1601-01-01 -> 1970-01-01 in ms

function chromeToMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.round(n / 1000) - CHROME_EPOCH_OFFSET_MS;
}
function mozMicroToMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.round(n / 1000);
}
function secToMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.round(n * 1000);
}
function asMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  return Math.round(n);
}
// Heuristic for extension install/update stamps that may arrive as ms or as
// Windows-epoch microseconds (Chromium Preferences stores the latter).
function flexibleStampToMs(v) {
  const n = Number(v);
  if (!Number.isFinite(n) || n <= 0) return null;
  if (n > 1e16) return chromeToMs(n);       // Windows-epoch microseconds
  if (n > 1e14) return Math.round(n / 1000); // unix microseconds
  return Math.round(n);                       // already milliseconds
}

/* ------------------------------ hashing utils ----------------------------- */

function sha256Buffer(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}
function sha256File(p, capBytes = Infinity) {
  const h = crypto.createHash("sha256");
  const fd = fs.openSync(p, "r");
  try {
    const buf = Buffer.allocUnsafe(1 << 20); // 1 MiB chunks
    let read = 0, total = 0;
    while ((read = fs.readSync(fd, buf, 0, buf.length, null)) > 0) {
      if (total + read > capBytes) {
        h.update(buf.subarray(0, capBytes - total));
        break;
      }
      h.update(buf.subarray(0, read));
      total += read;
    }
  } finally {
    fs.closeSync(fd);
  }
  return h.digest("hex");
}

function statSafe(p) {
  try { return fs.statSync(p); } catch { return null; }
}

// Deterministic directory digest: sha256 over sorted "rel\0size\0mtime\0fileSha"
// lines. File contents are hashed when within budget, otherwise size+mtime only
// (so very large stores stay cheap). Read-only; never enters symlinks.
function inventoryDir(dirPath, opts = {}) {
  const maxFiles = opts.maxFiles || 8000;
  const perFileHashCap = opts.perFileHashCap || (8 << 20); // 8 MiB
  const hashBudget = opts.hashBudget || (256 << 20);       // 256 MiB total
  const files = [];
  let bytes = 0;
  let hashedBytes = 0;

  function walk(dir, rel) {
    if (files.length >= maxFiles) return;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const ent of entries) {
      if (files.length >= maxFiles) break;
      if (ent.isSymbolicLink()) continue;
      const abs = path.join(dir, ent.name);
      const relPath = rel ? `${rel}/${ent.name}` : ent.name;
      if (ent.isDirectory()) { walk(abs, relPath); continue; }
      if (!ent.isFile()) continue;
      const st = statSafe(abs);
      if (!st) continue;
      let fileSha = "";
      if (st.size <= perFileHashCap && hashedBytes + st.size <= hashBudget) {
        try { fileSha = sha256File(abs); hashedBytes += st.size; } catch { fileSha = ""; }
      }
      files.push({ rel: relPath, size: st.size, mtime: Math.round(st.mtimeMs), sha256: fileSha });
      bytes += st.size;
    }
  }
  walk(dirPath, "");

  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  const digest = sha256Buffer(
    Buffer.from(files.map((f) => `${f.rel}\0${f.size}\0${f.mtime}\0${f.sha256}`).join("\n"), "utf8")
  );
  return { fileCount: files.length, bytes, sha256: digest, files };
}

/* --------------------------- safe SQLite reading -------------------------- */
// Copy a database (and its sidecars) into the run temp dir, then open the copy
// read-only. This guarantees the live source is never written to, even if the
// database is "hot" (WAL/SHM present) at acquisition time.

const SQLITE_SIDECARS = ["-wal", "-shm", "-journal"];

function copyForRead(srcMain, tmpDir) {
  fs.mkdirSync(tmpDir, { recursive: true });
  const base = path.basename(srcMain);
  const destMain = path.join(tmpDir, base);
  fs.copyFileSync(srcMain, destMain);
  for (const suffix of SQLITE_SIDECARS) {
    const sc = srcMain + suffix;
    if (statSafe(sc)) {
      try { fs.copyFileSync(sc, destMain + suffix); } catch { /* sidecar optional */ }
    }
  }
  return destMain;
}

function openReadonly(dbPath) {
  let db;
  try {
    db = new DatabaseSync(dbPath, { readOnly: true });
  } catch {
    // Older node:sqlite without the readOnly option — fall back, then lock down.
    db = new DatabaseSync(dbPath);
  }
  try { db.exec("PRAGMA query_only = TRUE;"); } catch { /* best effort */ }
  return db;
}

function tableExists(db, name) {
  try {
    const row = db.prepare(
      "SELECT 1 FROM sqlite_master WHERE type='table' AND name=? LIMIT 1"
    ).get(name);
    return !!row;
  } catch { return false; }
}

// Run a SELECT-only reader against a temporary copy of `srcMain`.
// Returns { rows, locked, copyPath } or throws (caught by the caller).
function withSqliteCopy(srcMain, tmpDir, fn) {
  if (!DatabaseSync) throw new Error(`SQLite runtime unavailable: ${sqliteLoadError}`);
  const locked = !!statSafe(srcMain + "-wal") || !!statSafe(srcMain + "-shm");
  const copyPath = copyForRead(srcMain, tmpDir);
  const db = openReadonly(copyPath);
  try {
    // Force the header/schema to be parsed: a non-SQLite or corrupt file throws
    // here, which surfaces as a recorded artifact error rather than a silent
    // empty result. A valid-but-empty database returns 0 and proceeds.
    db.prepare("SELECT count(*) FROM sqlite_master").get();
    const rows = fn(db);
    return { rows, locked, copyPath };
  } finally {
    try { db.close(); } catch { /* ignore */ }
  }
}

/* ------------------------- normalized record helper ----------------------- */

function domainFrom(value) {
  return risk.normalizeDomain(value || "") || "";
}

function makeAttributes(extra = {}) {
  return {
    relatedDomains: extra.relatedDomains || [],
    relatedUrls: extra.relatedUrls || [],
    ...extra,
  };
}

function eventIdFor(runId, artifactType, parts) {
  const key = [runId, artifactType, ...parts.map((p) => (p == null ? "" : String(p)))].join("|");
  return "ev_" + crypto.createHash("sha256").update(key).digest("hex").slice(0, 24);
}

function record(ctx, fields) {
  const url = fields.url || "";
  const domain = fields.domain != null ? fields.domain : domainFrom(url);
  const attributes = makeAttributes(fields.attributes || {});
  // Fold any related URLs' domains into relatedDomains for graph/timeline reuse.
  const relDomains = new Set(attributes.relatedDomains);
  for (const u of attributes.relatedUrls) {
    const d = domainFrom(u);
    if (d && d !== domain) relDomains.add(d);
  }
  attributes.relatedDomains = [...relDomains];
  return {
    eventId: eventIdFor(ctx.runId, ctx.artifactType, fields.idParts || [url, fields.ts, fields.type]),
    runId: ctx.runId,
    artifactId: ctx.artifactId,
    sourceArtifact: ctx.artifactType,
    type: fields.type,
    url,
    domain,
    title: fields.title || "",
    ts: fields.ts != null ? fields.ts : null,
    tsKind: fields.tsKind || "none",
    detail: fields.detail || "",
    attributes,
  };
}

function b64ByteLen(s) {
  if (!s || typeof s !== "string") return 0;
  const clean = s.replace(/[^A-Za-z0-9+/=]/g, "");
  const pad = (clean.match(/=+$/) || [""])[0].length;
  return Math.max(0, Math.floor(clean.length * 3 / 4) - pad);
}

function fileBaseFromUri(u) {
  if (!u) return "";
  try {
    if (u.startsWith("file:")) return path.basename(new URL(u).pathname);
  } catch { /* fall through */ }
  return path.basename(String(u));
}

const LIMIT = 50000; // per-table record cap (bounds memory & sidecar size)

/* ============================== READERS ================================== */
// Each reader returns { records, recordCount, locked, copied, copyPath, notes }.
// Readers assume `srcPath` exists (the dispatcher checks before calling).

/* ---- Chromium: history (urls table) ---- */
function readChromiumHistory(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "urls")) return [];
    return db.prepare(
      "SELECT url, title, visit_count, CAST(last_visit_time AS TEXT) AS last_visit_time FROM urls " +
      "WHERE url IS NOT NULL ORDER BY last_visit_time DESC LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "history",
    url: r.url,
    title: r.title || "",
    ts: chromeToMs(r.last_visit_time),
    tsKind: "last-visit",
    detail: `${r.title || r.url} · ${r.visit_count || 0} visit(s)`,
    idParts: [r.url, r.last_visit_time],
    attributes: { visitCount: r.visit_count || 0 },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Chromium: downloads (downloads + downloads_url_chains) ---- */
function readChromiumDownloads(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "downloads")) return [];
    const hasChains = tableExists(db, "downloads_url_chains");
    const chainSel = hasChains
      ? "(SELECT url FROM downloads_url_chains c WHERE c.id=d.id ORDER BY chain_index ASC LIMIT 1)"
      : "NULL";
    return db.prepare(
      `SELECT d.id, d.target_path, d.tab_url, d.referrer, d.total_bytes, ` +
      `CAST(d.start_time AS TEXT) AS start_time, CAST(d.end_time AS TEXT) AS end_time, ` +
      `d.mime_type, d.state, ${chainSel} AS chain_url ` +
      `FROM downloads d ORDER BY d.start_time DESC LIMIT ?`
    ).all(LIMIT);
  });
  const records = rows.map((r) => {
    const url = r.tab_url || r.chain_url || "";
    return record(ctx, {
      type: "download",
      url,
      title: fileBaseFromUri(r.target_path),
      ts: chromeToMs(r.start_time),
      tsKind: "download-start",
      detail: `${fileBaseFromUri(r.target_path) || "(file)"} · ${r.total_bytes || 0} bytes · ${r.mime_type || "?"}`,
      idParts: [r.id, r.target_path, r.start_time],
      attributes: {
        targetPath: r.target_path || "",
        bytes: r.total_bytes || 0,
        mimeType: r.mime_type || "",
        state: r.state,
        endTime: chromeToMs(r.end_time),
        relatedUrls: [r.chain_url, r.referrer].filter(Boolean),
      },
    });
  });
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Chromium: cookies (metadata + encrypted_value length only) ---- */
function readChromiumCookies(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "cookies")) return [];
    return db.prepare(
      "SELECT host_key, name, path, CAST(creation_utc AS TEXT) AS creation_utc, " +
      "CAST(expires_utc AS TEXT) AS expires_utc, CAST(last_access_utc AS TEXT) AS last_access_utc, " +
      "is_secure, is_httponly, samesite, is_persistent, length(encrypted_value) AS enc_len " +
      "FROM cookies LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => {
    const host = String(r.host_key || "").replace(/^\./, "");
    return record(ctx, {
      type: "cookie",
      url: "",
      domain: domainFrom(host) || host,
      title: r.name || "",
      ts: chromeToMs(r.creation_utc),
      tsKind: "cookie-created",
      detail: `${r.name || "?"} @ ${host}${r.is_secure ? " · secure" : ""}${r.is_httponly ? " · httpOnly" : ""}`,
      idParts: [host, r.name, r.path, r.creation_utc],
      attributes: {
        cookieName: r.name || "",
        cookiePath: r.path || "",
        secure: !!r.is_secure,
        httpOnly: !!r.is_httponly,
        sameSite: r.samesite,
        persistent: !!r.is_persistent,
        expires: chromeToMs(r.expires_utc),
        lastAccess: chromeToMs(r.last_access_utc),
        encryptedValuePresent: (r.enc_len || 0) > 0,
        encryptedValueLength: r.enc_len || 0, // length only — value never read
      },
    });
  });
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Chromium: bookmarks (Bookmarks JSON) ---- */
function readChromiumBookmarks(ctx, srcPath) {
  let json = null;
  try { json = JSON.parse(fs.readFileSync(srcPath, "utf8")); } catch { json = null; }
  const out = [];
  function walk(node, folder) {
    if (!node || typeof node !== "object") return;
    if (node.type === "url" && node.url) {
      out.push(record(ctx, {
        type: "bookmark",
        url: node.url,
        title: node.name || "",
        ts: chromeToMs(node.date_added),
        tsKind: "bookmark-added",
        detail: `${node.name || node.url}${folder ? ` · ${folder}` : ""}`,
        idParts: [node.url, node.date_added, node.id],
        attributes: { folder: folder || "", guid: node.guid || "" },
      }));
    }
    if (Array.isArray(node.children)) {
      for (const c of node.children) walk(c, node.name || folder);
    }
  }
  const roots = json && json.roots;
  if (roots && typeof roots === "object") {
    for (const key of Object.keys(roots)) walk(roots[key], "");
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- Chromium: extensions (manifest per ext + state from Preferences) ---- */
function readChromiumExtensions(ctx, extDir, profilePath) {
  // Pull install/update/state from Preferences / Secure Preferences if present.
  function loadSettings(file) {
    try {
      const j = JSON.parse(fs.readFileSync(file, "utf8"));
      return (j && j.extensions && j.extensions.settings) || {};
    } catch { return {}; }
  }
  const settings = Object.assign(
    {},
    loadSettings(path.join(profilePath, "Preferences")),
    loadSettings(path.join(profilePath, "Secure Preferences"))
  );

  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(extDir, { withFileTypes: true }); } catch { entries = []; }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const extId = ent.name;
    if (extId === "Temp") continue;
    const extPath = path.join(extDir, extId);
    // Newest version sub-directory.
    let versions = [];
    try { versions = fs.readdirSync(extPath, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name); } catch { versions = []; }
    versions.sort();
    const verDir = versions.length ? path.join(extPath, versions[versions.length - 1]) : extPath;

    let manifest = {};
    try { manifest = JSON.parse(fs.readFileSync(path.join(verDir, "manifest.json"), "utf8")); } catch { manifest = {}; }

    const st = settings[extId] || {};
    const enabled = st.state === undefined ? null : st.state === 1;
    out.push(record(ctx, {
      type: "extension",
      url: "",
      domain: "",
      title: (manifest && manifest.name) || extId,
      ts: flexibleStampToMs(st.install_time || st.first_install_time),
      tsKind: "extension-install",
      detail: `${(manifest && manifest.name) || extId} v${(manifest && manifest.version) || "?"}${enabled === null ? "" : enabled ? " · enabled" : " · disabled"}`,
      idParts: [extId, (manifest && manifest.version) || ""],
      attributes: {
        extensionId: extId,
        version: (manifest && manifest.version) || "",
        manifestVersion: (manifest && manifest.manifest_version != null) ? manifest.manifest_version : null,
        installTime: flexibleStampToMs(st.install_time || st.first_install_time),
        updateTime: flexibleStampToMs(st.last_update_time),
        enabledState: enabled === null ? "unknown" : enabled ? "enabled" : "disabled",
        sourcePath: verDir,
        permissions: (manifest && manifest.permissions) || [],
        hostPermissions: (manifest && (manifest.host_permissions || (manifest.permissions || []).filter((p) => /:\/\//.test(String(p))))) || [],
      },
    }));
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- Chromium: logins (metadata + password_value length only) ---- */
function readChromiumLogins(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "logins")) return [];
    // password_value is NEVER selected or decrypted — only its byte length.
    return db.prepare(
      "SELECT origin_url, username_value, signon_realm, " +
      "CAST(date_created AS TEXT) AS date_created, CAST(date_last_used AS TEXT) AS date_last_used, " +
      "times_used, length(password_value) AS pw_len FROM logins LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "login",
    url: r.origin_url || "",
    title: r.username_value || "",
    ts: chromeToMs(r.date_created),
    tsKind: "login-created",
    detail: `${r.username_value || "(account)"} @ ${domainFrom(r.origin_url) || r.signon_realm || "?"}`,
    idParts: [r.origin_url, r.username_value, r.date_created],
    attributes: {
      origin: r.origin_url || r.signon_realm || "",
      username: r.username_value || "",
      created: chromeToMs(r.date_created),
      lastUsed: chromeToMs(r.date_last_used),
      timesUsed: r.times_used || 0,
      encryptedFieldPresent: (r.pw_len || 0) > 0,
      encryptedFieldLength: r.pw_len || 0, // length only — credential never read
    },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Chromium: IndexedDB (per-origin directory inventory) ---- */
function readChromiumIndexedDb(ctx, idbDir) {
  const inv = inventoryDir(idbDir);
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(idbDir, { withFileTypes: true }); } catch { entries = []; }
  for (const ent of entries) {
    const m = ent.name.match(/^(https?|file|chrome-extension)_(.+?)_\d+\.indexeddb\.(leveldb|blob)$/i);
    if (!m) continue;
    const scheme = m[1].toLowerCase();
    const host = m[2];
    const st = statSafe(path.join(idbDir, ent.name));
    out.push(record(ctx, {
      type: "indexeddb",
      url: `${scheme}://${host}`,
      domain: domainFrom(host) || host,
      title: host,
      ts: st ? Math.round(st.mtimeMs) : null,
      tsKind: "fs-mtime",
      detail: `IndexedDB origin ${scheme}://${host}`,
      idParts: [scheme, host, m[3]],
      attributes: { scheme, store: m[3] },
    }));
  }
  return {
    records: out,
    recordCount: out.length,
    locked: false,
    copied: false,
    copyPath: null,
    inventory: { fileCount: inv.fileCount, bytes: inv.bytes },
    dirSha: inv.sha256,
    files: inv.files,
  };
}

/* ---- Chromium: favicons ---- */
function readChromiumFavicons(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "icon_mapping") || !tableExists(db, "favicons")) return [];
    const hasBitmaps = tableExists(db, "favicon_bitmaps");
    const sel = hasBitmaps
      ? "SELECT m.page_url, f.url AS icon_url, b.width, b.height, CAST(b.last_updated AS TEXT) AS last_updated " +
        "FROM icon_mapping m JOIN favicons f ON f.id=m.icon_id " +
        "JOIN favicon_bitmaps b ON b.icon_id=f.id LIMIT ?"
      : "SELECT m.page_url, f.url AS icon_url, NULL AS width, NULL AS height, NULL AS last_updated " +
        "FROM icon_mapping m JOIN favicons f ON f.id=m.icon_id LIMIT ?";
    return db.prepare(sel).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "favicon",
    url: r.page_url || "",
    title: domainFrom(r.page_url),
    ts: chromeToMs(r.last_updated),
    tsKind: "favicon-updated",
    detail: `icon ${r.icon_url || "?"}${r.width ? ` · ${r.width}x${r.height}` : ""}`,
    idParts: [r.page_url, r.icon_url, r.width],
    attributes: { iconUrl: r.icon_url || "", width: r.width, height: r.height, relatedUrls: [r.icon_url].filter(Boolean) },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Chromium: Top Sites ---- */
function readChromiumTopSites(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "top_sites")) return [];
    return db.prepare("SELECT url, title, url_rank FROM top_sites ORDER BY url_rank ASC LIMIT ?").all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "topsite",
    url: r.url || "",
    title: r.title || "",
    ts: null,
    tsKind: "none",
    detail: `#${r.url_rank} ${r.title || r.url}`,
    idParts: [r.url, r.url_rank],
    attributes: { rank: r.url_rank },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Chromium: Preferences (curated metadata only) ---- */
function readChromiumPreferences(ctx, srcPath) {
  let json = null;
  try { json = JSON.parse(fs.readFileSync(srcPath, "utf8")); } catch { json = null; }
  const out = [];
  if (json) {
    const homepage = json.homepage;
    if (homepage) {
      out.push(record(ctx, {
        type: "preference", url: homepage, ts: null, tsKind: "none",
        detail: `Homepage: ${homepage}`, idParts: ["homepage", homepage],
        attributes: { key: "homepage" },
      }));
    }
    const startup = json.session && json.session.startup_urls;
    if (Array.isArray(startup)) {
      for (const u of startup) {
        out.push(record(ctx, {
          type: "preference", url: u, ts: null, tsKind: "none",
          detail: `Startup URL: ${u}`, idParts: ["startup_url", u],
          attributes: { key: "session.startup_urls" },
        }));
      }
    }
    const dsp = json.default_search_provider_data && json.default_search_provider_data.template_url_data;
    if (dsp && dsp.keyword) {
      out.push(record(ctx, {
        type: "preference", url: dsp.url || "", ts: null, tsKind: "none",
        detail: `Default search: ${dsp.short_name || dsp.keyword}`, idParts: ["default_search", dsp.keyword],
        attributes: { key: "default_search_provider", keyword: dsp.keyword },
      }));
    }
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- Firefox: history ---- */
function readFirefoxHistory(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "moz_places")) return [];
    return db.prepare(
      "SELECT url, title, visit_count, CAST(last_visit_date AS TEXT) AS last_visit_date FROM moz_places " +
      "WHERE url IS NOT NULL AND last_visit_date IS NOT NULL " +
      "ORDER BY last_visit_date DESC LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "history",
    url: r.url,
    title: r.title || "",
    ts: mozMicroToMs(r.last_visit_date),
    tsKind: "last-visit",
    detail: `${r.title || r.url} · ${r.visit_count || 0} visit(s)`,
    idParts: [r.url, r.last_visit_date],
    attributes: { visitCount: r.visit_count || 0 },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Firefox: downloads (annotations in places.sqlite) ---- */
function readFirefoxDownloads(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "moz_annos") || !tableExists(db, "moz_anno_attributes") || !tableExists(db, "moz_places")) return [];
    return db.prepare(
      "SELECT p.url AS source_url, a.content AS dest, CAST(a.dateAdded AS TEXT) AS dateAdded " +
      "FROM moz_annos a " +
      "JOIN moz_places p ON p.id = a.place_id " +
      "JOIN moz_anno_attributes t ON t.id = a.anno_attribute_id " +
      "WHERE t.name = 'downloads/destinationFileURI' " +
      "ORDER BY a.dateAdded DESC LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "download",
    url: r.source_url || "",
    title: fileBaseFromUri(r.dest),
    ts: mozMicroToMs(r.dateAdded),
    tsKind: "download-added",
    detail: `${fileBaseFromUri(r.dest) || "(file)"} ← ${domainFrom(r.source_url) || "?"}`,
    idParts: [r.source_url, r.dest, r.dateAdded],
    attributes: { destination: r.dest || "", relatedUrls: [r.dest].filter(Boolean) },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Firefox: cookies (metadata + value length only) ---- */
function readFirefoxCookies(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "moz_cookies")) return [];
    // value is NEVER selected — only its length.
    return db.prepare(
      "SELECT host, name, path, expiry, CAST(lastAccessed AS TEXT) AS lastAccessed, " +
      "CAST(creationTime AS TEXT) AS creationTime, " +
      "isSecure, isHttpOnly, sameSite, length(value) AS val_len FROM moz_cookies LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => {
    const host = String(r.host || "").replace(/^\./, "");
    return record(ctx, {
      type: "cookie",
      url: "",
      domain: domainFrom(host) || host,
      title: r.name || "",
      ts: mozMicroToMs(r.creationTime),
      tsKind: "cookie-created",
      detail: `${r.name || "?"} @ ${host}${r.isSecure ? " · secure" : ""}${r.isHttpOnly ? " · httpOnly" : ""}`,
      idParts: [host, r.name, r.path, r.creationTime],
      attributes: {
        cookieName: r.name || "",
        cookiePath: r.path || "",
        secure: !!r.isSecure,
        httpOnly: !!r.isHttpOnly,
        sameSite: r.sameSite,
        expires: secToMs(r.expiry),
        lastAccess: mozMicroToMs(r.lastAccessed),
        valuePresent: (r.val_len || 0) > 0,
        valueLength: r.val_len || 0, // length only — value never read
      },
    });
  });
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Firefox: bookmarks ---- */
function readFirefoxBookmarks(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "moz_bookmarks") || !tableExists(db, "moz_places")) return [];
    return db.prepare(
      "SELECT b.title, p.url, CAST(b.dateAdded AS TEXT) AS dateAdded FROM moz_bookmarks b " +
      "JOIN moz_places p ON p.id = b.fk WHERE b.type = 1 AND p.url IS NOT NULL LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "bookmark",
    url: r.url,
    title: r.title || "",
    ts: mozMicroToMs(r.dateAdded),
    tsKind: "bookmark-added",
    detail: `${r.title || r.url}`,
    idParts: [r.url, r.dateAdded],
    attributes: {},
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Firefox: extensions (extensions.json / addons.json) ---- */
function readFirefoxExtensions(ctx, srcPath) {
  let json = null;
  try { json = JSON.parse(fs.readFileSync(srcPath, "utf8")); } catch { json = null; }
  const addons = (json && (json.addons || (json.schema ? [] : []))) || [];
  const out = [];
  for (const a of addons) {
    if (!a || !a.id) continue;
    const perms = (a.userPermissions && a.userPermissions.permissions) || [];
    const origins = (a.userPermissions && a.userPermissions.origins) || [];
    const name = (a.defaultLocale && a.defaultLocale.name) || a.id;
    const enabled = a.active === true && a.userDisabled !== true;
    out.push(record(ctx, {
      type: "extension",
      url: "",
      domain: "",
      title: name,
      ts: asMs(a.installDate),
      tsKind: "extension-install",
      detail: `${name} v${a.version || "?"}${enabled ? " · enabled" : " · disabled"}`,
      idParts: [a.id, a.version || ""],
      attributes: {
        extensionId: a.id,
        version: a.version || "",
        manifestVersion: (a.manifestVersion != null) ? a.manifestVersion
          : ((a.manifest && a.manifest.manifest_version != null) ? a.manifest.manifest_version : null),
        installTime: asMs(a.installDate),
        updateTime: asMs(a.updateDate),
        enabledState: enabled ? "enabled" : "disabled",
        sourcePath: a.path || "",
        permissions: perms,
        hostPermissions: origins,
        addonType: a.type || "",
      },
    }));
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- Firefox: logins (logins.json — never decrypt) ---- */
function readFirefoxLogins(ctx, srcPath) {
  let json = null;
  try { json = JSON.parse(fs.readFileSync(srcPath, "utf8")); } catch { json = null; }
  const logins = (json && json.logins) || [];
  const out = [];
  for (const l of logins) {
    if (!l) continue;
    // encryptedUsername / encryptedPassword are NEVER decrypted — only measured.
    out.push(record(ctx, {
      type: "login",
      url: l.hostname || l.origin || "",
      title: domainFrom(l.hostname || l.origin),
      ts: asMs(l.timeCreated),
      tsKind: "login-created",
      detail: `login @ ${domainFrom(l.hostname || l.origin) || l.hostname || "?"}`,
      idParts: [l.hostname, l.guid, l.timeCreated],
      attributes: {
        origin: l.hostname || l.origin || "",
        created: asMs(l.timeCreated),
        lastUsed: asMs(l.timeLastUsed),
        timesUsed: l.timesUsed || 0,
        encryptedFieldPresent: !!l.encryptedPassword,
        encryptedFieldLength: b64ByteLen(l.encryptedPassword),
        encryptedUsernameLength: b64ByteLen(l.encryptedUsername),
      },
    }));
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- Firefox: localStorage (webappsstore.sqlite or storage/default) ---- */
function decodeReversedScope(scope) {
  // moz scope looks like "443:https:moc.elpmaxe." -> host "example.com".
  const parts = String(scope || "").split(":");
  const reversed = parts[parts.length - 1] || "";
  const host = reversed.split("").reverse().join("").replace(/^\.+|\.+$/g, "");
  return host;
}
function readFirefoxLocalStorage(ctx, srcPath, tmpDir, isSqlite) {
  if (isSqlite) {
    const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
      if (!tableExists(db, "webappsstore2")) return [];
      // value is NEVER selected — only its length.
      return db.prepare("SELECT scope, key, length(value) AS val_len FROM webappsstore2 LIMIT ?").all(LIMIT);
    });
    const records = rows.map((r) => {
      const host = decodeReversedScope(r.scope);
      return record(ctx, {
        type: "localstorage",
        url: host ? `https://${host}` : "",
        domain: domainFrom(host) || host,
        title: host,
        ts: null,
        tsKind: "none",
        detail: `${r.key || "?"} @ ${host} · ${r.val_len || 0} bytes`,
        idParts: [r.scope, r.key],
        attributes: { key: r.key || "", valueLength: r.val_len || 0 },
      });
    });
    return { records, recordCount: records.length, locked, copied: true, copyPath };
  }
  // Directory inventory of storage/default (origins from dir names).
  return inventoryOriginDirs(ctx, srcPath, "localstorage", "ls");
}

/* ---- Firefox: IndexedDB (storage/default origins with idb) ---- */
function readFirefoxIndexedDb(ctx, storageDir) {
  return inventoryOriginDirs(ctx, storageDir, "indexeddb", "idb");
}

// Shared: enumerate storage/default/<encoded-origin>/<marker> directories.
function inventoryOriginDirs(ctx, storageDir, type, marker) {
  const inv = inventoryDir(storageDir);
  const out = [];
  let entries = [];
  try { entries = fs.readdirSync(storageDir, { withFileTypes: true }); } catch { entries = []; }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const sub = path.join(storageDir, ent.name);
    if (!statSafe(path.join(sub, marker))) continue;
    // Firefox encodes origins like "https+++example.com" or "https+++example.com+443".
    const decoded = ent.name.replace(/\+\+\+/g, "://").replace(/\+/g, ":");
    const host = domainFrom(decoded) || ent.name;
    const st = statSafe(sub);
    out.push(record(ctx, {
      type,
      url: decoded,
      domain: host,
      title: host,
      ts: st ? Math.round(st.mtimeMs) : null,
      tsKind: "fs-mtime",
      detail: `${type} origin ${decoded}`,
      idParts: [ent.name, marker],
      attributes: { encodedOrigin: ent.name },
    }));
  }
  return {
    records: out,
    recordCount: out.length,
    locked: false,
    copied: false,
    copyPath: null,
    inventory: { fileCount: inv.fileCount, bytes: inv.bytes },
    dirSha: inv.sha256,
    files: inv.files,
  };
}

/* ---- Firefox: favicons ---- */
function readFirefoxFavicons(ctx, srcPath, tmpDir) {
  const { rows, locked, copyPath } = withSqliteCopy(srcPath, tmpDir, (db) => {
    if (!tableExists(db, "moz_icons") || !tableExists(db, "moz_pages_w_icons") || !tableExists(db, "moz_icons_to_pages")) return [];
    return db.prepare(
      "SELECT pg.page_url, i.icon_url, i.width, i.expire_ms FROM moz_icons i " +
      "JOIN moz_icons_to_pages ip ON ip.icon_id = i.id " +
      "JOIN moz_pages_w_icons pg ON pg.id = ip.page_id LIMIT ?"
    ).all(LIMIT);
  });
  const records = rows.map((r) => record(ctx, {
    type: "favicon",
    url: r.page_url || "",
    title: domainFrom(r.page_url),
    ts: asMs(r.expire_ms),
    tsKind: "favicon-expire",
    detail: `icon ${r.icon_url || "?"}${r.width ? ` · ${r.width}px` : ""}`,
    idParts: [r.page_url, r.icon_url, r.width],
    attributes: { iconUrl: r.icon_url || "", width: r.width, relatedUrls: [r.icon_url].filter(Boolean) },
  }));
  return { records, recordCount: records.length, locked, copied: true, copyPath };
}

/* ---- Firefox: prefs.js (curated metadata only) ---- */
function readFirefoxPrefs(ctx, srcPath) {
  let text = "";
  try { text = fs.readFileSync(srcPath, "utf8"); } catch { text = ""; }
  const out = [];
  const wanted = new Set([
    "browser.startup.homepage",
    "browser.newtabpage.pinned",
    "browser.search.defaultenginename",
  ]);
  const re = /user_pref\("([^"]+)",\s*("?)(.*?)\2\);/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    const key = m[1];
    if (!wanted.has(key)) continue;
    const val = m[3];
    const isUrl = /^https?:\/\//i.test(val);
    out.push(record(ctx, {
      type: "preference",
      url: isUrl ? val : "",
      title: key,
      ts: null,
      tsKind: "none",
      detail: `${key} = ${val}`,
      idParts: [key, val],
      attributes: { key },
    }));
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- service worker registrations (metadata only, NO script extraction) ----
   Chromium persists registrations in <profile>/Service Worker/Database, a
   LevelDB store. Each registration value is a ServiceWorkerRegistrationData
   protobuf:
       field 1 (varint)  registration_id
       field 2 (bytes)   scope_url               tag 0x12
       field 3 (bytes)   script_url              tag 0x1a
       field 7 (varint)  last_update_check_time  tag 0x38  (base::Time micros
                                                            since 1601-01-01)
   LevelDB has no SQL interface and no third-party reader is available, so we
   carve registrations directly from the data files: locate the contiguous
   scope/script URL field pair and read the adjacent metadata. The worker script
   body (Service Worker/ScriptCache) is never read. Files are only read. */

const SW_SCAN_BUDGET = 64 << 20; // cap bytes scanned across the registration store

function readVarintAt(buf, pos) {
  let shift = 0n; let result = 0n; let i = pos;
  while (i < buf.length && i - pos < 10) {
    const b = buf[i];
    result |= BigInt(b & 0x7f) << shift;
    i += 1;
    if ((b & 0x80) === 0) return { value: result, next: i };
    shift += 7n;
  }
  return null;
}

function looksLikeUrl(s) {
  return /^[a-z][a-z0-9+.\-]*:\/\//i.test(s);
}

// Read a length-delimited field value starting at the length varint (the tag
// byte is assumed already matched by the caller).
function readDelimited(buf, lenPos) {
  const lv = readVarintAt(buf, lenPos);
  if (!lv) return null;
  const len = Number(lv.value);
  if (len <= 0 || len > 4096) return null;
  const start = lv.next; const end = start + len;
  if (end > buf.length) return null;
  const str = buf.toString("utf8", start, end);
  if (/[\u0000-\u0008\u000e-\u001f]/.test(str)) return null; // reject binary noise
  return { str, next: end };
}

function carveChromiumServiceWorkers(buf) {
  const regs = [];
  for (let i = 0; i + 2 < buf.length; i++) {
    if (buf[i] !== 0x12) continue;                    // field 2: scope_url
    const scope = readDelimited(buf, i + 1);
    if (!scope || !looksLikeUrl(scope.str)) continue;
    if (buf[scope.next] !== 0x1a) continue;           // field 3: script_url must follow
    const script = readDelimited(buf, scope.next + 1);
    if (!script || !looksLikeUrl(script.str)) continue;

    // registration_id (field 1) is serialized just before scope as 08 <varint>.
    let registrationId = null;
    for (let b = i - 1; b >= Math.max(0, i - 12); b--) {
      if (buf[b] === 0x08) {
        const v = readVarintAt(buf, b + 1);
        if (v && v.next === i) { registrationId = v.value.toString(); break; }
      }
    }

    // Parse following fields generically to recover last_update_check_time
    // (field 7). Stop at the next registration's scope tag or on malformed data.
    let lastUpdate = null;
    let p = script.next; let guard = 0;
    while (p < buf.length && guard < 24) {
      guard += 1;
      const tag = buf[p];
      if (tag === 0x12) break;
      const fieldNo = tag >> 3; const wire = tag & 0x07;
      let q = p + 1;
      if (wire === 0) {
        const v = readVarintAt(buf, q); if (!v) break;
        if (fieldNo === 7) lastUpdate = v.value;
        q = v.next;
      } else if (wire === 2) {
        const lv = readVarintAt(buf, q); if (!lv) break;
        q = lv.next + Number(lv.value);
        if (q > buf.length) break;
      } else if (wire === 5) { q += 4; }
      else if (wire === 1) { q += 8; }
      else break;
      p = q;
    }

    regs.push({
      scope: scope.str,
      script: script.str,
      registrationId,
      lastUpdate: lastUpdate != null ? chromeToMs(lastUpdate.toString()) : null,
    });
    i = script.next - 1;
  }
  return regs;
}

function readChromiumServiceWorkers(ctx, swRootPath) {
  const dbDir = path.join(swRootPath, "Database");
  const st = statSafe(dbDir);
  if (!st || !st.isDirectory()) {
    return { records: [], recordCount: 0, locked: false, copied: false, copyPath: null };
  }
  const inv = inventoryDir(dbDir); // deterministic provenance over the store

  let entries = [];
  try { entries = fs.readdirSync(dbDir, { withFileTypes: true }); } catch { entries = []; }
  entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));

  const seen = new Set();
  const out = [];
  let budget = SW_SCAN_BUDGET;
  for (const ent of entries) {
    if (!ent.isFile()) continue;
    if (!/\.(log|ldb|sst)$/i.test(ent.name)) continue; // data files only
    const abs = path.join(dbDir, ent.name);
    const fst = statSafe(abs);
    if (!fst || fst.size > budget) continue;
    let buf;
    try { buf = fs.readFileSync(abs); } catch { continue; }
    budget -= buf.length;
    for (const reg of carveChromiumServiceWorkers(buf)) {
      const key = `${reg.scope}\u0000${reg.script}`;
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(record(ctx, {
        type: "serviceworker",
        url: reg.script || reg.scope,
        domain: domainFrom(reg.scope || reg.script),
        title: reg.scope || "",
        ts: reg.lastUpdate,
        tsKind: reg.lastUpdate != null ? "sw-last-update" : "none",
        detail: `scope ${reg.scope} → ${reg.script}`,
        idParts: [reg.scope, reg.script],
        attributes: {
          scope: reg.scope,
          scriptUrl: reg.script,
          registrationId: reg.registrationId,
          lastUpdateTime: reg.lastUpdate,
          sourcePath: dbDir,
          sourceFile: ent.name,
          relatedUrls: [reg.scope, reg.script].filter(Boolean),
        },
      }));
      if (out.length >= LIMIT) break;
    }
    if (out.length >= LIMIT || budget <= 0) break;
  }
  return {
    records: out,
    recordCount: out.length,
    locked: false,
    copied: false,
    copyPath: null,
    dirSha: inv.sha256,
    inventory: { fileCount: inv.fileCount, bytes: inv.bytes },
  };
}

// Firefox: <profile>/serviceworker.txt — the Gecko ServiceWorkerRegistrar text
// store. The per-record line layout varies by version, so parse tolerantly: a
// version header line, then each registration contributes a scope URL and a
// current-worker (script) URL, optionally followed by a numeric last-update
// time. Worker script bodies are never read.
function readFirefoxServiceWorkers(ctx, srcPath) {
  let text = "";
  try { text = fs.readFileSync(srcPath, "utf8"); } catch { text = ""; }
  const lines = text.split(/\r?\n/);
  const out = [];
  let scope = null;

  function emit(script, lastUpdate) {
    out.push(record(ctx, {
      type: "serviceworker",
      url: script,
      domain: domainFrom(scope),
      title: scope,
      ts: lastUpdate,
      tsKind: lastUpdate != null ? "sw-last-update" : "none",
      detail: `scope ${scope} → ${script}`,
      idParts: [scope, script],
      attributes: {
        scope,
        scriptUrl: script,
        lastUpdateTime: lastUpdate,
        sourcePath: srcPath,
        relatedUrls: [scope, script].filter(Boolean),
      },
    }));
  }

  for (let idx = 1; idx < lines.length; idx++) { // line 0 is the format version
    const line = lines[idx].trim();
    if (!line || !looksLikeUrl(line)) continue;
    if (!scope) { scope = line; continue; }
    // Second URL of the pair = current worker (script) URL.
    let lastUpdate = null;
    for (let k = idx + 1; k < Math.min(lines.length, idx + 6); k++) {
      const t = lines[k].trim();
      if (looksLikeUrl(t)) break;           // next registration began
      if (/^\d{10,16}$/.test(t)) { lastUpdate = flexibleStampToMs(t); break; }
    }
    emit(line, lastUpdate);
    scope = null;
    if (out.length >= LIMIT) break;
  }
  return { records: out, recordCount: out.length, locked: false, copied: false, copyPath: null };
}

/* ---- generic inventory readers (metadata only) ---- */
function readInventory(ctx, targets) {
  // targets: array of absolute paths (files or dirs). Hash files, inventory dirs.
  const files = [];
  let bytes = 0;
  for (const t of targets) {
    const st = statSafe(t);
    if (!st) continue;
    if (st.isDirectory()) {
      const inv = inventoryDir(t);
      bytes += inv.bytes;
      for (const f of inv.files) files.push({ rel: `${path.basename(t)}/${f.rel}`, size: f.size, mtime: f.mtime, sha256: f.sha256 });
    } else if (st.isFile()) {
      let sha = "";
      try { sha = sha256File(t); } catch { sha = ""; }
      files.push({ rel: path.basename(t), size: st.size, mtime: Math.round(st.mtimeMs), sha256: sha });
      bytes += st.size;
    }
  }
  files.sort((a, b) => (a.rel < b.rel ? -1 : a.rel > b.rel ? 1 : 0));
  const dirSha = sha256Buffer(Buffer.from(files.map((f) => `${f.rel}\0${f.size}\0${f.mtime}\0${f.sha256}`).join("\n"), "utf8"));
  return {
    records: [],
    recordCount: files.length,
    locked: false,
    copied: false,
    copyPath: null,
    inventory: { fileCount: files.length, bytes },
    dirSha,
    files,
  };
}

/* ============================== DISPATCH ================================= */

const READERS = {
  chromium_history: (ctx, src, tmp) => readChromiumHistory(ctx, src, tmp),
  chromium_downloads: (ctx, src, tmp) => readChromiumDownloads(ctx, src, tmp),
  chromium_cookies: (ctx, src, tmp) => readChromiumCookies(ctx, src, tmp),
  chromium_bookmarks: (ctx, src) => readChromiumBookmarks(ctx, src),
  chromium_extensions: (ctx, src, tmp, job, target) => readChromiumExtensions(ctx, src, target.profilePath),
  chromium_logins: (ctx, src, tmp) => readChromiumLogins(ctx, src, tmp),
  chromium_indexeddb: (ctx, src) => readChromiumIndexedDb(ctx, src),
  chromium_favicons: (ctx, src, tmp) => readChromiumFavicons(ctx, src, tmp),
  chromium_topsites: (ctx, src, tmp) => readChromiumTopSites(ctx, src, tmp),
  chromium_preferences: (ctx, src) => readChromiumPreferences(ctx, src),
  chromium_serviceworkers: (ctx, src) => readChromiumServiceWorkers(ctx, src),

  firefox_history: (ctx, src, tmp) => readFirefoxHistory(ctx, src, tmp),
  firefox_downloads: (ctx, src, tmp) => readFirefoxDownloads(ctx, src, tmp),
  firefox_cookies: (ctx, src, tmp) => readFirefoxCookies(ctx, src, tmp),
  firefox_bookmarks: (ctx, src, tmp) => readFirefoxBookmarks(ctx, src, tmp),
  firefox_extensions: (ctx, src) => readFirefoxExtensions(ctx, src),
  firefox_logins: (ctx, src) => readFirefoxLogins(ctx, src),
  firefox_localstorage: (ctx, src, tmp) => readFirefoxLocalStorage(ctx, src, tmp, /\.sqlite$/i.test(src)),
  firefox_indexeddb: (ctx, src) => readFirefoxIndexedDb(ctx, src),
  firefox_favicons: (ctx, src, tmp) => readFirefoxFavicons(ctx, src, tmp),
  firefox_prefs: (ctx, src) => readFirefoxPrefs(ctx, src),
  firefox_serviceworkers: (ctx, src) => readFirefoxServiceWorkers(ctx, src),

  inventory: (ctx, src, tmp, job) => readInventory(ctx, job.candidates.filter((c) => statSafe(c))),
  unsupported: () => ({ records: [], recordCount: 0, locked: false, copied: false, copyPath: null, unsupported: true }),
};

function pickSource(job) {
  // "first" -> first existing candidate; "all" -> first existing as the anchor.
  for (const c of job.candidates) {
    if (statSafe(c)) return c;
  }
  return null;
}

function artifactIdFor(runId, artifactType, sourcePath) {
  return "art_" + crypto.createHash("sha256").update(`${runId}|${artifactType}|${sourcePath || ""}`).digest("hex").slice(0, 16);
}

function profileHashOf(browser, profilePath, browserVersion) {
  return crypto.createHash("sha256").update(`${browser}|${profilePath}|${browserVersion}`).digest("hex");
}

/* ------------------------------ run an acquisition ------------------------ */
// target = browsers.resolveTarget(...). Returns { run, artifacts, records }.
// Every artifact is independent: a thrown reader becomes a recorded error and
// acquisition proceeds (soft-failure architecture).

function acquireProfile(target, options = {}) {
  if (!target) throw new Error("acquireProfile: target is required");
  const startedAt = Date.now();
  const profileHash = profileHashOf(target.browser, target.profilePath, target.browserVersion);
  const runId = "run_" + startedAt + "_" + profileHash.slice(0, 8);
  const tmpRoot = path.join(options.tmpRoot || os.tmpdir(), `bf-acq-${runId}`);

  const onlyTypes = options.artifactTypes ? new Set(options.artifactTypes) : null;

  const run = {
    runId,
    browser: target.browser,
    browserFamily: target.browserFamily,
    browserVersion: target.browserVersion || "",
    versionSource: target.versionSource || "unknown",
    profile: target.profile,
    profilePath: target.profilePath,
    profileHash,
    platform: target.platform,
    host: target.host,
    startedAt,
    finishedAt: null,
    acquiredAt: null,
  };

  const artifacts = [];
  let records = [];

  try {
    for (const job of target.jobs) {
      if (onlyTypes && !onlyTypes.has(job.artifactType)) continue;

      const sourcePath = job.reader === "inventory" ? (pickSource(job) || job.candidates[0]) : pickSource(job);
      const artifactId = artifactIdFor(runId, job.artifactType, sourcePath || job.candidates[0]);
      const ctx = { runId, artifactId, artifactType: job.artifactType };

      const artifact = {
        artifactId,
        runId,
        artifactType: job.artifactType,
        sourcePath: sourcePath || job.candidates[0],
        sourceSize: 0,
        sourceModifiedTime: null,
        sha256: "",
        hashScope: "file",
        locked: false,
        copied: false,
        copyPath: null,
        recordCount: 0,
        errors: [],
      };

      // Nothing on disk for this artifact: record as a soft "not present".
      const haveSource = job.reader === "inventory"
        ? job.candidates.some((c) => statSafe(c))
        : !!sourcePath;
      if (!haveSource) {
        artifact.errors.push("not present");
        artifacts.push(artifact);
        continue;
      }

      // Source provenance (read-only stat + hash) for single-file artifacts.
      const st = statSafe(sourcePath);
      if (st && st.isFile()) {
        artifact.sourceSize = st.size;
        artifact.sourceModifiedTime = Math.round(st.mtimeMs);
        try { artifact.sha256 = sha256File(sourcePath); } catch (e) { artifact.errors.push(`hash failed: ${e.message}`); }
      } else if (st && st.isDirectory()) {
        artifact.hashScope = "directory";
      }

      try {
        const reader = READERS[job.reader];
        if (!reader) throw new Error(`no reader for ${job.reader}`);
        const res = reader(ctx, sourcePath, tmpRoot, job, target);

        artifact.recordCount = res.recordCount || (res.records ? res.records.length : 0);
        if (res.locked) artifact.locked = true;
        if (res.copied) { artifact.copied = true; artifact.copyPath = res.copyPath || null; }
        if (res.dirSha) { artifact.sha256 = res.dirSha; artifact.hashScope = "directory"; }
        if (res.inventory) { artifact.sourceSize = res.inventory.bytes; }
        if (res.files) { artifact.files = res.files.slice(0, 250); } // bounded sample for the report
        if (res.unsupported) artifact.errors.push("unsupported for this browser family");

        if (res.records && res.records.length) records = records.concat(res.records);
      } catch (e) {
        artifact.errors.push(String((e && e.message) || e));
      }

      artifacts.push(artifact);
    }
  } finally {
    // Remove temporary working copies; source databases are never touched.
    try { fs.rmSync(tmpRoot, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  run.finishedAt = Date.now();
  run.acquiredAt = run.finishedAt;

  return { run, artifacts, records };
}

module.exports = {
  acquireProfile,
  // time + hash helpers (exported for testing / reuse)
  chromeToMs,
  mozMicroToMs,
  secToMs,
  sha256File,
  inventoryDir,
  profileHashOf,
  sqliteAvailable: () => !!DatabaseSync,
};
