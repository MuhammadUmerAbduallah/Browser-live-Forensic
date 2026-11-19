// extensions.js
// Extension Forensics Engine.
//
// A dedicated investigation system for browser extensions. It does NOT acquire
// or re-read any browser data — it consumes the *already acquired* "extensions"
// artifact records (from acqstore.js, schema unchanged) plus the *already built*
// unified timeline (from timeline.js, schema unchanged) and behavioral findings.
//
// Supported browser families: Chrome, Edge, Brave, Opera (chromium) and Firefox
// (gecko). The acquisition layer already normalizes both into "extension"
// records with the same attribute shape:
//   { extensionId, name(title), version*, manifestVersion*, installTime,
//     updateTime, enabledState, permissions[], hostPermissions[], sourcePath,
//     addonType? }
// (* version/manifestVersion are present on records captured after the additive
//  acquire.js change; for older records version is recovered from the record
//  detail string and manifestVersion is reported "unknown".)
//
// Storage model mirrors the rest of the project's derived data (findings.json,
// graph.json, acquisitions.json, timeline.json): a single JSON sidecar
// (extensions.json) in the data directory. No database schema changes, no
// modifications to existing tables or acquisition/timeline schemas — fully
// additive and self-contained.
//
// Every Extension Finding contains: findingId, extensionId, severity, reason,
// evidence, ts.
// Every Extension Profile contains: extensionId, riskScore, riskLevel,
// findingCount, installAge, updateAge, permissionsSummary (+ additive fields and
// the correlation stores relatedTimelineIds[] / relatedFindingIds[]).

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const risk = require("./risk");

const SIDECAR = "extensions.json";
const FORMAT_VERSION = 1;

const DAY = 86400000;
const RECENT_INSTALL_DAYS = 14;
const RECENT_UPDATE_DAYS = 14;

const MAX_RELATED = 200;            // cap relatedTimelineIds per profile
const MAX_SNAPSHOT = 40;            // cap denormalized related-entry snapshot

// ---- severity scale (matches findings/timeline vocabulary) ----
const SEVERITY_RANK = { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];
const SCORE_WEIGHT = { INFO: 1, MEDIUM: 5, HIGH: 15, CRITICAL: 40 };
function sevRank(s) { return SEVERITY_RANK[s] != null ? SEVERITY_RANK[s] : 0; }
function maxSeverity(a, b) { return sevRank(a) >= sevRank(b) ? a : b; }

// ---- dangerous API permission classification ----
// reason key -> { severity, label }
const PERM_RISK = {
  debugger: { severity: "CRITICAL", label: "debugging permission (debugger)" },
  nativeMessaging: { severity: "CRITICAL", label: "native messaging permission" },
  proxy: { severity: "HIGH", label: "proxy control permission" },
  management: { severity: "HIGH", label: "extension management permission" },
  privacy: { severity: "HIGH", label: "privacy settings permission" },
  webRequest: { severity: "HIGH", label: "network interception (webRequest)" },
  webRequestBlocking: { severity: "HIGH", label: "blocking network interception" },
  clipboardRead: { severity: "HIGH", label: "clipboard read permission" },
  desktopCapture: { severity: "HIGH", label: "desktop capture permission" },
  tabCapture: { severity: "HIGH", label: "tab capture permission" },
  pageCapture: { severity: "HIGH", label: "page capture permission" },
  declarativeNetRequest: { severity: "MEDIUM", label: "declarative network request" },
  declarativeNetRequestFeedback: { severity: "MEDIUM", label: "declarative net request feedback" },
  cookies: { severity: "MEDIUM", label: "cookies permission" },
  history: { severity: "MEDIUM", label: "browsing history permission" },
  bookmarks: { severity: "MEDIUM", label: "bookmarks permission" },
  downloads: { severity: "MEDIUM", label: "downloads permission" },
  tabs: { severity: "MEDIUM", label: "tabs permission" },
  scripting: { severity: "MEDIUM", label: "script injection permission" },
  contentSettings: { severity: "MEDIUM", label: "content settings permission" },
  clipboardWrite: { severity: "MEDIUM", label: "clipboard write permission" },
  geolocation: { severity: "MEDIUM", label: "geolocation permission" },
  storage: { severity: "INFO", label: "storage permission" },
  activeTab: { severity: "INFO", label: "active tab permission" },
  alarms: { severity: "INFO", label: "alarms permission" },
  notifications: { severity: "INFO", label: "notifications permission" },
};

const EXCESSIVE_API_HIGH = 15;
const EXCESSIVE_API_MEDIUM = 8;

const CHROMIUM_FAMILY = new Set(["chromium"]);

function hostFromPattern(p) {
  if (!p) return "";
  const s = String(p);
  if (s === "<all_urls>") return "";
  // match scheme://HOST/...  (host may contain * or leading *.)
  const m = s.match(/^[a-z*]+:\/\/([^/]+)/i);
  let host = m ? m[1] : s;
  host = host.replace(/^\*\./, "").replace(/:\d+$/, "");
  if (!host || host === "*") return "";
  return host;
}

function isWildcardHostPattern(p) {
  const s = String(p || "");
  if (s === "<all_urls>") return true;
  const m = s.match(/^[a-z*]+:\/\/([^/]+)/i);
  if (!m) return false;
  const host = m[1];
  return host === "*" || /\*/.test(host);
}

function isAllUrlsPattern(p) {
  const s = String(p || "");
  if (s === "<all_urls>") return true;
  const m = s.match(/^[a-z*]+:\/\/([^/]+)(?:\/.*)?$/i);
  if (!m) return false;
  // Only a bare "*" host is "all urls"; "*.example.com" is a wildcard host.
  return m[1] === "*";
}

function isFilePattern(p) {
  return /^file:/i.test(String(p || ""));
}

function extFindingId(browser, extensionId, reason) {
  return "extf_" + crypto.createHash("sha256")
    .update(`${browser}|${extensionId}|${reason}`).digest("hex").slice(0, 20);
}

function versionFromDetail(detail) {
  const m = String(detail || "").match(/\sv(\S+?)(?:\s·|\s*$)/);
  return m ? m[1] : "";
}

function nd(v) { return risk.normalizeDomain(v) || ""; }

/* =============================== engine ================================= */

function createExtensionEngine(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);

  /** @type {object[]} */ let profiles = [];
  /** @type {object[]} */ let findings = [];
  let meta = emptyMeta();
  let scannedAt = 0;
  let byKey = new Map();     // composite key -> profile
  let byExtId = new Map();   // extensionId -> profile[]

  load();

  function emptyMeta() {
    return {
      scanned: false, scannedAt: 0,
      total: 0, findingCount: 0,
      byRiskLevel: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 },
      byBrowser: {}, bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 },
      enabled: 0, disabled: 0, correlated: 0,
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
      profiles = []; findings = []; meta = emptyMeta(); scannedAt = 0;
      byKey = new Map(); byExtId = new Map();
    }
  }

  function reindex() {
    byKey = new Map();
    byExtId = new Map();
    for (const p of profiles) {
      byKey.set(p.key, p);
      (byExtId.get(p.extensionId) || byExtId.set(p.extensionId, []).get(p.extensionId)).push(p);
    }
  }

  function persist() {
    fs.writeFileSync(sidecarPath, JSON.stringify({
      version: FORMAT_VERSION, scannedAt, meta, profiles, findings,
    }, null, 2));
  }

  /* ------------------------------ scan ---------------------------------- */

  // inputs = {
  //   extensions: [{ eventId, runId, artifactId, browser, browserFamily,
  //                  profile, host, acquiredAt, title, detail, ts, attributes }],
  //   timelineEntries: [ timeline entry, ... ],
  //   findings: [ behavioral finding, ... ],
  // }
  function scan(inputs = {}) {
    const extRecords = inputs.extensions || [];
    const timelineEntries = inputs.timelineEntries || [];
    const behavioral = inputs.findings || [];

    // De-dupe per install (browser+profile+extensionId), keep the most complete.
    const merged = new Map();
    for (const r of extRecords) {
      const a = r.attributes || {};
      const extensionId = a.extensionId || r.eventId;
      if (!extensionId) continue;
      const browser = r.browser || "";
      const prof = r.profile || "";
      const key = `${browser}\u241F${prof}\u241F${extensionId}`;
      const cand = normalizeRecord(r, a, extensionId, browser, prof);
      const existing = merged.get(key);
      if (!existing || (cand.permissions.length + cand.hostPermissions.length) >
        (existing.permissions.length + existing.hostPermissions.length)) {
        merged.set(key, cand);
      }
    }

    // Pre-index timeline entries / findings for correlation.
    const tlByDomain = new Map();
    const tlSwByDomain = new Map();
    const tlExtByEventId = new Map();
    for (const e of timelineEntries) {
      if (e.domain) (tlByDomain.get(e.domain) || tlByDomain.set(e.domain, []).get(e.domain)).push(e);
      if (e.category === "serviceworker" && e.domain) {
        (tlSwByDomain.get(e.domain) || tlSwByDomain.set(e.domain, []).get(e.domain)).push(e);
      }
      if (e.sourceType === "acquired" && e.artifactType === "extensions" && e.eventId) {
        tlExtByEventId.set(e.eventId, e);
      }
    }

    const allProfiles = [];
    const allFindings = [];

    for (const ext of merged.values()) {
      const result = assess(ext);
      const prof = result.profile;
      const fnds = result.findings;

      // ----- correlation (read-only over timeline + findings) -----
      const domains = prof.permissionsSummary.domains || [];
      const relatedTimeline = new Set();
      const relatedSw = new Set();
      const snapshot = [];

      // the extension's own acquired timeline entry
      const ownEntry = tlExtByEventId.get(ext.eventId);
      if (ownEntry) { relatedTimeline.add(ownEntry.timelineId); pushSnap(snapshot, ownEntry, "self"); }

      // serviceWorkers whose script/scope embeds the extensionId
      for (const e of timelineEntries) {
        if (e.category !== "serviceworker") continue;
        const hay = `${e.url} ${e.title} ${(e.tags || []).join(" ")}`;
        if (hay.includes(ext.extensionId)) {
          relatedTimeline.add(e.timelineId); relatedSw.add(e.timelineId);
          pushSnap(snapshot, e, "serviceworker");
        }
      }

      // host-permission domains -> timeline events & serviceWorkers
      for (const d of domains) {
        for (const e of (tlSwByDomain.get(d) || [])) {
          if (relatedTimeline.size >= MAX_RELATED) break;
          relatedTimeline.add(e.timelineId); relatedSw.add(e.timelineId);
          pushSnap(snapshot, e, "serviceworker");
        }
        for (const e of (tlByDomain.get(d) || [])) {
          if (relatedTimeline.size >= MAX_RELATED) break;
          relatedTimeline.add(e.timelineId);
          pushSnap(snapshot, e, "domain");
        }
      }

      // findings: by affected-domain overlap or extensionId/name mention
      const relatedFindings = new Set();
      const findingSnap = [];
      const domSet = new Set(domains);
      for (const f of behavioral) {
        const affected = f.affectedDomains || [];
        const hit = affected.some((d) => domSet.has(nd(d)) || domSet.has(d)) ||
          `${f.title} ${f.description}`.includes(ext.extensionId) ||
          (ext.name && `${f.title} ${f.description}`.includes(ext.name));
        if (hit) {
          relatedFindings.add(f.id);
          if (findingSnap.length < MAX_SNAPSHOT) {
            findingSnap.push({ id: f.id, severity: f.severity, title: f.title, lastSeen: f.lastSeen });
          }
        }
      }

      prof.relatedTimelineIds = [...relatedTimeline].slice(0, MAX_RELATED);
      prof.relatedFindingIds = [...relatedFindings];
      prof.relatedServiceWorkerIds = [...relatedSw];
      prof.relatedTimeline = snapshot.slice(0, MAX_SNAPSHOT);
      prof.relatedFindings = findingSnap;
      prof.correlation = {
        domains, timelineLinks: prof.relatedTimelineIds.length,
        serviceWorkerLinks: prof.relatedServiceWorkerIds.length,
        findingLinks: prof.relatedFindingIds.length,
      };

      allProfiles.push(prof);
      for (const f of fnds) allFindings.push(f);
    }

    allProfiles.sort((a, b) =>
      (sevRank(b.riskLevel) - sevRank(a.riskLevel)) ||
      (b.riskScore - a.riskScore) ||
      (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    allFindings.sort((a, b) =>
      (sevRank(b.severity) - sevRank(a.severity)) || (b.ts || 0) - (a.ts || 0));

    profiles = allProfiles;
    findings = allFindings;
    scannedAt = Date.now();
    meta = computeMeta(profiles, findings, scannedAt);
    reindex();
    persist();
    return meta;
  }

  function pushSnap(arr, e, relation) {
    if (arr.length >= MAX_SNAPSHOT) return;
    arr.push({
      timelineId: e.timelineId, ts: e.ts, sourceType: e.sourceType,
      category: e.category, severity: e.severity, title: e.title,
      domain: e.domain, relation,
    });
  }

  function normalizeRecord(r, a, extensionId, browser, prof) {
    const permissions = Array.isArray(a.permissions) ? a.permissions.map(String) : [];
    let hostPermissions = Array.isArray(a.hostPermissions) ? a.hostPermissions.map(String) : [];
    // Some manifests fold host patterns into permissions (MV2). Keep host-like
    // entries discoverable on both axes without losing the api/host split.
    const apiPerms = permissions.filter((p) => !/:\/\//.test(p) && p !== "<all_urls>");
    const hostLikeInPerms = permissions.filter((p) => /:\/\//.test(p) || p === "<all_urls>");
    hostPermissions = [...new Set([...hostPermissions, ...hostLikeInPerms])];

    return {
      key: `${browser}\u241F${prof}\u241F${extensionId}`,
      eventId: r.eventId || "",
      runId: r.runId || null,
      artifactId: r.artifactId || null,
      extensionId,
      name: r.title || a.name || extensionId,
      version: a.version || versionFromDetail(r.detail) || "",
      manifestVersion: a.manifestVersion != null ? a.manifestVersion : null,
      installTime: a.installTime != null ? a.installTime : (r.ts != null ? r.ts : null),
      updateTime: a.updateTime != null ? a.updateTime : null,
      enabledState: a.enabledState || "unknown",
      sourcePath: a.sourcePath || "",
      addonType: a.addonType || "",
      permissions: apiPerms,
      hostPermissions,
      browser,
      browserFamily: r.browserFamily || "",
      profile: prof,
      host: r.host || "",
      acquiredAt: r.acquiredAt != null ? r.acquiredAt : null,
    };
  }

  /* --------------------------- risk assessment -------------------------- */

  function assess(ext) {
    const ref = ext.acquiredAt || Date.now();
    const out = [];
    const add = (reason, severity, evidence, ts) => {
      out.push({
        findingId: extFindingId(ext.browser, ext.extensionId, reason),
        extensionId: ext.extensionId,
        severity,
        reason,
        evidence: evidence || "",
        ts: ts != null ? ts : ref,
      });
    };

    // ----- permission analysis -----
    const dangerous = [];
    for (const p of ext.permissions) {
      const info = PERM_RISK[p];
      if (info && sevRank(info.severity) >= sevRank("MEDIUM")) {
        dangerous.push(p);
        add(`dangerous-permission:${p}`, info.severity, info.label, ext.installTime);
      }
    }
    // excessive (count of declared api permissions)
    if (ext.permissions.length >= EXCESSIVE_API_HIGH) {
      add("excessive-permissions", "HIGH", `${ext.permissions.length} API permissions declared`, ext.installTime);
    } else if (ext.permissions.length >= EXCESSIVE_API_MEDIUM) {
      add("excessive-permissions", "MEDIUM", `${ext.permissions.length} API permissions declared`, ext.installTime);
    }

    // ----- host permission analysis -----
    const allUrls = ext.hostPermissions.some(isAllUrlsPattern);
    const wildcardHosts = ext.hostPermissions.filter(isWildcardHostPattern);
    const fileHosts = ext.hostPermissions.filter(isFilePattern);
    if (allUrls) {
      add("all-urls-host-permission", "CRITICAL", "broad host access (<all_urls> / *://*/*)", ext.installTime);
    } else if (wildcardHosts.length) {
      add("wildcard-host-permission", "HIGH",
        `${wildcardHosts.length} wildcard host pattern(s): ${wildcardHosts.slice(0, 5).join(", ")}`, ext.installTime);
    }
    if (fileHosts.length) {
      add("file-host-permission", "HIGH",
        `file:// access: ${fileHosts.slice(0, 5).join(", ")}`, ext.installTime);
    }

    // ----- install/state/source heuristics -----
    if (ext.enabledState === "disabled") {
      add("disabled-but-installed", "INFO", "extension is installed but disabled", ext.installTime);
    }
    const sp = ext.sourcePath || "";
    const inStdExtDir = /[\\/](Extensions|extensions|browser-extension-data)[\\/]/.test(sp) ||
      /\.xpi$/i.test(sp);
    if (sp && !inStdExtDir) {
      add("unpacked-extension", "HIGH", `loaded from non-standard path: ${sp}`, ext.installTime);
    } else if (sp && /[\\/](Temp|tmp|Downloads|Desktop)[\\/]/i.test(sp)) {
      add("sideloaded-extension", "HIGH", `source in user/transient path: ${sp}`, ext.installTime);
    }
    if (/[\\/](polic|managed|enterprise)/i.test(sp) || ext.addonType === "locale") {
      add("enterprise-policy-indicator", "MEDIUM", `policy/managed source indicator: ${sp || ext.addonType}`, ext.installTime);
    }

    // recency relative to acquisition time
    if (ext.installTime && (ref - ext.installTime) <= RECENT_INSTALL_DAYS * DAY) {
      add("recently-installed", "MEDIUM",
        `installed ${Math.max(0, Math.round((ref - ext.installTime) / DAY))} day(s) before acquisition`, ext.installTime);
    }
    if (ext.updateTime && (ref - ext.updateTime) <= RECENT_UPDATE_DAYS * DAY) {
      add("recently-updated", "INFO",
        `updated ${Math.max(0, Math.round((ref - ext.updateTime) / DAY))} day(s) before acquisition`, ext.updateTime);
    }

    // ----- score & level -----
    let score = 0;
    let level = "INFO";
    for (const f of out) {
      score += SCORE_WEIGHT[f.severity] || 0;
      level = maxSeverity(level, f.severity);
    }
    // cumulative escalation (peak severity + accumulated risk load)
    if (level !== "CRITICAL" && score >= 60) level = "CRITICAL";
    else if (sevRank(level) < sevRank("HIGH") && score >= 20) level = "HIGH";
    else if (sevRank(level) < sevRank("MEDIUM") && score >= 6) level = "MEDIUM";

    const domains = [...new Set(ext.hostPermissions.map(hostFromPattern).map(nd).filter(Boolean))];
    const permissionsSummary = {
      total: ext.permissions.length + ext.hostPermissions.length,
      api: ext.permissions,
      host: ext.hostPermissions,
      dangerous,
      wildcardHosts: wildcardHosts.length > 0 || allUrls,
      allUrls,
      fileAccess: fileHosts.length > 0,
      domains,
    };

    const profile = {
      key: ext.key,
      extensionId: ext.extensionId,
      name: ext.name,
      version: ext.version || "?",
      manifestVersion: ext.manifestVersion != null ? ext.manifestVersion : "unknown",
      browser: ext.browser,
      browserFamily: ext.browserFamily,
      profile: ext.profile,
      host: ext.host,
      enabledState: ext.enabledState,
      sourcePath: ext.sourcePath,
      installTime: ext.installTime,
      updateTime: ext.updateTime,
      acquiredAt: ext.acquiredAt,
      installAge: ext.installTime ? (ref - ext.installTime) : null,
      updateAge: ext.updateTime ? (ref - ext.updateTime) : null,
      riskScore: score,
      riskLevel: level,
      findingCount: out.length,
      permissionsSummary,
      runId: ext.runId,
      artifactId: ext.artifactId,
      eventId: ext.eventId,
      // correlation stores filled by scan()
      relatedTimelineIds: [],
      relatedFindingIds: [],
    };

    return { profile, findings: out };
  }

  function computeMeta(profs, fnds, ts) {
    const byRiskLevel = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
    const byBrowser = {};
    let enabled = 0, disabled = 0, correlated = 0;
    for (const p of profs) {
      byRiskLevel[p.riskLevel] = (byRiskLevel[p.riskLevel] || 0) + 1;
      if (p.browser) byBrowser[p.browser] = (byBrowser[p.browser] || 0) + 1;
      if (p.enabledState === "enabled") enabled++;
      else if (p.enabledState === "disabled") disabled++;
      if ((p.relatedTimelineIds && p.relatedTimelineIds.length) ||
        (p.relatedFindingIds && p.relatedFindingIds.length)) correlated++;
    }
    for (const f of fnds) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    return {
      scanned: true, scannedAt: ts,
      total: profs.length, findingCount: fnds.length,
      byRiskLevel, bySeverity, byBrowser, enabled, disabled, correlated,
    };
  }

  /* --------------------------- query / detail --------------------------- */

  function matchesProfile(p, f) {
    if (f.riskLevel && p.riskLevel !== f.riskLevel) return false;
    if (f.browser && p.browser !== f.browser) return false;
    if (f.enabledState && p.enabledState !== f.enabledState) return false;
    if (f.correlatedOnly && !((p.relatedTimelineIds || []).length || (p.relatedFindingIds || []).length)) return false;
    if (f.q) {
      const q = String(f.q).toLowerCase();
      const hay = `${p.name} ${p.extensionId} ${p.version} ${(p.permissionsSummary.api || []).join(" ")} ${(p.permissionsSummary.host || []).join(" ")}`.toLowerCase();
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
    return {
      rows: rows.slice(offset, offset + limit),
      total, scanned: meta.scanned, scannedAt,
    };
  }

  function detail(extensionId, key) {
    let p = null;
    if (key && byKey.has(key)) p = byKey.get(key);
    else { const arr = byExtId.get(extensionId); p = arr && arr.length ? arr[0] : null; }
    if (!p) return null;
    const extFindings = findings.filter((x) => x.extensionId === p.extensionId)
      .sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.ts || 0) - (a.ts || 0));
    return {
      profile: p,
      findings: extFindings,
      relatedTimeline: p.relatedTimeline || [],
      relatedFindings: p.relatedFindings || [],
    };
  }

  function listFindings(f = {}) {
    let rows = [...findings];
    if (f.severity) rows = rows.filter((x) => x.severity === f.severity);
    if (f.extensionId) rows = rows.filter((x) => x.extensionId === f.extensionId);
    if (f.reason) rows = rows.filter((x) => x.reason.includes(f.reason));
    rows.sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.ts || 0) - (a.ts || 0));
    return { rows, total: rows.length };
  }

  function exportData(f = {}) {
    const profs = list({ ...f, limit: 5000 }).rows;
    const ids = new Set(profs.map((p) => p.extensionId));
    const fnds = findings.filter((x) => ids.has(x.extensionId));
    return {
      meta, scannedAt, generatedAt: Date.now(),
      filter: f || {}, profiles: profs, findings: fnds,
    };
  }

  function stats() { return { ...meta, scannedAt }; }
  function filters() {
    return {
      browsers: Object.keys(meta.byBrowser).sort(),
      riskLevels: SEVERITY_ORDER.filter((s) => meta.byRiskLevel[s]),
      total: meta.total, scanned: meta.scanned, scannedAt,
    };
  }

  function clear() {
    profiles = []; findings = []; meta = emptyMeta(); scannedAt = 0;
    byKey = new Map(); byExtId = new Map();
    try { fs.writeFileSync(sidecarPath, JSON.stringify({ version: FORMAT_VERSION, scannedAt: 0, meta, profiles: [], findings: [] }, null, 2)); } catch { /* ignore */ }
    return { ok: true };
  }

  return {
    scan, list, detail, listFindings, exportData, stats, filters, clear,
    sidecarPath,
  };
}

module.exports = { createExtensionEngine, SEVERITY_RANK, SEVERITY_ORDER, PERM_RISK };
