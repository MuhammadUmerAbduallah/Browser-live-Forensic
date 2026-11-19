// hunting.js
// Advanced Threat Hunting Engine.
//
// Proactive, metadata-only threat hunting across every evidence source the
// platform already collects (live monitoring events, the unified timeline,
// extension & cache forensics, investigation findings, sessions, graph
// relationships and the IOC database). It is a pure correlator/aggregator:
// db.js injects a read-only snapshot and this engine derives threat findings,
// atomic indicators and multi-stage threat chains. It never re-acquires data,
// never recomputes integrity/timeline state and changes no schema.
//
// Architecture:
//   * Each hunt scans the evidence and emits atomic INDICATORS (huntType,
//     severity, domain, ts, timelineIds) plus rollup FINDINGS.
//   * A correlation pass groups indicators by registrable domain (and temporal
//     proximity) into multi-stage THREAT CHAINS. Future detections plug in as
//     additional indicator emitters with no schema change.
//
// Storage: a single JSON sidecar (hunting.json), mirroring the project pattern.
//
// Every threat finding contains: findingId, huntType, severity,
// confidenceScore, evidence, recommendation, ts.
// Every threat chain contains: chainId, severity, confidenceScore, startTs,
// endTs, indicators[], relatedTimelineIds[], relatedFindingIds[],
// relatedDomains[], relatedExtensions[].

const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const risk = require("./risk");

const SIDECAR = "hunting.json";
const FORMAT_VERSION = 1;

const SEVERITY_RANK = { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "INFO"];
const SCORE_WEIGHT = { INFO: 1, MEDIUM: 5, HIGH: 15, CRITICAL: 40 };
function sevRank(s) { return SEVERITY_RANK[s] != null ? SEVERITY_RANK[s] : 0; }
function maxSeverity(a, b) { return sevRank(a) >= sevRank(b) ? a : b; }

const HUNT_TYPES = [
  "session-hijacking", "fingerprinting", "webrtc-exposure", "redirect-chain",
  "drive-by-download", "cookie-abuse", "service-worker-abuse", "extension-abuse",
  "tracker-escalation", "multi-stage",
];
const HUNT_LABELS = {
  "session-hijacking": "Session Hijacking Indicators",
  fingerprinting: "Browser Fingerprinting Indicators",
  "webrtc-exposure": "WebRTC Exposure Indicators",
  "redirect-chain": "Malicious Redirect Chains",
  "drive-by-download": "Drive-by Download Indicators",
  "cookie-abuse": "Cookie Abuse Indicators",
  "service-worker-abuse": "Service Worker Abuse Indicators",
  "extension-abuse": "Extension Abuse Indicators",
  "tracker-escalation": "Tracker Escalation Chains",
  "multi-stage": "Multi-Stage Threat Chains",
};
const RECOMMENDATIONS = {
  "session-hijacking": "Invalidate and rotate affected session cookies; verify no cross-domain token reuse.",
  fingerprinting: "Review fingerprinting scripts; consider anti-fingerprinting controls and blocking the origin.",
  "webrtc-exposure": "Audit WebRTC/media usage; disable WebRTC or enforce a proxy to prevent local-IP leakage.",
  "redirect-chain": "Inspect the redirect chain endpoints; block suspicious hops and the terminal domain.",
  "drive-by-download": "Quarantine and hash the downloaded artifact; verify it was user-initiated.",
  "cookie-abuse": "Clear excessive/tracking cookies; review consent and tracker-blocking policy.",
  "service-worker-abuse": "Unregister the service worker; clear its cache and review its scope/script origin.",
  "extension-abuse": "Review and remove the extension; audit its permissions and update history.",
  "tracker-escalation": "Block the tracker cluster; review cross-site tracking exposure.",
  "multi-stage": "Treat as a correlated incident; preserve evidence and follow the per-stage recommendations.",
};

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const EXEC_EXT = new Set(["exe", "dll", "msi", "scr", "bat", "cmd", "com", "ps1", "vbs", "js", "jar", "apk", "dmg", "pkg", "deb", "rpm", "sh"]);
const ARCHIVE_EXT = new Set(["zip", "rar", "7z", "gz", "tar", "tgz", "cab", "iso", "bz2", "xz"]);
const SESSION_COOKIE_RE = /(sess|sid|sessionid|token|auth|jwt|sso|csrf|xsrf)/i;
const STUN_TURN_RE = /(^|\.)(stun|turn)\d*\.|:3478|:5349|stun:|turn:/i;

function nd(v) { return risk.normalizeDomain(v) || ""; }
function lc(s) { return String(s == null ? "" : s).toLowerCase(); }
function extOf(u) { const m = lc(u).match(/\.([a-z0-9]+)(?:[?#]|$)/); return m ? m[1] : ""; }

function hid(prefix, parts) {
  return prefix + crypto.createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 20);
}

/* =============================== engine ================================= */

function createHuntingEngine(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  const sidecarPath = path.join(dataDir, SIDECAR);

  /** @type {object[]} */ let findings = [];
  /** @type {object[]} */ let chains = [];
  /** @type {object[]} */ let indicators = [];
  let meta = emptyMeta();
  let scannedAt = 0;
  let byFinding = new Map();
  let byChain = new Map();

  load();

  function emptyMeta() {
    return {
      scanned: false, scannedAt: 0,
      findingCount: 0, chainCount: 0, indicatorCount: 0,
      bySeverity: { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 },
      byHunt: {}, integrity: null, maxSeverity: "INFO",
    };
  }
  function load() {
    if (!fs.existsSync(sidecarPath)) return;
    try {
      const s = JSON.parse(fs.readFileSync(sidecarPath, "utf8"));
      findings = s.findings || []; chains = s.chains || []; indicators = s.indicators || [];
      meta = s.meta || emptyMeta(); scannedAt = s.scannedAt || 0;
      reindex();
    } catch { findings = []; chains = []; indicators = []; meta = emptyMeta(); scannedAt = 0; byFinding = new Map(); byChain = new Map(); }
  }
  function reindex() {
    byFinding = new Map(); byChain = new Map();
    for (const f of findings) byFinding.set(f.findingId, f);
    for (const c of chains) byChain.set(c.chainId, c);
  }
  function persist() {
    fs.writeFileSync(sidecarPath, JSON.stringify({
      version: FORMAT_VERSION, scannedAt, meta, findings, chains,
      indicators: indicators.slice(0, 5000),
    }, null, 2));
  }

  /* ------------------------------- scan --------------------------------- */

  function scan(inputs = {}) {
    const ctx = buildContext(inputs);

    const F = [];   // findings
    const I = [];   // indicators
    const emit = {
      finding: (huntType, severity, confidence, key, evidence, extra) => {
        const f = {
          findingId: hid("thf_", [huntType, key]),
          huntType, severity,
          confidenceScore: Math.round(confidence * 100) / 100,
          evidence: evidence || "",
          recommendation: RECOMMENDATIONS[huntType] || "",
          ts: (extra && extra.ts) || ctx.now,
          title: (extra && extra.title) || HUNT_LABELS[huntType],
          relatedTimelineIds: ((extra && extra.timelineIds) || []).slice(0, 100),
          relatedDomains: ((extra && extra.domains) || []).slice(0, 50),
          relatedFindingIds: ((extra && extra.findingIds) || []).slice(0, 50),
          relatedExtensions: ((extra && extra.extensions) || []).slice(0, 50),
          indicatorCount: (extra && extra.indicatorCount) || 0,
        };
        F.push(f);
        return f;
      },
      indicator: (huntType, type, severity, domain, ts, evidence, timelineIds, extra) => {
        const i = {
          indicatorId: hid("ind_", [huntType, type, domain || "", String(ts || 0)]),
          huntType, type, severity,
          domain: domain || "", ts: ts || ctx.now,
          evidence: evidence || "",
          timelineIds: (timelineIds || []).slice(0, 40),
          findingIds: (extra && extra.findingIds) || [],
          extensions: (extra && extra.extensions) || [],
        };
        I.push(i);
        return i;
      },
    };

    HUNTS.forEach((h) => { try { h(ctx, emit); } catch (e) { /* a hunt never breaks the scan */ } });

    // ---- correlate indicators into multi-stage threat chains ----
    const builtChains = correlateChains(I, F, ctx);

    findings = F.sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.confidenceScore - a.confidenceScore));
    indicators = I.sort((a, b) => (a.ts || 0) - (b.ts || 0));
    chains = builtChains.sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.confidenceScore - a.confidenceScore));
    scannedAt = Date.now();
    meta = computeMeta(ctx);
    reindex();
    persist();
    return meta;
  }

  /* --------------------------- context build ---------------------------- */

  function buildContext(inputs) {
    const events = inputs.liveEvents || [];
    const timelineEntries = inputs.timelineEntries || [];
    const tlByEventId = new Map();
    const tlByDomain = new Map();
    for (const e of timelineEntries) {
      if (e.eventId) tlByEventId.set(e.eventId, e.timelineId);
      if (e.domain) (tlByDomain.get(e.domain) || tlByDomain.set(e.domain, []).get(e.domain)).push(e.timelineId);
    }
    const extProfiles = inputs.extensions || [];
    const extByDomain = new Map();
    for (const p of extProfiles) {
      for (const d of ((p.permissionsSummary && p.permissionsSummary.domains) || [])) {
        (extByDomain.get(d) || extByDomain.set(d, []).get(d)).push(p);
      }
    }
    const ioc = inputs.ioc || null;
    return {
      now: Date.now(),
      events,
      timelineEntries,
      tlByEventId, tlByDomain, extByDomain,
      extProfiles,
      extFindings: inputs.extensionFindings || [],
      cacheProfiles: inputs.cacheProfiles || [],
      cacheFindings: inputs.cacheFindings || [],
      investigationFindings: inputs.investigationFindings || [],
      sessions: inputs.sessions || [],
      graph: inputs.graph || {},
      integrity: inputs.integrity || null,
      ioc,
      isTracker: (d) => ioc ? ioc.isTracker(d) : risk.isTracker(d),
      isSuspDomain: (d) => ioc ? ioc.isSuspiciousDomain(d) : false,
      isSuspTld: (d) => ioc ? ioc.isSuspiciousTld(d) : risk.suspiciousTld(d),
      isExecutable: (u) => ioc ? ioc.isExecutable(u) : risk.EXECUTABLE_RE.test(lc(u)),
      tlForEvent: (e) => { const id = tlByEventId.get(e.id); return id ? [id] : []; },
      tlForDomain: (d) => (tlByDomain.get(d) || []).slice(0, 20),
      extForDomain: (d) => (extByDomain.get(d) || []),
    };
  }

  function eventsByType(ctx, type) { return ctx.events.filter((e) => e.type === type); }
  function rawOf(e) { return e.raw || {}; }

  /* ------------------------------- hunts -------------------------------- */

  // 1. Session hijacking indicators
  function huntSessionHijacking(ctx, emit) {
    const cookieEvents = eventsByType(ctx, "cookie");
    const byName = new Map();
    for (const e of cookieEvents) {
      const name = lc(e.name || (e.raw && e.raw.name) || "");
      const dom = nd(e.domain);
      if (!name || !dom) continue;
      const b = byName.get(name) || { domains: new Set(), tlIds: [], lastTs: 0 };
      b.domains.add(dom); b.tlIds.push(...ctx.tlForEvent(e)); b.lastTs = Math.max(b.lastTs, e.ts || 0);
      byName.set(name, b);
    }
    for (const [name, b] of byName) {
      const domains = [...b.domains];
      const sessionLike = SESSION_COOKIE_RE.test(name);
      if (domains.length >= 2 && (sessionLike || domains.length >= 3)) {
        const sev = sessionLike ? "HIGH" : "MEDIUM";
        emit.indicator("session-hijacking", "cross-domain-cookie-reuse", sev, domains[0], b.lastTs,
          `cookie "${name}" reused across ${domains.length} domains`, b.tlIds, {});
        emit.finding("session-hijacking", sev, sessionLike ? 0.7 : 0.5, `reuse:${name}`,
          `Session-style cookie "${name}" observed across ${domains.length} domains: ${domains.slice(0, 5).join(", ")}`,
          { ts: b.lastTs, domains, timelineIds: b.tlIds });
      }
    }
    // unusual session patterns from reconstructed sessions
    for (const s of ctx.sessions) {
      const trackers = (s.trackerDomains || []).length;
      const visited = (s.visitedDomains || []).length;
      if ((s.level === "HIGH" || s.peakRisk === "HIGH") && (trackers >= 3 || visited >= 8)) {
        emit.indicator("session-hijacking", "unusual-session-pattern", "MEDIUM", nd(s.primaryDomain), s.startTime,
          `high-risk session: ${visited} domains, ${trackers} trackers`, ctx.tlForDomain(nd(s.primaryDomain)), {});
        emit.finding("session-hijacking", "MEDIUM", 0.45, `session:${s.sessionId}`,
          `High-risk session ${s.sessionId} on ${s.primaryDomain}: ${visited} domains, ${trackers} trackers, ${s.cookiesCreated || 0} cookies`,
          { ts: s.startTime, domains: [nd(s.primaryDomain)], timelineIds: ctx.tlForDomain(nd(s.primaryDomain)) });
      }
    }
  }

  // 2. Browser fingerprinting indicators
  function huntFingerprinting(ctx, emit) {
    const fp = eventsByType(ctx, "fingerprint");
    const byDomain = new Map();
    for (const e of fp) {
      const dom = nd(e.domain);
      const method = lc((e.raw && e.raw.method) || e.name || "unknown");
      if (!dom) continue;
      const b = byDomain.get(dom) || { methods: new Set(), tlIds: [], lastTs: 0 };
      b.methods.add(method); b.tlIds.push(...ctx.tlForEvent(e)); b.lastTs = Math.max(b.lastTs, e.ts || 0);
      byDomain.set(dom, b);
    }
    for (const [dom, b] of byDomain) {
      const methods = [...b.methods];
      const composite = methods.length >= 2;
      const sev = composite ? "HIGH" : "MEDIUM";
      for (const m of methods) {
        emit.indicator("fingerprinting", `fp-${m}`, composite ? "HIGH" : "MEDIUM", dom, b.lastTs,
          `${m} fingerprinting on ${dom}`, b.tlIds, {});
      }
      // tracking persistence: fp domain also writes storage / has cookies
      const persists = ctx.events.some((e) => nd(e.domain) === dom && (e.type === "storage" || e.type === "cookie"));
      const conf = Math.min(0.95, 0.4 + 0.15 * methods.length + (persists ? 0.15 : 0));
      emit.finding("fingerprinting", persists ? maxSeverity(sev, "HIGH") : sev, conf, `fp:${dom}`,
        `${composite ? "Composite" : "Single-vector"} fingerprinting on ${dom} via ${methods.join(", ")}${persists ? " with persistent storage" : ""}`,
        { ts: b.lastTs, domains: [dom], timelineIds: b.tlIds });
    }
  }

  // 3. WebRTC exposure indicators
  function huntWebRtc(ctx, emit) {
    // STUN/TURN signalling inferred from request URLs/hosts
    const stun = ctx.events.filter((e) => (e.type === "request" || e.type === "tracker") &&
      STUN_TURN_RE.test(lc((e.raw && e.raw.requestUrl) || e.url || e.domain || "")));
    const stunDomains = new Map();
    for (const e of stun) {
      const dom = nd(e.domain) || nd((e.raw && e.raw.requestUrl)); if (!dom) continue;
      const b = stunDomains.get(dom) || { tlIds: [], lastTs: 0, n: 0 };
      b.tlIds.push(...ctx.tlForEvent(e)); b.lastTs = Math.max(b.lastTs, e.ts || 0); b.n++;
      stunDomains.set(dom, b);
    }
    for (const [dom, b] of stunDomains) {
      emit.indicator("webrtc-exposure", "stun-turn-activity", "MEDIUM", dom, b.lastTs,
        `${b.n} STUN/TURN signalling request(s) to ${dom}`, b.tlIds, {});
      emit.finding("webrtc-exposure", b.n >= 3 ? "HIGH" : "MEDIUM", b.n >= 3 ? 0.6 : 0.45, `stun:${dom}`,
        `WebRTC STUN/TURN signalling to ${dom} (${b.n} requests) — potential local-IP exposure`,
        { ts: b.lastTs, domains: [dom], timelineIds: b.tlIds });
    }
    // media access (camera/mic) clustering -> WebRTC media use
    const media = ctx.events.filter((e) => e.type === "permission" &&
      /(camera|microphone)/i.test((e.raw && e.raw.permission) || e.name || ""));
    const byDom = new Map();
    for (const e of media) { const d = nd(e.domain); if (!d) continue; const b = byDom.get(d) || { n: 0, tlIds: [], ts: 0 }; b.n++; b.tlIds.push(...ctx.tlForEvent(e)); b.ts = Math.max(b.ts, e.ts || 0); byDom.set(d, b); }
    for (const [d, b] of byDom) {
      emit.indicator("webrtc-exposure", "media-access", "INFO", d, b.ts, `camera/microphone access on ${d}`, b.tlIds, {});
      if (b.n >= 2) emit.finding("webrtc-exposure", "MEDIUM", 0.4, `media:${d}`,
        `Repeated media-device access on ${d} (${b.n}×) — review for WebRTC IP leakage`,
        { ts: b.ts, domains: [d], timelineIds: b.tlIds });
    }
  }

  // 4. Malicious redirect chains
  function huntRedirects(ctx, emit) {
    const reqs = ctx.events.filter((e) => (e.type === "request" || e.type === "tracker" || e.type === "navigation") &&
      rawOf(e).statusCode != null).sort((a, b) => (a.ts || 0) - (b.ts || 0));
    const byDomain = new Map();
    const redirects = reqs.filter((e) => REDIRECT_STATUS.has(Number(rawOf(e).statusCode)));
    for (const e of redirects) {
      const d = nd(e.domain); if (!d) continue;
      const b = byDomain.get(d) || { n: 0, tlIds: [], ts: 0 }; b.n++; b.tlIds.push(...ctx.tlForEvent(e)); b.ts = Math.max(b.ts, e.ts || 0); byDomain.set(d, b);
    }
    for (const [d, b] of byDomain) {
      const suspicious = ctx.isSuspTld(d) || ctx.isSuspDomain(d);
      if (b.n >= 5 || suspicious) {
        const sev = suspicious ? "HIGH" : (b.n >= 8 ? "HIGH" : "MEDIUM");
        emit.indicator("redirect-chain", suspicious ? "suspicious-redirect-domain" : "excessive-redirects", sev, d, b.ts,
          `${b.n} redirect responses for ${d}${suspicious ? " (suspicious domain)" : ""}`, b.tlIds, {});
        emit.finding("redirect-chain", sev, suspicious ? 0.65 : 0.5, `redir:${d}`,
          `${b.n} cached/observed redirects involving ${d}${suspicious ? " — suspicious domain" : ""}`,
          { ts: b.ts, domains: [d], timelineIds: b.tlIds });
      }
    }
    // cross-domain redirect chain within a short window
    let windowStart = 0; let windowDomains = new Set(); let windowTl = [];
    for (const e of redirects) {
      const ts = e.ts || 0;
      if (ts - windowStart > 10000) { windowStart = ts; windowDomains = new Set(); windowTl = []; }
      windowDomains.add(nd(e.domain)); windowTl.push(...ctx.tlForEvent(e));
      if (windowDomains.size >= 3) {
        emit.indicator("redirect-chain", "cross-domain-chain", "HIGH", [...windowDomains][0], ts,
          `cross-domain redirect chain across ${windowDomains.size} domains`, windowTl.slice(0, 40), {});
        emit.finding("redirect-chain", "HIGH", 0.6, `redir-chain:${windowStart}`,
          `Cross-domain redirect chain across ${windowDomains.size} domains within 10s: ${[...windowDomains].slice(0, 6).join(" → ")}`,
          { ts, domains: [...windowDomains], timelineIds: windowTl });
        windowDomains = new Set(); windowTl = [];
      }
    }
    // reuse cache redirect findings
    for (const f of ctx.cacheFindings.filter((x) => x.reason === "excessive-redirect-chain")) {
      emit.indicator("redirect-chain", "cache-redirect", "MEDIUM", "", f.ts, f.evidence, [], { findingIds: [f.findingId] });
    }
  }

  // 5. Drive-by download indicators
  function huntDriveBy(ctx, emit) {
    const dls = eventsByType(ctx, "download").sort((a, b) => (a.ts || 0) - (b.ts || 0));
    const navs = eventsByType(ctx, "navigation").concat(eventsByType(ctx, "tab"));
    let recent = [];
    for (const e of dls) {
      const name = (e.raw && e.raw.filename) || e.url || (e.raw && e.raw.url) || "";
      const dom = nd(e.domain) || nd(name);
      const ext = extOf(name);
      const exe = EXEC_EXT.has(ext) || ctx.isExecutable(name);
      const arch = ARCHIVE_EXT.has(ext);
      const susp = dom && (ctx.isSuspTld(dom) || ctx.isSuspDomain(dom));
      const tlIds = ctx.tlForEvent(e);
      // automatic: no navigation to this domain in the preceding 5s
      const navMatch = navs.some((n) => Math.abs((n.ts || 0) - (e.ts || 0)) <= 5000 && nd(n.domain) === dom);
      if (exe || arch) {
        const sev = susp ? "CRITICAL" : (exe ? "HIGH" : "MEDIUM");
        emit.indicator("drive-by-download", exe ? "suspicious-executable" : "suspicious-archive", sev, dom, e.ts,
          `${exe ? "executable" : "archive"} download ${name}${susp ? " from suspicious domain" : ""}`, tlIds, {});
        emit.finding("drive-by-download", sev, susp ? 0.85 : (exe ? 0.6 : 0.45), `dl:${name}:${dom}`,
          `${exe ? "Executable" : "Archive"} download "${name}" from ${dom || "?"}${susp ? " (suspicious domain)" : ""}${!navMatch ? " with no matching navigation (possible automatic download)" : ""}`,
          { ts: e.ts, domains: dom ? [dom] : [], timelineIds: tlIds });
      } else if (!navMatch) {
        emit.indicator("drive-by-download", "automatic-download", "MEDIUM", dom, e.ts,
          `download ${name} with no preceding navigation`, tlIds, {});
      }
      // chained downloads: multiple within 8s
      recent = recent.filter((r) => (e.ts || 0) - r.ts <= 8000);
      recent.push({ ts: e.ts || 0, dom, tlIds });
      if (recent.length >= 3) {
        emit.indicator("drive-by-download", "chained-downloads", "HIGH", dom, e.ts,
          `${recent.length} downloads within 8s`, recent.flatMap((r) => r.tlIds), {});
        emit.finding("drive-by-download", "HIGH", 0.55, `dl-chain:${e.ts}`,
          `Chained download behavior: ${recent.length} downloads within 8 seconds`,
          { ts: e.ts, domains: [...new Set(recent.map((r) => r.dom).filter(Boolean))], timelineIds: recent.flatMap((r) => r.tlIds) });
        recent = [];
      }
    }
    // reuse cache executable artifacts
    for (const f of ctx.cacheFindings.filter((x) => x.reason === "suspicious-cached-executable")) {
      emit.indicator("drive-by-download", "cached-executable", "HIGH", "", f.ts, f.evidence, [], { findingIds: [f.findingId] });
    }
  }

  // 6. Cookie abuse indicators
  function huntCookieAbuse(ctx, emit) {
    const cookies = eventsByType(ctx, "cookie").sort((a, b) => (a.ts || 0) - (b.ts || 0));
    const byDomain = new Map();
    for (const e of cookies) {
      const d = nd(e.domain); if (!d) continue;
      const b = byDomain.get(d) || { n: 0, tlIds: [], ts: 0, names: new Set() };
      b.n++; b.tlIds.push(...ctx.tlForEvent(e)); b.ts = Math.max(b.ts, e.ts || 0);
      b.names.add(lc(e.name || "")); byDomain.set(d, b);
    }
    for (const [d, b] of byDomain) {
      const tracker = ctx.isTracker(d);
      if (b.n >= 10) {
        const sev = tracker ? "HIGH" : "MEDIUM";
        emit.indicator("cookie-abuse", "excessive-cookie-creation", sev, d, b.ts,
          `${b.n} cookie writes on ${d}`, b.tlIds, {});
        emit.finding("cookie-abuse", sev, tracker ? 0.6 : 0.45, `cookies:${d}`,
          `Excessive cookie creation on ${d}: ${b.n} writes (${b.names.size} distinct)${tracker ? " — tracker domain (possible stuffing)" : ""}`,
          { ts: b.ts, domains: [d], timelineIds: b.tlIds });
      }
      if (tracker && b.n >= 1) {
        emit.indicator("cookie-abuse", "tracking-cookie", "INFO", d, b.ts, `tracking cookies on ${d}`, b.tlIds, {});
      }
    }
    // long-lived tracking cookies from acquired cookie timeline entries (expireTime in tags/cache)
    for (const e of ctx.timelineEntries.filter((x) => x.category === "cookie" && (x.tags || []).includes("tracker"))) {
      emit.indicator("cookie-abuse", "long-lived-tracking-cookie", "INFO", e.domain, e.ts,
        `persistent tracking cookie on ${e.domain}`, [e.timelineId], {});
    }
  }

  // 7. Service worker abuse indicators
  function huntServiceWorker(ctx, emit) {
    const swProfiles = ctx.cacheProfiles.filter((p) => p.cacheType === "serviceworker");
    for (const p of swProfiles) {
      const scope = p.scope || p.cacheName || "";
      const dom = nd(scope) || (p.domainSample || [])[0] || "";
      const broad = /^https?:\/\/[^/]+\/?$/.test(scope) || /\/$/.test(scope);
      const susp = dom && (ctx.isSuspDomain(dom) || ctx.isSuspTld(dom) || ctx.isTracker(dom));
      const sev = susp ? "HIGH" : (broad ? "MEDIUM" : "INFO");
      emit.indicator("service-worker-abuse", susp ? "suspicious-service-worker" : "sw-persistence", sev, dom, p.updateTime || ctx.now,
        `service worker scope ${scope || "?"}${broad ? " (broad)" : ""}`, ctx.tlForDomain(dom), {});
      if (sev !== "INFO") emit.finding("service-worker-abuse", sev, susp ? 0.6 : 0.4, `sw:${p.cacheId}`,
        `Persistent service worker${scope ? " scope " + scope : ""}${broad ? " (broad scope)" : ""}${susp ? " on flagged domain" : ""}`,
        { ts: p.updateTime || ctx.now, domains: dom ? [dom] : [], timelineIds: ctx.tlForDomain(dom) });
    }
    // timeline serviceworker entries with no cache profile
    for (const e of ctx.timelineEntries.filter((x) => x.category === "serviceworker")) {
      if (e.domain && (ctx.isTracker(e.domain) || ctx.isSuspTld(e.domain))) {
        emit.indicator("service-worker-abuse", "suspicious-service-worker", "MEDIUM", e.domain, e.ts,
          `service worker on flagged domain ${e.domain}`, [e.timelineId], {});
      }
    }
  }

  // 8. Extension abuse indicators (aggregate existing extension findings)
  function huntExtensions(ctx, emit) {
    const byExt = new Map();
    for (const f of ctx.extFindings) {
      const b = byExt.get(f.extensionId) || { reasons: [], sev: "INFO", ts: 0 };
      b.reasons.push(f.reason); b.sev = maxSeverity(b.sev, f.severity); b.ts = Math.max(b.ts, f.ts || 0);
      byExt.set(f.extensionId, b);
    }
    for (const p of ctx.extProfiles) {
      const agg = byExt.get(p.extensionId);
      const domains = (p.permissionsSummary && p.permissionsSummary.domains) || [];
      const reasons = agg ? agg.reasons : [];
      const dangerous = reasons.some((r) => r.startsWith("dangerous-permission") || r === "all-urls-host-permission" || r === "native-messaging");
      const persists = reasons.includes("recently-updated") || reasons.includes("recently-installed") || p.enabledState === "enabled";
      if (sevRank(p.riskLevel) >= sevRank("MEDIUM")) {
        emit.indicator("extension-abuse", dangerous ? "dangerous-permissions" : "extension-risk", p.riskLevel, "", p.installTime || ctx.now,
          `${p.name}: ${reasons.slice(0, 4).join(", ") || "elevated risk"}`, p.relatedTimelineIds || [], { extensions: [p.extensionId] });
        emit.finding("extension-abuse", p.riskLevel, Math.min(0.9, 0.4 + 0.1 * reasons.length), `ext:${p.extensionId}`,
          `Extension "${p.name}" (${p.browser || "?"}) risk ${p.riskLevel}: ${reasons.slice(0, 6).join(", ") || "elevated risk"}${persists ? " · persistent" : ""}`,
          { ts: p.installTime || ctx.now, domains, timelineIds: p.relatedTimelineIds || [], extensions: [p.extensionId], findingIds: (p.relatedFindingIds || []) });
      }
    }
  }

  // 9. Tracker escalation chains
  function huntTrackerEscalation(ctx, emit) {
    const trackerEvents = ctx.events.filter((e) => e.type === "tracker" || (e.raw && e.raw.trackerDetected) || (e.domain && ctx.isTracker(e.domain)));
    const byTracker = new Map();
    const firstPartyByTracker = new Map();
    for (const e of trackerEvents) {
      const d = nd(e.domain); if (!d) continue;
      const b = byTracker.get(d) || { n: 0, tlIds: [], ts: 0 }; b.n++; b.tlIds.push(...ctx.tlForEvent(e)); b.ts = Math.max(b.ts, e.ts || 0); byTracker.set(d, b);
      const fp = (e.raw && e.raw.pageDomain) || (e.raw && e.raw.tabDomain) || "";
      if (fp) (firstPartyByTracker.get(d) || firstPartyByTracker.set(d, new Set()).get(d)).add(nd(fp));
    }
    const trackers = [...byTracker.keys()];
    if (trackers.length >= 5) {
      const tlIds = trackers.flatMap((d) => byTracker.get(d).tlIds).slice(0, 60);
      emit.indicator("tracker-escalation", "tracker-clustering", "MEDIUM", trackers[0], ctx.now,
        `${trackers.length} distinct tracker domains contacted`, tlIds, {});
      emit.finding("tracker-escalation", trackers.length >= 12 ? "HIGH" : "MEDIUM", Math.min(0.85, 0.4 + 0.03 * trackers.length), `tracker-cluster`,
        `Tracker cluster: ${trackers.length} distinct tracker/analytics domains contacted`,
        { ts: ctx.now, domains: trackers.slice(0, 50), timelineIds: tlIds });
    }
    for (const [d, fps] of firstPartyByTracker) {
      if (fps.size >= 3) {
        emit.indicator("tracker-escalation", "cross-site-tracking", "MEDIUM", d, byTracker.get(d).ts,
          `${d} present across ${fps.size} first-party sites`, byTracker.get(d).tlIds, {});
        emit.finding("tracker-escalation", "MEDIUM", 0.55, `xsite:${d}`,
          `Cross-site tracker ${d} observed across ${fps.size} first-party sites`,
          { ts: byTracker.get(d).ts, domains: [d, ...fps], timelineIds: byTracker.get(d).tlIds });
      }
    }
    // tracker persistence: tracker domain with storage/cookie/SW
    for (const [d, b] of byTracker) {
      const persists = ctx.events.some((e) => nd(e.domain) === d && (e.type === "storage" || e.type === "cookie")) ||
        ctx.cacheProfiles.some((p) => p.cacheType === "serviceworker" && (p.domainSample || []).includes(d));
      if (persists && b.n >= 2) {
        emit.indicator("tracker-escalation", "tracker-persistence", "MEDIUM", d, b.ts,
          `persistent tracker ${d} (storage/SW present)`, b.tlIds, {});
      }
    }
  }

  const HUNTS = [
    huntSessionHijacking, huntFingerprinting, huntWebRtc, huntRedirects,
    huntDriveBy, huntCookieAbuse, huntServiceWorker, huntExtensions, huntTrackerEscalation,
  ];

  /* ----------------------- multi-stage chain builder -------------------- */

  function correlateChains(I, F, ctx) {
    // Group indicators by registrable domain.
    const byDomain = new Map();
    for (const ind of I) {
      const d = nd(ind.domain);
      if (!d) continue;
      (byDomain.get(d) || byDomain.set(d, []).get(d)).push(ind);
    }
    const findingsByDomain = new Map();
    for (const f of F) for (const d of (f.relatedDomains || [])) (findingsByDomain.get(nd(d)) || findingsByDomain.set(nd(d), []).get(nd(d))).push(f.findingId);

    const out = [];
    for (const [domain, inds] of byDomain) {
      const huntTypes = new Set(inds.map((i) => i.huntType));
      if (huntTypes.size < 2 && inds.length < 3) continue; // not multi-stage
      const tsList = inds.map((i) => i.ts || 0).filter(Boolean).sort((a, b) => a - b);
      let severity = "INFO";
      for (const i of inds) severity = maxSeverity(severity, i.severity);
      // escalate when multiple distinct stages converge
      if (huntTypes.size >= 3) severity = maxSeverity(severity, "HIGH");
      if (huntTypes.size >= 4 && sevRank(severity) >= sevRank("HIGH")) severity = "CRITICAL";
      const confidence = Math.min(0.97, 0.4 + 0.12 * huntTypes.size + 0.03 * inds.length);
      const tlIds = [...new Set(inds.flatMap((i) => i.timelineIds))].slice(0, 200);
      const exts = [...new Set(inds.flatMap((i) => i.extensions || []))];
      const findingIds = [...new Set((findingsByDomain.get(domain) || []))].slice(0, 50);
      // related investigation findings on this domain
      const invFindingIds = ctx.investigationFindings
        .filter((f) => (f.affectedDomains || []).some((x) => nd(x) === domain))
        .map((f) => f.id).slice(0, 50);
      out.push({
        chainId: hid("chain_", [domain, [...huntTypes].sort().join(",")]),
        title: `Multi-stage activity on ${domain}`,
        domain,
        severity,
        confidenceScore: Math.round(confidence * 100) / 100,
        startTs: tsList[0] || ctx.now,
        endTs: tsList[tsList.length - 1] || ctx.now,
        huntTypes: [...huntTypes],
        indicators: inds.map((i) => ({ indicatorId: i.indicatorId, huntType: i.huntType, type: i.type, severity: i.severity, ts: i.ts, evidence: i.evidence })),
        relatedTimelineIds: tlIds,
        relatedFindingIds: [...new Set([...findingIds, ...invFindingIds])],
        relatedDomains: [domain],
        relatedExtensions: exts,
      });
    }
    return out;
  }

  function computeMeta(ctx) {
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, INFO: 0 };
    const byHunt = {};
    let maxSev = "INFO";
    for (const f of findings) {
      bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
      byHunt[f.huntType] = (byHunt[f.huntType] || 0) + 1;
      maxSev = maxSeverity(maxSev, f.severity);
    }
    for (const c of chains) { byHunt["multi-stage"] = (byHunt["multi-stage"] || 0) + 1; maxSev = maxSeverity(maxSev, c.severity); }
    const integ = ctx.integrity ? summarizeIntegrity(ctx.integrity) : null;
    return {
      scanned: true, scannedAt,
      findingCount: findings.length, chainCount: chains.length, indicatorCount: indicators.length,
      bySeverity, byHunt, maxSeverity: maxSev, integrity: integ,
    };
  }

  function summarizeIntegrity(st) {
    const by = (st && st.byStatus) || {};
    const total = st.total || 0;
    let overall = "UNVERIFIED";
    if (total > 0) {
      if ((by.MODIFIED || 0) > 0 || (by.MISSING || 0) > 0) overall = "COMPROMISED";
      else if ((by.UNKNOWN || 0) > 0) overall = "INCOMPLETE";
      else overall = "VERIFIED";
    }
    return { total, valid: by.VALID || 0, modified: by.MODIFIED || 0, missing: by.MISSING || 0, unknown: by.UNKNOWN || 0, overall };
  }

  /* --------------------------- query / detail --------------------------- */

  function matchesFinding(f, q) {
    if (q.huntType && f.huntType !== q.huntType) return false;
    if (q.severity && f.severity !== q.severity) return false;
    if (q.minSeverity && sevRank(f.severity) < sevRank(q.minSeverity)) return false;
    if (q.q) {
      const s = lc(q.q);
      if (!lc(`${f.title} ${f.evidence} ${f.huntType} ${(f.relatedDomains || []).join(" ")}`).includes(s)) return false;
    }
    return true;
  }

  function list(f = {}) {
    let rows = findings.filter((x) => matchesFinding(x, f));
    rows.sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.confidenceScore - a.confidenceScore) || (b.ts - a.ts));
    const total = rows.length;
    const limit = Math.min(Number(f.limit) || 500, 5000);
    const offset = Number(f.offset) || 0;
    return { rows: rows.slice(offset, offset + limit), total, scanned: meta.scanned, scannedAt };
  }

  function listChains(f = {}) {
    let rows = [...chains];
    if (f.severity) rows = rows.filter((c) => c.severity === f.severity);
    if (f.minSeverity) rows = rows.filter((c) => sevRank(c.severity) >= sevRank(f.minSeverity));
    if (f.q) { const s = lc(f.q); rows = rows.filter((c) => lc(`${c.title} ${c.domain} ${(c.huntTypes || []).join(" ")}`).includes(s)); }
    rows.sort((a, b) => (sevRank(b.severity) - sevRank(a.severity)) || (b.confidenceScore - a.confidenceScore));
    const total = rows.length;
    const limit = Math.min(Number(f.limit) || 500, 5000);
    return { rows: rows.slice(0, limit), total, scanned: meta.scanned, scannedAt };
  }

  function detail(id) {
    if (byChain.has(id)) {
      const c = byChain.get(id);
      const memberFindings = findings.filter((f) => c.huntTypes.includes(f.huntType) && (f.relatedDomains || []).some((d) => nd(d) === c.domain));
      return { kind: "chain", chain: c, findings: memberFindings };
    }
    const f = byFinding.get(id);
    if (!f) return null;
    const inChains = chains.filter((c) => (c.relatedDomains || []).some((d) => (f.relatedDomains || []).map(nd).includes(nd(d))));
    return { kind: "finding", finding: f, chains: inChains };
  }

  function exportData(f = {}) {
    const fnd = findings.filter((x) => matchesFinding(x, f));
    return { meta, scannedAt, generatedAt: Date.now(), filter: f || {}, findings: fnd, chains };
  }

  function stats() { return { ...meta, scannedAt }; }
  function filters() {
    return {
      huntTypes: Object.keys(meta.byHunt).sort(),
      severities: SEVERITY_ORDER.filter((s) => meta.bySeverity[s]),
      labels: HUNT_LABELS, scanned: meta.scanned, scannedAt,
    };
  }

  function clear() {
    findings = []; chains = []; indicators = []; meta = emptyMeta(); scannedAt = 0;
    byFinding = new Map(); byChain = new Map();
    try { fs.writeFileSync(sidecarPath, JSON.stringify({ version: FORMAT_VERSION, scannedAt: 0, meta, findings: [], chains: [], indicators: [] }, null, 2)); } catch { /* ignore */ }
    return { ok: true };
  }

  return {
    scan, list, listChains, detail, exportData, stats, filters, clear,
    types: HUNT_TYPES, labels: HUNT_LABELS, sidecarPath,
  };
}

module.exports = { createHuntingEngine, HUNT_TYPES, HUNT_LABELS, SEVERITY_ORDER };
