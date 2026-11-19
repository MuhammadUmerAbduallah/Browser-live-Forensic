// detect.js
// IOC & Behavioral Detection Engine. Pure and dependency-light: consumes
// reconstructed session objects (each with a chronological `.events` array of
// stored events) plus an IOC database, and emits forensic findings.
//
// Finding shape:
//   { id, rule, severity, title, description, confidence,
//     firstSeen, lastSeen, evidence, affectedDomains, affectedSessions,
//     relatedEventIds, primaryDomain }
//
// Detection is deterministic: a given pattern always yields the same finding
// id (anchored on its terminal event, or the session for session-level rules),
// so repeated/incremental runs upsert rather than duplicate.

const SEVERITY_RANK = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
const MAX_PER_RULE = 5; // cap instances per rule per session

/* --------------------------------- helpers -------------------------------- */

function isNav(e) { return e.type === "navigation" || e.type === "tab"; }
function permName(e) { return (e.raw && e.raw.permission) || e.name || "unknown"; }
function fpMethod(e) { return ((e.raw && e.raw.method) || e.name || "unknown").toLowerCase(); }
function dlName(e) { return (e.raw && e.raw.filename) || e.url || (e.raw && e.raw.url) || ""; }

function stepFromEvent(e) {
  return { eventId: e.id, type: e.type, detail: e.detail, domain: e.domain, ts: e.ts, risk: e.risk };
}

function makeFinding(opts) {
  const { rule, anchor, session, steps, severity, title, description, confidence, extraDomains } = opts;
  const evidence = steps.map(stepFromEvent);
  const times = evidence.map((s) => s.ts).filter(Boolean);
  const firstSeen = times.length ? Math.min(...times) : session.startTime;
  const lastSeen = times.length ? Math.max(...times) : session.endTime;
  const domains = [...new Set([
    ...evidence.map((s) => s.domain).filter(Boolean),
    ...(extraDomains || []),
  ])];
  const id = anchor === "session" ? `${rule}_${session.sessionId}` : `${rule}_${anchor.id}`;
  return {
    id, rule, severity, title, description,
    confidence: Math.round(confidence * 100) / 100,
    firstSeen, lastSeen,
    evidence,
    affectedDomains: domains,
    affectedSessions: [session.sessionId],
    relatedEventIds: evidence.map((s) => s.eventId).filter(Boolean),
    primaryDomain: session.primaryDomain,
  };
}

/* --------------------------------- rules ---------------------------------- */

// A. Tracker Escalation: Navigation -> Tracker Activity -> Cookie Creation.
function ruleTrackerEscalation(session, ioc) {
  const ev = session.events;
  const out = [];
  for (let k = 0; k < ev.length && out.length < MAX_PER_RULE; k++) {
    if (ev[k].type !== "cookie") continue;
    let t = -1;
    for (let j = k - 1; j >= 0; j--) { if (ioc.isTrackerEvent(ev[j])) { t = j; break; } }
    if (t < 0) continue;
    let n = -1;
    for (let i = t - 1; i >= 0; i--) { if (isNav(ev[i])) { n = i; break; } }
    if (n < 0) continue;
    out.push(makeFinding({
      rule: "TRACKER_ESCALATION", anchor: ev[k], session, steps: [ev[n], ev[t], ev[k]],
      severity: "MEDIUM", confidence: 0.7,
      title: "Tracker escalation chain",
      description: "A page navigation was followed by tracker contact and then cookie creation — a pattern consistent with tracker-driven identifier seeding.",
    }));
  }
  return out;
}

// B. Permission Escalation: Permission Request -> Storage Activity -> Tracker Activity.
function rulePermissionEscalation(session, ioc) {
  const ev = session.events;
  const out = [];
  for (let s = 0; s < ev.length && out.length < MAX_PER_RULE; s++) {
    if (ev[s].type !== "storage") continue;
    let p = -1;
    for (let i = s - 1; i >= 0; i--) { if (ev[i].type === "permission") { p = i; break; } }
    if (p < 0) continue;
    let k = -1;
    for (let j = s + 1; j < ev.length; j++) { if (ioc.isTrackerEvent(ev[j])) { k = j; break; } }
    if (k < 0) continue;
    out.push(makeFinding({
      rule: "PERMISSION_ESCALATION", anchor: ev[s], session, steps: [ev[p], ev[s], ev[k]],
      severity: "HIGH", confidence: 0.75,
      title: "Permission-to-tracking escalation",
      description: `A '${permName(ev[p])}' permission request was followed by local storage activity and then tracker contact, suggesting permission-gated data collection.`,
    }));
  }
  return out;
}

// C. Suspicious Download Chain: Navigation -> Multiple Tracker Requests -> Download.
function ruleSuspiciousDownloadChain(session, ioc) {
  const ev = session.events;
  const out = [];
  const MIN_TRACKERS = 3;
  for (let k = 0; k < ev.length && out.length < MAX_PER_RULE; k++) {
    if (ev[k].type !== "download") continue;
    let n = -1;
    for (let i = k - 1; i >= 0; i--) { if (isNav(ev[i])) { n = i; break; } }
    if (n < 0) continue;
    const trackers = [];
    for (let j = n + 1; j < k; j++) if (ioc.isTrackerEvent(ev[j])) trackers.push(ev[j]);
    if (trackers.length < MIN_TRACKERS) continue;
    const exe = ioc.isExecutable(dlName(ev[k]));
    out.push(makeFinding({
      rule: "SUSPICIOUS_DOWNLOAD_CHAIN", anchor: ev[k], session,
      steps: [ev[n], ...trackers.slice(0, 4), ev[k]],
      severity: exe ? "CRITICAL" : "HIGH",
      confidence: exe ? 0.85 : 0.7,
      title: exe ? "Executable download after heavy tracking" : "Suspicious download chain",
      description: `A navigation was followed by ${trackers.length} tracker requests and then a download${exe ? " of an executable/installer payload" : ""}.`,
    }));
  }
  return out;
}

// D. Excessive Tracking: more than X tracker domains within a session.
function ruleExcessiveTracking(session, ioc, opts) {
  const threshold = (opts && opts.excessiveTrackerDomains) || 5;
  if (session.trackerDomains.length <= threshold) return [];
  const samples = session.events.filter((e) => ioc.isTrackerEvent(e)).slice(0, 6);
  const sev = session.trackerDomains.length > threshold * 2 ? "HIGH" : "MEDIUM";
  return [makeFinding({
    rule: "EXCESSIVE_TRACKING", anchor: "session", session, steps: samples,
    severity: sev, confidence: 0.8,
    extraDomains: session.trackerDomains,
    title: "Excessive third-party tracking",
    description: `${session.trackerDomains.length} distinct tracker domains were contacted in a single session (threshold ${threshold}).`,
  })];
}

// E. Fingerprinting Indicators: canvas / WebGL / AudioContext / font enumeration.
function ruleFingerprinting(session) {
  const fps = session.events.filter((e) => e.type === "fingerprint");
  if (!fps.length) return [];
  const methods = new Set(fps.map(fpMethod));
  const strong =
    methods.size >= 2 ||
    (methods.has("canvas") && (methods.has("webgl") || methods.has("audio"))) ||
    (methods.has("webgl") && methods.has("audio"));
  if (!strong) return [];
  const confidence = Math.min(0.6 + 0.12 * methods.size, 0.95);
  return [makeFinding({
    rule: "FINGERPRINTING", anchor: "session", session, steps: fps.slice(0, 8),
    severity: methods.size >= 3 ? "HIGH" : "MEDIUM", confidence,
    title: "Browser fingerprinting indicators",
    description: `Multiple fingerprinting vectors were exercised: ${[...methods].join(", ")}.`,
  })];
}

// F. Persistent Identifier Creation:
//    Storage write -> Cookie creation -> Repeated tracker communication.
function rulePersistentIdentifier(session, ioc) {
  const ev = session.events;
  const out = [];
  const MIN_REPEAT = 3;
  for (let j = 0; j < ev.length && out.length < MAX_PER_RULE; j++) {
    if (ev[j].type !== "cookie") continue;
    let s = -1;
    for (let i = j - 1; i >= 0; i--) { if (ev[i].type === "storage") { s = i; break; } }
    if (s < 0) continue;
    const trackersAfter = [];
    for (let k = j + 1; k < ev.length; k++) if (ioc.isTrackerEvent(ev[k])) trackersAfter.push(ev[k]);
    if (trackersAfter.length < MIN_REPEAT) continue;
    out.push(makeFinding({
      rule: "PERSISTENT_IDENTIFIER", anchor: ev[j], session,
      steps: [ev[s], ev[j], ...trackersAfter.slice(0, 4)],
      severity: "HIGH", confidence: 0.78,
      title: "Persistent identifier creation",
      description: `A storage write and cookie creation were followed by ${trackersAfter.length} repeated tracker communications — a persistent cross-site identifier pattern.`,
    }));
  }
  return out;
}

// G. High-Risk Session: cumulative session risk exceeds threshold.
function ruleHighRiskSession(session, opts) {
  const threshold = (opts && opts.highRiskScore) || 200;
  const trigger = session.riskScore >= threshold || session.risk === "HIGH";
  if (!trigger) return [];
  const top = [...session.events].sort((a, b) => (b.score || 0) - (a.score || 0)).slice(0, 5);
  const sev = session.riskScore >= threshold * 2 ? "CRITICAL" : "HIGH";
  return [makeFinding({
    rule: "HIGH_RISK_SESSION", anchor: "session", session, steps: top,
    severity: sev, confidence: 0.9,
    extraDomains: session.trackerDomains,
    title: "High-risk browsing session",
    description: `Session cumulative risk score is ${session.riskScore} (threshold ${threshold}); peak event risk ${session.peakRisk}.`,
  })];
}

/* ------------------------------- orchestration ---------------------------- */

const RULES = [
  (s, ioc, o) => ruleTrackerEscalation(s, ioc, o),
  (s, ioc, o) => rulePermissionEscalation(s, ioc, o),
  (s, ioc, o) => ruleSuspiciousDownloadChain(s, ioc, o),
  (s, ioc, o) => ruleExcessiveTracking(s, ioc, o),
  (s) => ruleFingerprinting(s),
  (s, ioc, o) => rulePersistentIdentifier(s, ioc, o),
  (s, ioc, o) => ruleHighRiskSession(s, o),
];

// Run every rule against a single session object.
function runRules(session, ioc, opts = {}) {
  if (!session || !session.events || !session.events.length) return [];
  const findings = [];
  for (const rule of RULES) {
    try { findings.push(...(rule(session, ioc, opts) || [])); }
    catch { /* a single rule failure must not abort the scan */ }
  }
  return findings;
}

// Run rules across many sessions, returning a flat findings array.
function runForSessions(sessions, ioc, opts = {}) {
  const all = [];
  for (const s of sessions) all.push(...runRules(s, ioc, opts));
  return all;
}

function severityRank(sev) { return SEVERITY_RANK[sev] ?? -1; }

const RULE_LOGIC = {
  TRACKER_ESCALATION: "Navigation → Tracker activity → Cookie creation, in time order within one session.",
  PERMISSION_ESCALATION: "Permission request → Storage write → Tracker activity, in time order within one session.",
  SUSPICIOUS_DOWNLOAD_CHAIN: "Navigation → 3+ tracker requests → Download (escalated when the payload is an executable).",
  EXCESSIVE_TRACKING: "Distinct tracker-domain count in a single session exceeds the configured threshold.",
  FINGERPRINTING: "Two or more distinct fingerprinting vectors (canvas, WebGL, AudioContext, font enumeration) exercised in one session.",
  PERSISTENT_IDENTIFIER: "Storage write → Cookie creation → 3+ repeated tracker communications within one session.",
  HIGH_RISK_SESSION: "Cumulative session risk score (or peak event risk) crosses the high-risk threshold.",
};

module.exports = {
  runRules, runForSessions, severityRank,
  SEVERITY_RANK, RULE_LOGIC,
};
