// db.js
// Local persistent store. Tries better-sqlite3 (fast, on-disk SQL).
// If the native module can't load (e.g. not rebuilt for this Electron),
// it transparently falls back to a JSONL-backed store so the app ALWAYS runs.
//
// Both stores implement the same interface:
//   insert(event) -> stored event with { risk, score, reasons }
//   recent(limit)
//   search({ type, q, risk, domain, since, until, limit, offset }) -> { rows, total }
//   stats()
//   cookieSummary(limit)
//   domainSummary(limit)
//   createCase(spec) -> case
//   cases()
//   caseDetail(id) -> { case, events, summary }
//   clear()
//   backend  -> "sqlite" | "jsonl"

const fs = require("fs");
const path = require("path");
const risk = require("./risk");
const detect = require("./detect");
const { createIoc } = require("./ioc");
const { createGraphStore } = require("./graph");
const { createAcquisitionStore } = require("./acqstore");
const { createTimelineEngine } = require("./timeline");
const { createExtensionEngine } = require("./extensions");
const { createCacheEngine } = require("./cache");
const { createIntegrityEngine } = require("./integrity");
const { createReportingEngine } = require("./reporting");
const { createHuntingEngine } = require("./hunting");

function enrich(event) {
  // Compute display fields shared by both backends.
  const domain =
    risk.normalizeDomain(event.domain) ||
    risk.normalizeDomain(event.url) ||
    risk.normalizeDomain(event.requestUrl) ||
    "";
  const ts = event.receivedAt ? Date.parse(event.receivedAt) : Date.now();
  return { domain, ts: Number.isFinite(ts) ? ts : Date.now() };
}

function buildStored(event, count) {
  const { domain, ts } = enrich(event);
  const r = risk.assess(event, { count });
  return {
    id: event.id,
    receivedAt: event.receivedAt,
    ts,
    type: event.type || "unknown",
    title: event.title || "",
    url: event.url || "",
    domain,
    name: event.name || event.key || event.permission || "",
    detail: risk.describe(event),
    risk: r.risk,
    score: r.score,
    reasons: r.reasons,
    raw: event,
  };
}

/* ----------------------------- SQLite backend ----------------------------- */

function createSqliteStore(DatabaseSync, dbPath) {
  const db = new DatabaseSync(dbPath);
  try { db.exec("PRAGMA journal_mode = WAL;"); } catch { /* ignore */ }

  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      received_at TEXT,
      ts INTEGER,
      type TEXT,
      title TEXT,
      url TEXT,
      domain TEXT,
      name TEXT,
      detail TEXT,
      risk TEXT,
      score INTEGER,
      reasons TEXT,
      raw TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
    CREATE INDEX IF NOT EXISTS idx_events_domain ON events(domain);
    CREATE INDEX IF NOT EXISTS idx_events_risk ON events(risk);

    CREATE TABLE IF NOT EXISTS cases (
      id TEXT PRIMARY KEY,
      title TEXT,
      notes TEXT,
      created_at TEXT,
      since INTEGER,
      until INTEGER,
      filter_type TEXT,
      filter_q TEXT,
      filter_risk TEXT,
      filter_domain TEXT
    );
  `);

  // node:sqlite only binds null/number/bigint/string/Uint8Array — never undefined.
  const S = (v) => (v === undefined || v === null ? null : v);

  const insertStmt = db.prepare(`
    INSERT OR IGNORE INTO events
      (id, received_at, ts, type, title, url, domain, name, detail, risk, score, reasons, raw)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  function countFor(event, domain) {
    if (event.type === "cookie") {
      const row = db
        .prepare(`SELECT COUNT(*) c FROM events WHERE type='cookie' AND domain=? AND name=?`)
        .get(domain, event.name || "");
      return row.c + 1;
    }
    if (event.type === "request") {
      const row = db
        .prepare(`SELECT COUNT(*) c FROM events WHERE type='request' AND domain=?`)
        .get(domain);
      return row.c + 1;
    }
    if (event.type === "tracker") {
      const row = db
        .prepare(`SELECT COUNT(*) c FROM events WHERE type='tracker' AND domain=?`)
        .get(domain);
      return row.c + 1;
    }
    return 1;
  }

  function insert(event) {
    const { domain } = enrich(event);
    const count = countFor(event, domain);
    const s = buildStored(event, count);
    insertStmt.run(
      S(s.id), S(s.receivedAt), S(s.ts), S(s.type), S(s.title), S(s.url),
      S(s.domain), S(s.name), S(s.detail), S(s.risk), S(s.score),
      JSON.stringify(s.reasons), JSON.stringify(s.raw)
    );
    return s;
  }

  function rowToObj(row) {
    return {
      id: row.id,
      receivedAt: row.received_at,
      ts: row.ts,
      type: row.type,
      title: row.title,
      url: row.url,
      domain: row.domain,
      name: row.name,
      detail: row.detail,
      risk: row.risk,
      score: row.score,
      reasons: safeParse(row.reasons, []),
      raw: safeParse(row.raw, {}),
    };
  }

  function recent(limit = 100) {
    return db
      .prepare(`SELECT * FROM events ORDER BY ts DESC LIMIT ?`)
      .all(limit)
      .map(rowToObj);
  }

  // Build a WHERE clause + ordered positional params array.
  function whereFromFilters(f = {}) {
    const clauses = [];
    const params = [];
    if (f.type) { clauses.push("type = ?"); params.push(f.type); }
    if (f.risk) { clauses.push("risk = ?"); params.push(f.risk); }
    if (f.domain) { clauses.push("domain LIKE ?"); params.push(`%${f.domain}%`); }
    if (f.since) { clauses.push("ts >= ?"); params.push(Number(f.since)); }
    if (f.until) { clauses.push("ts <= ?"); params.push(Number(f.until)); }
    if (f.q) {
      clauses.push("(title LIKE ? OR url LIKE ? OR domain LIKE ? OR name LIKE ? OR detail LIKE ?)");
      const like = `%${f.q}%`;
      params.push(like, like, like, like, like);
    }
    return { sql: clauses.length ? `WHERE ${clauses.join(" AND ")}` : "", params };
  }

  function search(f = {}) {
    const limit = Math.min(Number(f.limit) || 200, 1000);
    const offset = Number(f.offset) || 0;
    const { sql, params } = whereFromFilters(f);
    const total = db.prepare(`SELECT COUNT(*) c FROM events ${sql}`).get(...params).c;
    const rows = db
      .prepare(`SELECT * FROM events ${sql} ORDER BY ts DESC LIMIT ? OFFSET ?`)
      .all(...params, limit, offset)
      .map(rowToObj);
    return { rows, total };
  }

  function stats() {
    const total = db.prepare(`SELECT COUNT(*) c FROM events`).get().c;
    const byType = {};
    db.prepare(`SELECT type, COUNT(*) c FROM events GROUP BY type`)
      .all().forEach((r) => { byType[r.type] = r.c; });
    const byRisk = { INFO: 0, MEDIUM: 0, HIGH: 0 };
    db.prepare(`SELECT risk, COUNT(*) c FROM events GROUP BY risk`)
      .all().forEach((r) => { byRisk[r.risk] = r.c; });
    const topDomains = db
      .prepare(`SELECT domain, COUNT(*) c FROM events WHERE domain != '' GROUP BY domain ORDER BY c DESC LIMIT 8`)
      .all();
    const bounds = db.prepare(`SELECT MIN(ts) a, MAX(ts) b FROM events`).get();
    return { total, byType, byRisk, topDomains, since: bounds.a, until: bounds.b };
  }

  function cookieSummary(limit = 50) {
    return db
      .prepare(`
        SELECT domain, name, COUNT(*) c, MAX(score) s, MAX(received_at) last
        FROM events WHERE type='cookie'
        GROUP BY domain, name ORDER BY c DESC LIMIT ?`)
      .all(limit)
      .map((r) => ({
        domain: r.domain, name: r.name, count: r.c,
        risk: risk.levelFromScore(r.s), last: r.last,
      }));
  }

  function domainSummary(limit = 50) {
    return db
      .prepare(`
        SELECT domain, COUNT(*) c, MAX(score) s
        FROM events WHERE domain != ''
        GROUP BY domain ORDER BY c DESC LIMIT ?`)
      .all(limit)
      .map((r) => ({ domain: r.domain, count: r.c, risk: risk.levelFromScore(r.s) }));
  }

  function createCase(spec) {
    const id = `case_${Date.now()}`;
    db.prepare(`
      INSERT INTO cases (id, title, notes, created_at, since, until, filter_type, filter_q, filter_risk, filter_domain)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      id,
      spec.title || "Untitled case",
      spec.notes || "",
      new Date().toISOString(),
      S(spec.since), S(spec.until),
      S(spec.type), S(spec.q), S(spec.risk), S(spec.domain)
    );
    return caseDetail(id).case;
  }

  function cases() {
    return db.prepare(`SELECT * FROM cases ORDER BY created_at DESC`).all().map(caseRowToObj);
  }

  function caseRowToObj(row) {
    return {
      id: row.id, title: row.title, notes: row.notes, createdAt: row.created_at,
      since: row.since, until: row.until,
      filters: { type: row.filter_type, q: row.filter_q, risk: row.filter_risk, domain: row.filter_domain },
    };
  }

  function caseDetail(id) {
    const row = db.prepare(`SELECT * FROM cases WHERE id=?`).get(id);
    if (!row) return null;
    const c = caseRowToObj(row);
    const { rows } = search({
      type: c.filters.type, q: c.filters.q, risk: c.filters.risk, domain: c.filters.domain,
      since: c.since, until: c.until, limit: 1000,
    });
    return { case: c, events: rows, summary: summarize(rows) };
  }

  function clear() {
    db.exec(`DELETE FROM events; DELETE FROM cases;`);
  }

  // Pull a bounded recent pool (with raw) for relation/timeline analysis.
  function investigate(domain) {
    const d = risk.normalizeDomain(domain);
    if (!d) return composeInvestigation("", []);
    const pool = db
      .prepare(`SELECT * FROM events ORDER BY ts DESC LIMIT 20000`)
      .all()
      .map(rowToObj);
    return composeInvestigation(d, pool);
  }

  function sessionPool() {
    return db.prepare(`SELECT * FROM events ORDER BY ts ASC LIMIT 50000`).all().map(rowToObj);
  }
  function eventsSince(ts) {
    return db.prepare(`SELECT * FROM events WHERE ts >= ? ORDER BY ts ASC LIMIT 100000`)
      .all(Number(ts) || 0).map(rowToObj);
  }
  function eventsByIds(ids) {
    if (!ids || !ids.length) return [];
    const place = ids.map(() => "?").join(",");
    return db.prepare(`SELECT * FROM events WHERE id IN (${place})`).all(...ids).map(rowToObj);
  }
  function sessions() {
    return buildSessionObjects(sessionPool())
      .map(sessionSummary)
      .sort((a, b) => b.startTime - a.startTime);
  }
  function sessionDetail(id) {
    const all = buildSessionObjects(sessionPool());
    const s = all.find((x) => x.sessionId === id);
    return s ? sessionDetailFrom(s) : null;
  }

  function prune() {
    const now = Date.now();
    const DAY = 86400000;
    db.prepare(`DELETE FROM events WHERE risk='INFO' AND ts < ?`).run(now - 30 * DAY);
    db.prepare(`DELETE FROM events WHERE risk='MEDIUM' AND ts < ?`).run(now - 90 * DAY);
    let total = db.prepare(`SELECT COUNT(*) c FROM events`).get().c;
    if (total > RETENTION_CAP) {
      const over = total - RETENTION_CAP;
      // Drop oldest non-HIGH first; HIGH is protected unless nothing else remains.
      db.prepare(
        `DELETE FROM events WHERE id IN
           (SELECT id FROM events WHERE risk != 'HIGH' ORDER BY ts ASC LIMIT ?)`
      ).run(over);
      total = db.prepare(`SELECT COUNT(*) c FROM events`).get().c;
      if (total > RETENTION_CAP) {
        db.prepare(
          `DELETE FROM events WHERE id IN
             (SELECT id FROM events ORDER BY ts ASC LIMIT ?)`
        ).run(total - RETENTION_CAP);
      }
    }
    return { backend: "sqlite", total: db.prepare(`SELECT COUNT(*) c FROM events`).get().c };
  }

  return {
    backend: "sqlite",
    insert, recent, search, stats, cookieSummary, domainSummary,
    createCase, cases, caseDetail, clear, investigate, prune,
    sessions, sessionDetail, eventsSince, eventsByIds,
  };
}

/* ------------------------------ JSONL backend ----------------------------- */
// Fallback store. Keeps everything in memory, persists events to events.jsonl
// (the same format the project already uses) and cases to cases.json.

function createJsonlStore(dataDir) {
  const eventsPath = path.join(dataDir, "events.jsonl");
  const casesPath = path.join(dataDir, "cases.json");
  fs.mkdirSync(dataDir, { recursive: true });

  const events = [];
  const byId = new Set();
  let caseList = [];

  // Load existing events (raw originals) and re-enrich them.
  if (fs.existsSync(eventsPath)) {
    for (const line of fs.readFileSync(eventsPath, "utf8").split("\n")) {
      const t = line.trim();
      if (!t) continue;
      try {
        const raw = JSON.parse(t);
        if (raw.id && byId.has(raw.id)) continue;
        ingest(raw, false);
      } catch { /* skip bad line */ }
    }
  }
  if (fs.existsSync(casesPath)) {
    try { caseList = JSON.parse(fs.readFileSync(casesPath, "utf8")); } catch { caseList = []; }
  }

  function countFor(event, domain) {
    if (event.type === "cookie") {
      return events.filter((e) => e.type === "cookie" && e.domain === domain && e.name === (event.name || "")).length + 1;
    }
    if (event.type === "request") {
      return events.filter((e) => e.type === "request" && e.domain === domain).length + 1;
    }
    if (event.type === "tracker") {
      return events.filter((e) => e.type === "tracker" && e.domain === domain).length + 1;
    }
    return 1;
  }

  function ingest(raw, persist) {
    if (raw.id && byId.has(raw.id)) return null; // dedupe by id
    const { domain } = enrich(raw);
    const count = countFor(raw, domain);
    const s = buildStored(raw, count);
    events.push(s);
    if (s.id) byId.add(s.id);
    if (persist) fs.appendFileSync(eventsPath, `${JSON.stringify(raw)}\n`);
    return s;
  }

  function insert(event) { return ingest(event, true); }

  function recent(limit = 100) {
    return [...events].sort((a, b) => b.ts - a.ts).slice(0, limit);
  }

  function matchFilters(e, f) {
    if (f.type && e.type !== f.type) return false;
    if (f.risk && e.risk !== f.risk) return false;
    if (f.domain && !e.domain.includes(f.domain)) return false;
    if (f.since && e.ts < Number(f.since)) return false;
    if (f.until && e.ts > Number(f.until)) return false;
    if (f.q) {
      const q = f.q.toLowerCase();
      const hay = `${e.title} ${e.url} ${e.domain} ${e.name} ${e.detail}`.toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  }

  function search(f = {}) {
    const all = [...events].filter((e) => matchFilters(e, f)).sort((a, b) => b.ts - a.ts);
    const limit = Math.min(Number(f.limit) || 200, 1000);
    const offset = Number(f.offset) || 0;
    return { rows: all.slice(offset, offset + limit), total: all.length };
  }

  function stats() {
    const byType = {};
    const byRisk = { INFO: 0, MEDIUM: 0, HIGH: 0 };
    const domains = {};
    let min = Infinity, max = -Infinity;
    for (const e of events) {
      byType[e.type] = (byType[e.type] || 0) + 1;
      byRisk[e.risk] = (byRisk[e.risk] || 0) + 1;
      if (e.domain) domains[e.domain] = (domains[e.domain] || 0) + 1;
      if (e.ts < min) min = e.ts;
      if (e.ts > max) max = e.ts;
    }
    const topDomains = Object.entries(domains)
      .sort((a, b) => b[1] - a[1]).slice(0, 8)
      .map(([domain, c]) => ({ domain, c }));
    return {
      total: events.length, byType, byRisk, topDomains,
      since: events.length ? min : null, until: events.length ? max : null,
    };
  }

  function cookieSummary(limit = 50) {
    const map = new Map();
    for (const e of events) {
      if (e.type !== "cookie") continue;
      const key = `${e.domain}|${e.name}`;
      const cur = map.get(key) || { domain: e.domain, name: e.name, count: 0, score: 0, last: e.receivedAt };
      cur.count++; cur.score = Math.max(cur.score, e.score); cur.last = e.receivedAt;
      map.set(key, cur);
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, limit)
      .map((r) => ({ domain: r.domain, name: r.name, count: r.count, risk: risk.levelFromScore(r.score), last: r.last }));
  }

  function domainSummary(limit = 50) {
    const map = new Map();
    for (const e of events) {
      if (!e.domain) continue;
      const cur = map.get(e.domain) || { domain: e.domain, count: 0, score: 0 };
      cur.count++; cur.score = Math.max(cur.score, e.score);
      map.set(e.domain, cur);
    }
    return [...map.values()].sort((a, b) => b.count - a.count).slice(0, limit)
      .map((r) => ({ domain: r.domain, count: r.count, risk: risk.levelFromScore(r.score) }));
  }

  function persistCases() { fs.writeFileSync(casesPath, JSON.stringify(caseList, null, 2)); }

  function createCase(spec) {
    const c = {
      id: `case_${Date.now()}`,
      title: spec.title || "Untitled case",
      notes: spec.notes || "",
      createdAt: new Date().toISOString(),
      since: spec.since || null, until: spec.until || null,
      filters: { type: spec.type || null, q: spec.q || null, risk: spec.risk || null, domain: spec.domain || null },
    };
    caseList.unshift(c);
    persistCases();
    return c;
  }

  function cases() { return caseList; }

  function caseDetail(id) {
    const c = caseList.find((x) => x.id === id);
    if (!c) return null;
    const { rows } = search({ ...c.filters, since: c.since, until: c.until, limit: 1000 });
    return { case: c, events: rows, summary: summarize(rows) };
  }

  function clear() {
    events.length = 0; byId.clear(); caseList = [];
    if (fs.existsSync(eventsPath)) fs.writeFileSync(eventsPath, "");
    persistCases();
  }

  function investigate(domain) {
    const d = risk.normalizeDomain(domain);
    if (!d) return composeInvestigation("", []);
    return composeInvestigation(d, events);
  }

  function sessions() {
    return buildSessionObjects(events)
      .map(sessionSummary)
      .sort((a, b) => b.startTime - a.startTime);
  }
  function sessionDetail(id) {
    const all = buildSessionObjects(events);
    const s = all.find((x) => x.sessionId === id);
    return s ? sessionDetailFrom(s) : null;
  }

  function eventsSince(ts) {
    const t = Number(ts) || 0;
    return events.filter((e) => e.ts >= t).sort((a, b) => a.ts - b.ts);
  }
  function eventsByIds(ids) {
    const set = new Set(ids || []);
    return events.filter((e) => set.has(e.id));
  }

  function prune() {
    const now = Date.now();
    let kept = events.filter((e) => pruneEvent(e, now));
    if (kept.length > RETENTION_CAP) {
      const asc = [...kept].sort((a, b) => a.ts - b.ts);
      const drop = new Set();
      let over = kept.length - RETENTION_CAP;
      for (const e of asc) { if (over <= 0) break; if (e.risk !== "HIGH") { drop.add(e.id); over--; } }
      if (over > 0) { for (const e of asc) { if (over <= 0) break; if (!drop.has(e.id)) { drop.add(e.id); over--; } } }
      kept = kept.filter((e) => !drop.has(e.id));
    }
    events.length = 0; byId.clear();
    for (const e of kept) { events.push(e); if (e.id) byId.add(e.id); }
    fs.writeFileSync(
      eventsPath,
      kept.length ? kept.map((e) => JSON.stringify(e.raw)).join("\n") + "\n" : ""
    );
    return { backend: "jsonl", total: kept.length };
  }

  return {
    backend: "jsonl",
    insert, recent, search, stats, cookieSummary, domainSummary,
    createCase, cases, caseDetail, clear, investigate, prune,
    sessions, sessionDetail, eventsSince, eventsByIds,
  };
}

/* -------------------------------- helpers --------------------------------- */

function summarize(rows) {
  const byType = {};
  const byRisk = { INFO: 0, MEDIUM: 0, HIGH: 0 };
  const domains = {};
  let min = Infinity, max = -Infinity;
  for (const e of rows) {
    byType[e.type] = (byType[e.type] || 0) + 1;
    byRisk[e.risk] = (byRisk[e.risk] || 0) + 1;
    if (e.domain) domains[e.domain] = (domains[e.domain] || 0) + 1;
    if (e.ts < min) min = e.ts;
    if (e.ts > max) max = e.ts;
  }
  const topDomains = Object.entries(domains).sort((a, b) => b[1] - a[1]).slice(0, 10)
    .map(([domain, c]) => ({ domain, c }));
  return {
    total: rows.length, byType, byRisk, topDomains,
    since: rows.length ? min : null, until: rows.length ? max : null,
  };
}

function safeParse(s, fallback) {
  try { return JSON.parse(s); } catch { return fallback; }
}

/* --------------------- investigation & correlation ------------------------ */

const RISK_RANK = { INFO: 0, MEDIUM: 1, HIGH: 2 };
const CHAIN_GAP_MS = 30000; // events within 30s form one correlation chain

function maxRisk(events) {
  return events.reduce((m, e) => (RISK_RANK[e.risk] > RISK_RANK[m] ? e.risk : m), "INFO");
}

function classifyChain(events) {
  const types = new Set(events.map((e) => e.type));
  if (types.has("download")) return "Download chain";
  if (types.has("permission")) return "Sensitive permission activity";
  if ((types.has("tracker") || types.has("request")) && (types.has("cookie") || types.has("storage"))) {
    return "Tracking sequence";
  }
  if (types.has("navigation") || types.has("tab")) return "Page-load activity burst";
  return "Activity burst";
}

// Group time-adjacent events into forensic correlation chains.
function buildChains(events) {
  const sorted = [...events].sort((a, b) => a.ts - b.ts);
  const groups = [];
  let cur = null;
  for (const e of sorted) {
    if (!cur || e.ts - cur.until > CHAIN_GAP_MS) {
      cur = { events: [e], since: e.ts, until: e.ts };
      groups.push(cur);
    } else {
      cur.events.push(e);
      cur.until = e.ts;
    }
  }
  return groups
    .filter((g) => g.events.length > 1)
    .map((g) => ({
      since: g.since,
      until: g.until,
      span: g.until - g.since,
      label: classifyChain(g.events),
      risk: maxRisk(g.events),
      domains: [...new Set(g.events.map((e) => e.domain).filter(Boolean))],
      steps: g.events.map((e) => ({
        id: e.id, ts: e.ts, type: e.type, risk: e.risk, detail: e.detail, domain: e.domain,
      })),
    }))
    .sort((a, b) => b.until - a.until);
}

// Build the full investigation report for a domain from a pool of stored events.
function composeInvestigation(domain, pool) {
  const d = risk.normalizeDomain(domain);
  const target = pool.filter((e) => e.domain === d);

  // --- related domains (initiator <-> target relationships) ---
  const related = new Map();
  const bump = (other, role) => {
    if (!other || other === d) return;
    const r = related.get(other) || { domain: other, count: 0, asParent: 0, asChild: 0, tracker: false };
    r.count++;
    if (role === "parent") r.asParent++; else r.asChild++;
    if (risk.isTracker(other)) r.tracker = true;
    related.set(other, r);
  };
  for (const e of target) {
    const init = risk.normalizeDomain(e.raw && e.raw.initiator);
    if (init) bump(init, "parent"); // page that triggered activity ON this domain
  }
  for (const e of pool) {
    const init = risk.normalizeDomain(e.raw && e.raw.initiator);
    if (init === d && e.domain) bump(e.domain, "child"); // resource this domain triggered
  }
  const relatedDomains = [...related.values()]
    .sort((a, b) => b.count - a.count)
    .slice(0, 25);

  // --- summary ---
  const byType = {};
  const byRisk = { INFO: 0, MEDIUM: 0, HIGH: 0 };
  let min = Infinity, max = -Infinity, maxScore = 0;
  for (const e of target) {
    byType[e.type] = (byType[e.type] || 0) + 1;
    byRisk[e.risk] = (byRisk[e.risk] || 0) + 1;
    if (e.ts < min) min = e.ts;
    if (e.ts > max) max = e.ts;
    if (e.score > maxScore) maxScore = e.score;
  }

  // --- risk overview: top reasons by frequency ---
  const reasonFreq = new Map();
  for (const e of target) {
    for (const r of e.reasons || []) reasonFreq.set(r, (reasonFreq.get(r) || 0) + 1);
  }
  const topReasons = [...reasonFreq.entries()]
    .sort((a, b) => b[1] - a[1]).slice(0, 8)
    .map(([reason, c]) => ({ reason, count: c }));

  // --- tracker intelligence ---
  const trackerMap = new Map();
  const addTracker = (key, score, url, ts) => {
    const k = key || "?";
    const cur = trackerMap.get(k) || { domain: k, count: 0, score: 0, analytics: false, last: ts };
    cur.count++;
    cur.score = Math.max(cur.score, score || 0);
    cur.analytics = cur.analytics || risk.isAnalytics(url);
    cur.last = Math.max(cur.last, ts || 0);
    trackerMap.set(k, cur);
  };
  // (a) trackers observed directly on this domain
  for (const e of target) {
    const url = (e.raw && e.raw.requestUrl) || e.url || "";
    const isTrk = e.type === "tracker" || (e.raw && e.raw.trackerDetected) ||
      risk.isTracker(e.domain) || risk.isAnalytics(url);
    if (!isTrk) continue;
    addTracker(risk.normalizeDomain(url) || e.domain, e.score, url, e.ts);
  }
  // (b) tracker endpoints this domain reached out to (children)
  for (const e of pool) {
    const init = risk.normalizeDomain(e.raw && e.raw.initiator);
    if (init !== d) continue;
    const url = (e.raw && e.raw.requestUrl) || e.url || "";
    const isTrk = e.type === "tracker" || (e.raw && e.raw.trackerDetected) ||
      risk.isTracker(e.domain) || risk.isAnalytics(url);
    if (!isTrk) continue;
    addTracker(e.domain || risk.normalizeDomain(url), e.score, url, e.ts);
  }
  const trackers = [...trackerMap.values()]
    .sort((a, b) => b.count - a.count)
    .map((t) => ({ ...t, risk: risk.levelFromScore(t.score) }));

  // --- timeline (ascending) ---
  const timeline = [...target].sort((a, b) => a.ts - b.ts).map((e) => ({
    id: e.id, ts: e.ts, type: e.type, risk: e.risk, score: e.score, detail: e.detail, domain: e.domain,
  }));

  // --- correlation chains across domain + related domains ---
  const relatedSet = new Set(related.keys());
  const chainPool = pool.filter((e) => e.domain === d || relatedSet.has(e.domain));
  const chains = buildChains(chainPool);

  return {
    domain: d,
    summary: {
      domain: d,
      total: target.length,
      byType,
      firstSeen: target.length ? min : null,
      lastSeen: target.length ? max : null,
    },
    riskOverview: {
      maxRisk: maxRisk(target),
      maxScore,
      byRisk,
      isTracker: risk.isTracker(d),
      suspiciousTld: risk.suspiciousTld(d),
      topReasons,
    },
    trackers,
    relatedDomains,
    timeline,
    chains,
  };
}

/* ----------------------- session reconstruction --------------------------- */

const SESSION_GAP_MS = 30 * 60 * 1000; // 30 minutes of inactivity ends a session

function isTrackerEvent(e) {
  const url = (e.raw && e.raw.requestUrl) || e.url || "";
  return e.type === "tracker" || (e.raw && e.raw.trackerDetected) ||
    risk.isTracker(e.domain) || risk.isAnalytics(url);
}

// Related domains (initiator parent/child links) within a set of events.
function relatedWithin(events, focus) {
  const related = new Map();
  const bump = (other, role) => {
    if (!other || other === focus) return;
    const r = related.get(other) || { domain: other, count: 0, asParent: 0, asChild: 0, tracker: false };
    r.count++;
    if (role === "parent") r.asParent++; else r.asChild++;
    if (risk.isTracker(other)) r.tracker = true;
    related.set(other, r);
  };
  for (const e of events) {
    const init = risk.normalizeDomain(e.raw && e.raw.initiator);
    if (e.domain === focus && init) bump(init, "parent");
    if (init === focus && e.domain) bump(e.domain, "child");
  }
  return [...related.values()].sort((a, b) => b.count - a.count).slice(0, 25);
}

// Build a complete session object from its member events.
function composeSession(events) {
  const sorted = [...events].sort((a, b) => a.ts - b.ts);
  const startTime = sorted[0].ts;
  const endTime = sorted[sorted.length - 1].ts;
  const duration = endTime - startTime;
  const sessionId = `sess_${startTime}`;

  const domainCount = new Map();
  const navDomainCount = new Map();
  const trackerSet = new Set();
  const visited = new Set();
  const permissionsRequested = [];
  const downloads = [];
  let cookiesCreated = 0, storageWrites = 0, riskScore = 0;
  let peak = "INFO";

  for (const e of sorted) {
    riskScore += e.score || 0;
    if (RISK_RANK[e.risk] > RISK_RANK[peak]) peak = e.risk;
    if (e.domain) {
      visited.add(e.domain);
      domainCount.set(e.domain, (domainCount.get(e.domain) || 0) + 1);
    }
    if ((e.type === "navigation" || e.type === "tab") && e.domain) {
      navDomainCount.set(e.domain, (navDomainCount.get(e.domain) || 0) + 1);
    }
    if (isTrackerEvent(e) && e.domain) trackerSet.add(e.domain);
    if (e.type === "permission") {
      permissionsRequested.push({
        permission: (e.raw && e.raw.permission) || e.name || "unknown",
        domain: e.domain, ts: e.ts, risk: e.risk,
      });
    }
    if (e.type === "download") {
      downloads.push({
        filename: (e.raw && e.raw.filename) || "",
        url: e.url || (e.raw && e.raw.url) || "",
        domain: e.domain, ts: e.ts, risk: e.risk,
      });
    }
    if (e.type === "cookie") cookiesCreated++;
    if (e.type === "storage") storageWrites++;
  }

  const pickTop = (m) => [...m.entries()].sort((a, b) => b[1] - a[1])[0];
  const primaryDomain = (pickTop(navDomainCount) || pickTop(domainCount) || [""])[0];
  const trackerDomains = [...trackerSet];

  // Session-level risk: start from peak event risk, escalate on cumulative load.
  let level = peak;
  if (level !== "HIGH" && (riskScore >= 250 || trackerDomains.length >= 10)) level = "HIGH";
  else if (level === "INFO" && (riskScore >= 80 || trackerDomains.length >= 4)) level = "MEDIUM";

  return {
    sessionId, startTime, endTime, duration, primaryDomain,
    visitedDomains: [...visited], trackerDomains,
    permissionsRequested, downloads,
    cookiesCreated, storageWrites,
    riskScore, risk: level, peakRisk: peak,
    eventCount: sorted.length,
    events: sorted,
  };
}

// Split a chronological pool into sessions by 30-min inactivity gaps.
function buildSessionObjects(pool) {
  const sorted = [...pool].sort((a, b) => a.ts - b.ts);
  const groups = [];
  let cur = null;
  for (const e of sorted) {
    if (!cur || e.ts - cur.lastTs > SESSION_GAP_MS) {
      cur = { events: [e], lastTs: e.ts };
      groups.push(cur);
    } else {
      cur.events.push(e);
      cur.lastTs = e.ts;
    }
  }
  return groups.map((g) => composeSession(g.events));
}

function sessionSummary(s) {
  const { events, ...rest } = s;
  return rest;
}

// Slim event for timeline rendering.
function slimEvent(e) {
  return { id: e.id, ts: e.ts, type: e.type, risk: e.risk, score: e.score, detail: e.detail, domain: e.domain };
}

// Full detail: chronological timeline, phase-ordered activity chain,
// correlation chains, and related domains.
function sessionDetailFrom(s) {
  const ev = s.events;
  const timeline = [...ev].sort((a, b) => a.ts - b.ts).map(slimEvent);

  // Canonical activity-chain ordering:
  // Navigation -> Tracker Requests -> Storage -> Cookie -> Permission -> Downloads
  const phaseDef = [
    { phase: "navigation", types: ["navigation", "tab"] },
    { phase: "tracker", types: ["tracker", "request"] },
    { phase: "storage", types: ["storage"] },
    { phase: "cookie", types: ["cookie"] },
    { phase: "permission", types: ["permission"] },
    { phase: "download", types: ["download"] },
  ];
  const phases = phaseDef.map(({ phase, types }) => {
    const items = ev.filter((e) => types.includes(e.type))
      .sort((a, b) => a.ts - b.ts).map(slimEvent);
    return { phase, count: items.length, events: items };
  });

  const relatedDomains = relatedWithin(ev, s.primaryDomain);
  const chains = buildChains(ev);

  return { ...sessionSummary(s), timeline, phases, chains, relatedDomains };
}

function pruneEvent(e, now) {
  const DAY = 86400000;
  if (e.risk === "HIGH") return true;            // HIGH kept forever
  if (e.risk === "MEDIUM") return e.ts >= now - 90 * DAY;
  return e.ts >= now - 30 * DAY;                 // INFO / other: 30 days
}
const RETENTION_CAP = 100000;

// Attach the IOC + behavioral detection layer on top of a backend store.
// Findings and the IOC database are persisted as JSON in the data dir, so the
// behavior is identical across the sqlite and jsonl backends.
function attachDetection(base, dataDir) {
  const findingsPath = path.join(dataDir, "findings.json");
  const iocPath = path.join(dataDir, "ioc.json");
  const graphFilePath = path.join(dataDir, "graph.json");
  const GRAPH_MAX_NODES = 60000;

  let iocSeed = {};
  if (fs.existsSync(iocPath)) {
    try { iocSeed = JSON.parse(fs.readFileSync(iocPath, "utf8")); } catch { iocSeed = {}; }
  }
  const ioc = createIoc(iocSeed);

  let graphInit = null;
  let graphCheckpoint = 0;
  if (fs.existsSync(graphFilePath)) {
    try {
      const saved = JSON.parse(fs.readFileSync(graphFilePath, "utf8"));
      graphCheckpoint = saved.checkpoint || 0;
      graphInit = { nodes: saved.nodes || [], edges: saved.edges || [] };
    } catch { graphInit = null; }
  }
  const graph = createGraphStore(graphInit);

  // Browser acquisition runs persist to their own sidecar (acquisitions.json).
  // No schema changes, no existing-table modifications — fully additive.
  const acq = createAcquisitionStore(dataDir);

  // Timeline Reconstruction Engine. Merges the live-event dataset, behavioral
  // findings and acquisition records into one chronological forensic timeline.
  // Persists to its own sidecar (timeline.json) — no schema changes, fully
  // additive, identical across the sqlite and jsonl backends.
  const timeline = createTimelineEngine(dataDir);

  // Extension Forensics Engine. A dedicated extension investigation system that
  // consumes the already-acquired "extensions" artifact records plus the built
  // timeline and behavioral findings — it never reacquires browser data.
  // Persists to its own sidecar (extensions.json) — no schema changes, fully
  // additive, identical across the sqlite and jsonl backends.
  const extensions = createExtensionEngine(dataDir);

  // Cache Forensics Engine. Consumes acquired serviceworker/favicon records plus
  // (when the profile path is still present) metadata-only on-disk cache reads,
  // and correlates against the timeline, findings and extension profiles. It
  // never reacquires browser data via acquire.js and never reads cached page
  // content. Persists to its own sidecar (cache.json) — no schema changes.
  const cache = createCacheEngine(dataDir);

  // Evidence Integrity Engine. Computes SHA256 baselines and chain-of-custody
  // for every evidence item the platform produces (acquisitions, artifacts,
  // timeline entries, extension/cache/investigation findings, exports) and
  // verifies them on demand. Persists to its own sidecar (integrity.json) — no
  // schema changes, fully additive.
  const integrity = createIntegrityEngine(dataDir);

  // Reporting Engine. Aggregates a bounded, read-only snapshot of every engine
  // into immutable, structured forensic report records (HTML/JSON/PDF). It never
  // recomputes integrity or rebuilds the timeline — it consumes their output.
  // Persists to its own sidecar (reports.json) — no schema changes, fully
  // additive.
  const reporting = createReportingEngine(dataDir);

  // Advanced Threat Hunting Engine. Proactive, metadata-only hunting that
  // correlates live events, timeline, extensions, cache, findings, sessions,
  // graph and IOCs into threat findings and multi-stage threat chains. Consumes
  // existing engine output (no re-acquisition, no schema change). Persists to
  // its own sidecar (hunting.json).
  const hunting = createHuntingEngine(dataDir);

  const findings = new Map();
  let checkpoint = 0;
  if (fs.existsSync(findingsPath)) {
    try {
      const saved = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
      checkpoint = saved.checkpoint || 0;
      for (const f of saved.findings || []) findings.set(f.id, f);
    } catch { /* start fresh */ }
  }

  const opts = {}; // rule thresholds use defaults; expandable via persisted config

  function persistFindings() {
    fs.writeFileSync(findingsPath, JSON.stringify({
      checkpoint, findings: [...findings.values()],
    }, null, 2));
  }
  function persistIoc() {
    fs.writeFileSync(iocPath, JSON.stringify(ioc.snapshot(), null, 2));
  }
  function persistGraph() {
    const g = graph.toJSON();
    fs.writeFileSync(graphFilePath, JSON.stringify({ checkpoint: graphCheckpoint, nodes: g.nodes, edges: g.edges }, null, 2));
  }

  function graphRebuild() {
    graph.clear();
    const sessions = buildSessionObjects(base.eventsSince(0));
    for (const s of sessions) graph.ingestSession(s, ioc);
    for (const f of findings.values()) graph.ingestFinding(f, ioc);
    graph.trim(GRAPH_MAX_NODES);
    graphCheckpoint = Date.now();
    persistGraph();
    return graph.stats();
  }

  function graphIngestIncremental() {
    const sinceTs = graphCheckpoint > 0 ? graphCheckpoint - 2 * SESSION_GAP_MS : 0;
    const sessions = buildSessionObjects(base.eventsSince(sinceTs));
    for (const s of sessions) graph.ingestSession(s, ioc);
    for (const f of findings.values()) graph.ingestFinding(f, ioc); // findings set stays small
    graph.trim(GRAPH_MAX_NODES);
    graphCheckpoint = Date.now();
    persistGraph();
    return graph.stats();
  }

  // bounded subgraph; nodeId yields a neighborhood instead of a top-N view
  function graphView(opts = {}) {
    if (opts.nodeId || opts.focus) {
      return graph.neighbors(opts.nodeId || opts.focus, opts.depth || 2, opts.cap || 250);
    }
    return graph.subgraph({
      nodeTypes: opts.nodeTypes || opts.types,
      risk: opts.risk || opts.minRisk,
      search: opts.search || opts.q,
      limit: opts.limit,
    });
  }
  function graphNeighborhood(id, depth, cap) { return graph.neighbors(id, depth || 2, cap || 250); }
  function graphPaths(id, opts) { return graph.evidencePaths(id, opts || {}); }
  function graphPath(from, to) { return graph.pathBetween(from, to); }
  function graphClusters(opts) { return graph.clusters(opts || {}); }
  function graphStats() { return graph.stats(); }
  function graphSerialize(format) {
    return format === "graphml" ? graph.toGraphML() : JSON.stringify(graph.toJSON(), null, 2);
  }
  function graphExportData() { return { ...graph.toJSON(), stats: graph.stats() }; }
  function graphFlush() { persistGraph(); }

  function upsert(list, scopedSessionIds) {
    let changed = 0;
    // Drop prior findings that belong entirely to the rescanned sessions, so a
    // re-scan reflects the current state (no stale findings).
    if (scopedSessionIds) {
      for (const [id, f] of findings) {
        if ((f.affectedSessions || []).every((sid) => scopedSessionIds.has(sid))) {
          findings.delete(id); changed++;
        }
      }
    }
    for (const f of list) { findings.set(f.id, f); changed++; }
    return changed;
  }

  function detectAll() {
    const pool = base.eventsSince(0);
    const sessions = buildSessionObjects(pool);
    findings.clear();
    for (const f of detect.runForSessions(sessions, ioc, opts)) findings.set(f.id, f);
    checkpoint = Date.now();
    persistFindings();
    return findingsMeta();
  }

  function detectIncremental() {
    const sinceTs = checkpoint > 0 ? checkpoint - 2 * SESSION_GAP_MS : 0;
    const pool = base.eventsSince(sinceTs);
    if (!pool.length) { checkpoint = Date.now(); return { changed: 0, ...findingsMeta() }; }
    const sessions = buildSessionObjects(pool);
    const scoped = new Set(sessions.map((s) => s.sessionId));
    const fresh = detect.runForSessions(sessions, ioc, opts);
    const changed = upsert(fresh, scoped);
    checkpoint = Date.now();
    persistFindings();
    return { changed, ...findingsMeta() };
  }

  function findingsMeta() {
    const bySeverity = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const f of findings.values()) bySeverity[f.severity] = (bySeverity[f.severity] || 0) + 1;
    return { total: findings.size, bySeverity };
  }

  function listFindings(filter = {}) {
    let arr = [...findings.values()];
    if (filter.severity) arr = arr.filter((f) => f.severity === filter.severity);
    if (filter.rule) arr = arr.filter((f) => f.rule === filter.rule);
    if (filter.domain) arr = arr.filter((f) => f.affectedDomains.some((d) => d.includes(filter.domain)));
    return arr.sort((a, b) =>
      detect.severityRank(b.severity) - detect.severityRank(a.severity) ||
      b.lastSeen - a.lastSeen);
  }

  function findingDetail(id) {
    const f = findings.get(id);
    if (!f) return null;
    const relatedEvents = base.eventsByIds(f.relatedEventIds || [])
      .sort((a, b) => a.ts - b.ts);
    const relatedSessions = (f.affectedSessions || [])
      .map((sid) => base.sessionDetail(sid))
      .filter(Boolean)
      .map((d) => ({
        sessionId: d.sessionId, primaryDomain: d.primaryDomain, risk: d.risk,
        riskScore: d.riskScore, startTime: d.startTime, endTime: d.endTime,
        duration: d.duration, eventCount: d.eventCount,
        visitedDomains: d.visitedDomains, trackerDomains: d.trackerDomains,
      }));
    return {
      finding: f,
      logic: detect.RULE_LOGIC[f.rule] || "",
      relatedEvents,
      relatedSessions,
    };
  }

  function clearFindings() { findings.clear(); checkpoint = 0; persistFindings(); }

  function iocList() { return { snapshot: ioc.snapshot(), counts: ioc.counts() }; }
  function iocAdd(category, value) {
    const ok = ioc.add(category, value);
    if (ok) persistIoc();
    return { ok, ...iocList() };
  }

  // --- browser acquisition (read-only forensic captures) ---
  function acqSaveRun(result) { return acq.saveRun(result); }
  function acqList() { return acq.list(); }
  function acqDetail(id) { return acq.detail(id); }
  function acqRecords(id, filter) { return acq.recordsForRun(id, filter || {}); }
  function acqStats() { return acq.stats(); }
  function acqRemove(id) { return acq.removeRun(id); }
  function acqClear() { return acq.clear(); }

  // --- timeline reconstruction (additive sidecar; no schema changes) ---
  // Gather the three input datasets the engine merges. Live events and findings
  // come straight from the base store + detection layer; acquisition records are
  // paged out of the acquisition sidecar through its existing read API (no new
  // acq methods, no schema change).
  const TL_RECORD_PAGE = 5000;
  const TL_RUN_RECORD_CAP = 200000;
  function collectTimelineInputs() {
    const liveEvents = base.eventsSince(0);
    const findingList = [...findings.values()];
    const runs = [];
    for (const summary of acq.list()) {
      const d = acq.detail(summary.runId);
      if (!d) continue;
      const records = [];
      let offset = 0;
      for (;;) {
        const { rows, total } = acq.recordsForRun(summary.runId, { limit: TL_RECORD_PAGE, offset });
        if (!rows.length) break;
        records.push(...rows);
        offset += rows.length;
        if (rows.length < TL_RECORD_PAGE || offset >= total || records.length >= TL_RUN_RECORD_CAP) break;
      }
      runs.push({ run: d.run, artifacts: d.artifacts || [], records });
    }
    return { liveEvents, findings: findingList, runs };
  }
  function timelineBuild() { return timeline.build(collectTimelineInputs()); }
  function timelineQuery(filter) { return timeline.query(filter || {}); }
  function timelineDetail(id) { return timeline.detail(id); }
  function timelineFilters() { return timeline.filters(); }
  function timelineExport(filter) { return timeline.exportData(filter || {}); }
  function timelineStats() { return timeline.stats(); }
  function timelineClear() { return timeline.clear(); }

  // --- extension forensics (additive sidecar; no schema changes) ---
  // Gather inputs from the existing acquisition records (no reacquisition), the
  // built timeline and the behavioral findings. Extension records are pulled
  // through the acquisition store's existing read API and enriched with their
  // run/browser context so the engine can attribute each install.
  function collectExtensionInputs() {
    const extensionsIn = [];
    for (const summary of acq.list()) {
      const d = acq.detail(summary.runId);
      if (!d) continue;
      const run = d.run || {};
      let offset = 0;
      for (;;) {
        const { rows, total } = acq.recordsForRun(summary.runId, { type: "extension", limit: 5000, offset });
        if (!rows.length) break;
        for (const rec of rows) {
          extensionsIn.push({
            eventId: rec.eventId,
            runId: rec.runId,
            artifactId: rec.artifactId,
            title: rec.title,
            detail: rec.detail,
            ts: rec.ts,
            attributes: rec.attributes || {},
            browser: run.browser || "",
            browserFamily: run.browserFamily || "",
            profile: run.profile || "",
            host: run.host || "",
            acquiredAt: run.acquiredAt != null ? run.acquiredAt : run.finishedAt,
          });
        }
        offset += rows.length;
        if (rows.length < 5000 || offset >= total) break;
      }
    }
    const tl = timeline.query({ limit: 5000, order: "asc" });
    const timelineEntries = (tl && tl.rows) || [];
    const findingList = [...findings.values()];
    return { extensions: extensionsIn, timelineEntries, findings: findingList };
  }
  function extScan() { return extensions.scan(collectExtensionInputs()); }
  function extList(filter) { return extensions.list(filter || {}); }
  function extDetail(extensionId, key) { return extensions.detail(extensionId, key); }
  function extFindings(filter) { return extensions.listFindings(filter || {}); }
  function extExport(filter) { return extensions.exportData(filter || {}); }
  function extStats() { return extensions.stats(); }
  function extFilters() { return extensions.filters(); }
  function extClear() { return extensions.clear(); }

  // --- cache forensics (additive sidecar; no schema changes) ---
  // Gather inputs from existing acquisition records (serviceworker + favicon),
  // the run metadata (incl. profilePath for permitted metadata-only on-disk
  // cache extraction), the built timeline, behavioral findings, the extension
  // profiles and the IOC matcher. No browser data is reacquired via acquire.js.
  function collectCacheInputs() {
    const runs = [];
    for (const summary of acq.list()) {
      const d = acq.detail(summary.runId);
      if (!d) continue;
      const run = d.run || {};
      const swRecords = pageRecords(summary.runId, "serviceworker");
      const faviconRecords = pageRecords(summary.runId, "favicon");
      runs.push({
        run: {
          runId: run.runId, browser: run.browser, browserFamily: run.browserFamily,
          profile: run.profile, profilePath: run.profilePath, host: run.host,
          acquiredAt: run.acquiredAt != null ? run.acquiredAt : run.finishedAt,
          finishedAt: run.finishedAt,
        },
        swRecords, faviconRecords,
      });
    }
    const tl = timeline.query({ limit: 5000, order: "asc" });
    const timelineEntries = (tl && tl.rows) || [];
    const findingList = [...findings.values()];
    const extList = extensions.list({ limit: 5000 });
    const extProfiles = (extList && extList.rows) || [];
    return { runs, timelineEntries, findings: findingList, extensions: extProfiles, ioc };
  }
  function pageRecords(runId, type) {
    const records = [];
    let offset = 0;
    for (;;) {
      const { rows, total } = acq.recordsForRun(runId, { type, limit: 5000, offset });
      if (!rows.length) break;
      records.push(...rows);
      offset += rows.length;
      if (rows.length < 5000 || offset >= total) break;
    }
    return records;
  }
  function cacheScan() { return cache.scan(collectCacheInputs()); }
  function cacheList(filter) { return cache.list(filter || {}); }
  function cacheDetail(id) { return cache.detail(id); }
  function cacheFindings(filter) { return cache.listFindings(filter || {}); }
  function cacheExport(filter) { return cache.exportData(filter || {}); }
  function cacheStats() { return cache.stats(); }
  function cacheFilters() { return cache.filters(); }
  function cacheClear() { return cache.clear(); }

  // --- evidence integrity (additive sidecar; no schema changes) ---
  // Gather the current state of every evidence-producing engine. Extension and
  // cache findings are enriched with their parent profile's relatedTimelineIds
  // so the integrity record can link findings to timeline evidence (read-only;
  // no engine schema is modified).
  function collectIntegrityInputs() {
    const acquisitions = [];
    for (const summary of acq.list()) {
      const d = acq.detail(summary.runId);
      if (!d) continue;
      acquisitions.push({ run: d.run, summary: d.summary, artifacts: d.artifacts || [] });
    }
    const tl = timeline.query({ limit: 5000, order: "asc" });
    const timelineEntries = (tl && tl.rows) || [];

    const extProfiles = (extensions.list({ limit: 5000 }).rows) || [];
    const extTlByExt = new Map();
    for (const p of extProfiles) extTlByExt.set(p.extensionId, p.relatedTimelineIds || []);
    const extensionFindings = (extensions.listFindings({}).rows || []).map((f) => ({
      ...f, relatedTimelineIds: extTlByExt.get(f.extensionId) || [],
    }));

    const cacheProfiles = (cache.list({ limit: 5000 }).rows) || [];
    const cacheTlByCache = new Map();
    for (const p of cacheProfiles) cacheTlByCache.set(p.cacheId, p.relatedTimelineIds || []);
    const cacheFindings = (cache.listFindings({}).rows || []).map((f) => ({
      ...f, relatedTimelineIds: cacheTlByCache.get(f.cacheId) || [],
    }));

    const investigationFindings = [...findings.values()];
    return { acquisitions, timelineEntries, extensionFindings, cacheFindings, investigationFindings };
  }
  function integrityList(filter) { return integrity.list(filter || {}); }
  function integrityDetail(id) { return integrity.detail(id); }
  function integrityVerify(id) { return integrity.verify(id, collectIntegrityInputs()); }
  function integrityVerifyAll() { return integrity.verifyAll(collectIntegrityInputs()); }
  function integrityCustody(filter) { return integrity.listCustody(filter || {}); }
  function integrityExport(filter) { return integrity.exportData(filter || {}); }
  function integrityStats() { return integrity.stats(); }
  function integrityFilters() { return integrity.filters(); }
  function integrityRecordExport(info) { return integrity.recordExport(info || {}); }
  function integrityClear() { return integrity.clear(); }

  // --- reporting (additive sidecar; no schema changes) ---
  // Gather a bounded, read-only snapshot of every evidence source for the
  // Reporting Engine. Uses only existing engine read APIs — nothing is
  // recomputed and no schema is touched.
  function collectReportSources() {
    const REPORT_CAP = 1000;
    const acqSummaries = acq.list();
    const runs = [];
    for (const s of acqSummaries.slice(0, 100)) {
      const d = acq.detail(s.runId);
      if (d) runs.push({ run: d.run, summary: d.summary, artifacts: d.artifacts || [] });
    }
    const tl = timeline.query({ limit: REPORT_CAP, order: "asc" });
    const ext = extensions.list({ limit: REPORT_CAP });
    const ca = cache.list({ limit: REPORT_CAP });
    const inv = listFindings({}).slice(0, REPORT_CAP);
    const integ = integrity.list({ limit: REPORT_CAP });
    let sessionList = [];
    try { sessionList = base.sessions(); } catch { sessionList = []; }
    return {
      generatedAt: Date.now(),
      acquisitions: { list: acqSummaries, runs, stats: acq.stats() },
      timeline: { stats: timeline.stats(), sample: (tl && tl.rows) || [], total: (tl && tl.total) || 0 },
      extensions: { stats: extensions.stats(), profiles: (ext && ext.rows) || [], findings: extensions.listFindings({}).rows || [] },
      cache: { stats: cache.stats(), profiles: (ca && ca.rows) || [], findings: cache.listFindings({}).rows || [] },
      findings: { meta: findingsMeta(), list: inv },
      integrity: { stats: integrity.stats(), records: (integ && integ.rows) || [], custody: integrity.listCustody({ limit: REPORT_CAP }).rows || [] },
      sessions: { list: sessionList.slice(0, 500), count: sessionList.length },
      graph: { stats: graphStats() },
      ioc: { counts: ioc.counts() },
    };
  }
  function reportCreate(options) { return reporting.create(options || {}, collectReportSources()); }
  function reportList(filter) { return reporting.list(filter || {}); }
  function reportDetail(id) { return reporting.detail(id); }
  function reportExportData(id) { return reporting.exportData(id); }
  function reportStats() { return reporting.stats(); }
  function reportRemove(id) { return reporting.remove(id); }
  function reportClear() { return reporting.clear(); }

  // --- threat hunting (additive sidecar; no schema changes) ---
  // Gather a bounded, read-only snapshot of every evidence source. Live events
  // carry the richest raw signals (fingerprint method, statusCode, filename,
  // trackerDetected); the rest come from the existing engines' read APIs.
  function collectHuntInputs() {
    const HUNT_CAP = 5000;
    const liveEvents = base.eventsSince(0);
    const tl = timeline.query({ limit: HUNT_CAP, order: "asc" });
    const timelineEntries = (tl && tl.rows) || [];
    const extProfiles = (extensions.list({ limit: HUNT_CAP }).rows) || [];
    const extensionFindings = (extensions.listFindings({}).rows) || [];
    const cacheProfiles = (cache.list({ limit: HUNT_CAP }).rows) || [];
    const cacheFindings = (cache.listFindings({}).rows) || [];
    const investigationFindings = [...findings.values()];
    let sessionList = [];
    try { sessionList = base.sessions(); } catch { sessionList = []; }
    return {
      liveEvents,
      timelineEntries,
      extensions: extProfiles,
      extensionFindings,
      cacheProfiles,
      cacheFindings,
      investigationFindings,
      sessions: sessionList,
      graph: graphStats(),
      integrity: integrity.stats(),
      ioc,
    };
  }
  function huntScan() { return hunting.scan(collectHuntInputs()); }
  function huntList(filter) { return hunting.list(filter || {}); }
  function huntDetail(id) { return hunting.detail(id); }
  function huntChains(filter) { return hunting.listChains(filter || {}); }
  function huntExportData(filter) { return hunting.exportData(filter || {}); }
  function huntStats() { return hunting.stats(); }
  function huntFilters() { return hunting.filters(); }
  function huntClear() { return hunting.clear(); }

  // Scoped clearing. "events" covers the live-activity dataset and everything
  // derived from it (cases, findings, graph). "acquisitions" is independent.
  // Each scope can be cleared on its own.
  function clearScope(scopes = {}) {
    const want = Array.isArray(scopes)
      ? { events: scopes.includes("events"), acquisitions: scopes.includes("acquisitions") }
      : scopes;
    const done = { events: false, acquisitions: false };
    if (want.events) {
      base.clear();
      clearFindings();
      graph.clear();
      persistGraph();
      done.events = true;
    }
    if (want.acquisitions) {
      acq.clear();
      done.acquisitions = true;
    }
    // The timeline is derived from both datasets; drop it if either is cleared
    // so it never references removed events or acquisition records.
    if (done.events || done.acquisitions) {
      try { timeline.clear(); } catch { /* ignore */ }
      // Extension forensics derives from acquisition records + timeline; clear
      // it too so profiles/correlations never reference dropped data.
      try { extensions.clear(); } catch { /* ignore */ }
      // Cache forensics derives from acquisition records + timeline + extensions;
      // clear it as well to avoid dangling references.
      try { cache.clear(); } catch { /* ignore */ }
      // Evidence integrity references all of the above; clear its baselines and
      // custody log so verification never points at removed evidence.
      try { integrity.clear(); } catch { /* ignore */ }
      // Reports are immutable snapshots of the above; clear them too so stored
      // reports never reference removed evidence.
      try { reporting.clear(); } catch { /* ignore */ }
      // Threat hunting derives from all of the above; clear it as well.
      try { hunting.clear(); } catch { /* ignore */ }
    }
    return done;
  }

  return {
    ...base,
    ioc,
    detectAll, detectIncremental, findingsMeta,
    findings: listFindings, finding: findingDetail, clearFindings,
    iocList, iocAdd,
    // Relationship graph & evidence correlation engine.
    graphRebuild, graphIngestIncremental, graphView, graphNeighborhood,
    graphPaths, graphPath, graphClusters, graphStats, graphSerialize,
    graphExportData, graphFlush,
    // Browser acquisition store (additive sidecar; no schema changes).
    acqSaveRun, acqList, acqDetail, acqRecords, acqStats, acqRemove, acqClear,
    // Timeline Reconstruction Engine (additive sidecar; no schema changes).
    timelineBuild, timelineQuery, timelineDetail, timelineFilters,
    timelineExport, timelineStats, timelineClear,
    // Extension Forensics Engine (additive sidecar; no schema changes).
    extScan, extList, extDetail, extFindings, extExport, extStats, extFilters, extClear,
    // Cache Forensics Engine (additive sidecar; no schema changes).
    cacheScan, cacheList, cacheDetail, cacheFindings, cacheExport, cacheStats, cacheFilters, cacheClear,
    // Evidence Integrity Engine (additive sidecar; no schema changes).
    integrityList, integrityDetail, integrityVerify, integrityVerifyAll, integrityCustody,
    integrityExport, integrityStats, integrityFilters, integrityRecordExport, integrityClear,
    // Reporting Engine (additive sidecar; no schema changes).
    reportCreate, reportList, reportDetail, reportExportData, reportStats, reportRemove, reportClear,
    // Advanced Threat Hunting Engine (additive sidecar; no schema changes).
    huntScan, huntList, huntDetail, huntChains, huntExportData, huntStats, huntFilters, huntClear,
    clearScope,
    // Clearing all data clears derived findings, the graph, the timeline, the
    // extension/cache forensics sidecars, the evidence integrity sidecar, the
    // reports sidecar and the threat-hunting sidecar too.
    clear: () => { base.clear(); clearFindings(); graph.clear(); persistGraph(); try { timeline.clear(); } catch { /* ignore */ } try { extensions.clear(); } catch { /* ignore */ } try { cache.clear(); } catch { /* ignore */ } try { integrity.clear(); } catch { /* ignore */ } try { reporting.clear(); } catch { /* ignore */ } try { hunting.clear(); } catch { /* ignore */ } },
    // After a retention prune, recompute derived data so nothing references dropped events.
    prune: () => { const r = base.prune(); try { detectAll(); graphRebuild(); } catch { /* ignore */ } return r; },
  };
}

// Factory: prefer Node's built-in SQLite, fall back to JSONL.
function createStore(dataDir) {
  fs.mkdirSync(dataDir, { recursive: true });
  let base;
  try {
    // Built into the Node runtime that ships inside Electron — no native build,
    // no electron-rebuild, no compiler toolchain required.
    const { DatabaseSync } = require("node:sqlite");
    base = createSqliteStore(DatabaseSync, path.join(dataDir, "forensics.db"));
  } catch (err) {
    console.warn(
      "[store] node:sqlite unavailable, using JSONL fallback.\n" +
      "        (Older Electron may need the --experimental-sqlite flag.)\n" +
      `        reason: ${err && err.message}`
    );
    base = createJsonlStore(dataDir);
  }
  return attachDetection(base, dataDir);
}

module.exports = { createStore };
