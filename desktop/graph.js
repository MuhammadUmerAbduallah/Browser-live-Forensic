// graph.js
// Relationship Graph & Evidence Correlation engine. Pure and dependency-light:
// builds a typed property graph from reconstructed sessions, their events, and
// forensic findings. Supports incremental ingestion, bounded subgraph queries,
// neighborhood/path analysis, high-risk cluster detection, and JSON/GraphML
// export. No network, no state beyond the in-memory maps it owns.
//
// Node types : session, domain, tracker, cookie, storage, permission, download, finding
// Edge types : visited, contacted, created, modified, requested, triggered, related_to

const risk = require("./risk");

const RANK = { INFO: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };
function rank(r) { return RANK[r] ?? 0; }
function higher(a, b) { return rank(a) >= rank(b) ? a : b; }

function sevToRisk(sev) {
  if (sev === "CRITICAL") return "CRITICAL";
  if (sev === "HIGH") return "HIGH";
  if (sev === "MEDIUM") return "MEDIUM";
  return "INFO";
}

function createGraphStore(initial) {
  const nodes = new Map(); // id -> node
  const edges = new Map(); // id -> edge
  let adj = null;          // adjacency cache: id -> Map(neighborId -> edge)

  if (initial) {
    for (const n of initial.nodes || []) nodes.set(n.id, n);
    for (const e of initial.edges || []) edges.set(e.id, e);
  }

  function invalidate() { adj = null; }

  function upsertNode(id, type, label, attrs = {}) {
    let n = nodes.get(id);
    if (!n) {
      n = { id, type, label: label || id, risk: "INFO", score: 0, count: 0, firstSeen: null, lastSeen: null, meta: {} };
      nodes.set(id, n);
      invalidate();
    }
    if (label) n.label = label;
    if (attrs.risk) n.risk = higher(n.risk, attrs.risk);
    if (attrs.score != null) n.score = Math.max(n.score, attrs.score);
    if (attrs.ts != null) {
      n.firstSeen = n.firstSeen == null ? attrs.ts : Math.min(n.firstSeen, attrs.ts);
      n.lastSeen = n.lastSeen == null ? attrs.ts : Math.max(n.lastSeen, attrs.ts);
    }
    if (attrs.meta) Object.assign(n.meta, attrs.meta);
    n.count++;
    return id;
  }

  function upsertEdge(type, from, to, attrs = {}) {
    if (!from || !to || from === to) return null;
    const id = `${type}|${from}|${to}`;
    let e = edges.get(id);
    if (!e) {
      e = { id, type, from, to, weight: 0, firstSeen: null, lastSeen: null };
      edges.set(id, e);
      invalidate();
    }
    e.weight++;
    if (attrs.ts != null) {
      e.firstSeen = e.firstSeen == null ? attrs.ts : Math.min(e.firstSeen, attrs.ts);
      e.lastSeen = e.lastSeen == null ? attrs.ts : Math.max(e.lastSeen, attrs.ts);
    }
    return id;
  }

  /* ----------------------------- ingestion ------------------------------- */

  function domNode(domain, ioc, e) {
    if (!domain) return null;
    const tracker = ioc.isTracker(domain);
    const type = tracker ? "tracker" : "domain";
    const id = `${type}:${domain}`;
    upsertNode(id, type, domain, { risk: e && e.risk, score: e && e.score, ts: e && e.ts });
    return id;
  }

  // Ingest one reconstructed session and all of its events.
  function ingestSession(session, ioc) {
    const sId = `session:${session.sessionId}`;
    upsertNode(sId, "session", session.primaryDomain || session.sessionId, {
      risk: session.risk, score: session.riskScore, ts: session.startTime,
      meta: {
        primaryDomain: session.primaryDomain, duration: session.duration,
        startTime: session.startTime, endTime: session.endTime, eventCount: session.eventCount,
      },
    });

    // Session-level domain mapping (visited first-party, contacted trackers).
    for (const d of session.visitedDomains || []) {
      const id = domNode(d, ioc);
      if (id) upsertEdge(id.startsWith("tracker:") ? "contacted" : "visited", sId, id, { ts: session.startTime });
    }
    for (const d of session.trackerDomains || []) {
      const id = domNode(d, ioc);
      if (id) upsertEdge("contacted", sId, id, { ts: session.startTime });
    }

    for (const e of session.events) {
      const dom = e.domain;
      const init = (e.raw && e.raw.initiator) ? risk.normalizeDomain(e.raw.initiator) : "";

      switch (e.type) {
        case "navigation":
        case "tab": {
          const id = domNode(dom, ioc, e);
          if (id) upsertEdge("visited", sId, id, { ts: e.ts });
          break;
        }
        case "tracker":
        case "request": {
          const id = domNode(dom, ioc, e);
          if (!id) break;
          upsertEdge("contacted", sId, id, { ts: e.ts });
          if (init) {
            const pId = domNode(init, ioc, e);
            if (pId) upsertEdge("contacted", pId, id, { ts: e.ts });
          }
          break;
        }
        case "cookie": {
          const dId = domNode(dom, ioc, e);
          const cId = `cookie:${dom}:${e.name || "?"}`;
          upsertNode(cId, "cookie", e.name || "cookie", { risk: e.risk, score: e.score, ts: e.ts, meta: { domain: dom } });
          const rel = (e.raw && e.raw.removed) ? "modified" : "created";
          if (dId) upsertEdge(rel, dId, cId, { ts: e.ts });
          upsertEdge(rel, sId, cId, { ts: e.ts });
          break;
        }
        case "storage": {
          const dId = domNode(dom, ioc, e);
          const key = (e.raw && e.raw.key) || e.name || "?";
          const kId = `storage:${dom}:${key}`;
          upsertNode(kId, "storage", key, { risk: e.risk, score: e.score, ts: e.ts, meta: { domain: dom, area: e.raw && e.raw.storageArea } });
          const action = (e.raw && e.raw.action) || "set";
          const rel = (action === "remove" || action === "clear") ? "modified" : "created";
          if (dId) upsertEdge(rel, dId, kId, { ts: e.ts });
          upsertEdge(rel, sId, kId, { ts: e.ts });
          break;
        }
        case "permission": {
          const dId = domNode(dom, ioc, e);
          const name = (e.raw && e.raw.permission) || e.name || "unknown";
          const pId = `permission:${dom}:${name}`;
          upsertNode(pId, "permission", name, { risk: e.risk, score: e.score, ts: e.ts, meta: { domain: dom } });
          if (dId) upsertEdge("requested", dId, pId, { ts: e.ts });
          upsertEdge("requested", sId, pId, { ts: e.ts });
          break;
        }
        case "download": {
          const dId = domNode(dom, ioc, e);
          const fId = `download:${e.id}`;
          const fname = (e.raw && e.raw.filename) || e.url || "download";
          upsertNode(fId, "download", fname, { risk: e.risk, score: e.score, ts: e.ts, meta: { domain: dom, url: e.url } });
          if (dId) upsertEdge("triggered", dId, fId, { ts: e.ts });
          upsertEdge("triggered", sId, fId, { ts: e.ts });
          break;
        }
        default:
          break; // fingerprint etc. tracked via its domain node's risk/score
      }
    }
  }

  // Ingest a finding and correlate it to sessions, domains and trackers.
  function ingestFinding(finding, ioc) {
    const fId = `finding:${finding.id}`;
    upsertNode(fId, "finding", finding.title || finding.rule, {
      risk: sevToRisk(finding.severity),
      score: Math.round((finding.confidence || 0) * 100),
      ts: finding.lastSeen,
      meta: {
        rule: finding.rule, severity: finding.severity, confidence: finding.confidence,
        evidence: (finding.evidence || []).length,
      },
    });
    for (const sid of finding.affectedSessions || []) {
      upsertEdge("related_to", fId, `session:${sid}`, { ts: finding.lastSeen });
    }
    for (const d of finding.affectedDomains || []) {
      const tracker = ioc.isTracker(d);
      const id = `${tracker ? "tracker" : "domain"}:${d}`;
      upsertNode(id, tracker ? "tracker" : "domain", d, { risk: sevToRisk(finding.severity) });
      upsertEdge("related_to", fId, id, { ts: finding.lastSeen });
    }
  }

  /* ------------------------------ adjacency ------------------------------ */

  function adjacency() {
    if (adj) return adj;
    adj = new Map();
    const link = (a, b, e) => {
      if (!adj.has(a)) adj.set(a, new Map());
      adj.get(a).set(b, e);
    };
    for (const e of edges.values()) { link(e.from, e.to, e); link(e.to, e.from, e); }
    return adj;
  }

  function degreeMap() {
    const deg = new Map();
    for (const e of edges.values()) {
      deg.set(e.from, (deg.get(e.from) || 0) + 1);
      deg.set(e.to, (deg.get(e.to) || 0) + 1);
    }
    return deg;
  }

  /* ------------------------------- queries ------------------------------- */

  // Bounded subgraph. Never returns more than `limit` nodes — large datasets
  // are surfaced top-down by risk / degree / score, with edges restricted to
  // the selected node set.
  function subgraph(opts = {}) {
    const limit = Math.min(Number(opts.limit) || 300, 1500);
    const types = opts.nodeTypes && opts.nodeTypes.length ? new Set(opts.nodeTypes) : null;
    const minRank = opts.risk ? rank(opts.risk) : -1;
    const q = (opts.search || "").toLowerCase();
    const deg = degreeMap();

    let candidates = [...nodes.values()].filter((n) => {
      if (types && !types.has(n.type)) return false;
      if (minRank >= 0 && rank(n.risk) < minRank) return false;
      if (q && !(`${n.label} ${n.id}`.toLowerCase().includes(q))) return false;
      return true;
    });

    const totalMatching = candidates.length;
    candidates.sort((a, b) =>
      rank(b.risk) - rank(a.risk) ||
      (deg.get(b.id) || 0) - (deg.get(a.id) || 0) ||
      b.score - a.score);
    const picked = candidates.slice(0, limit);
    const idset = new Set(picked.map((n) => n.id));

    const subEdges = [];
    for (const e of edges.values()) {
      if (idset.has(e.from) && idset.has(e.to)) subEdges.push(e);
    }
    return {
      nodes: picked.map((n) => ({ ...n, degree: deg.get(n.id) || 0 })),
      edges: subEdges,
      truncated: totalMatching > picked.length,
      total: { nodes: nodes.size, edges: edges.size, matching: totalMatching },
    };
  }

  // Neighborhood subgraph around a node up to `depth` hops (BFS, node-capped).
  function neighbors(id, depth = 1, cap = 250) {
    if (!nodes.has(id)) return { nodes: [], edges: [], truncated: false, total: { nodes: nodes.size, edges: edges.size } };
    const a = adjacency();
    const seen = new Set([id]);
    let frontier = [id];
    for (let d = 0; d < depth && seen.size < cap; d++) {
      const next = [];
      for (const cur of frontier) {
        const nb = a.get(cur);
        if (!nb) continue;
        for (const other of nb.keys()) {
          if (!seen.has(other)) { seen.add(other); next.push(other); if (seen.size >= cap) break; }
        }
        if (seen.size >= cap) break;
      }
      frontier = next;
    }
    const deg = degreeMap();
    const outNodes = [...seen].map((nid) => ({ ...nodes.get(nid), degree: deg.get(nid) || 0 }));
    const subEdges = [...edges.values()].filter((e) => seen.has(e.from) && seen.has(e.to));
    return { nodes: outNodes, edges: subEdges, truncated: seen.size >= cap, total: { nodes: nodes.size, edges: edges.size } };
  }

  // Shortest path between two nodes (BFS). Returns a node-id array or null.
  function shortestPath(from, to, maxDepth = 8) {
    if (!nodes.has(from) || !nodes.has(to)) return null;
    if (from === to) return [from];
    const a = adjacency();
    const prev = new Map([[from, null]]);
    let frontier = [from];
    for (let d = 0; d < maxDepth && frontier.length; d++) {
      const next = [];
      for (const cur of frontier) {
        const nb = a.get(cur);
        if (!nb) continue;
        for (const other of nb.keys()) {
          if (prev.has(other)) continue;
          prev.set(other, cur);
          if (other === to) {
            const path = [to]; let c = to;
            while ((c = prev.get(c)) != null) path.unshift(c);
            return path;
          }
          next.push(other);
        }
      }
      frontier = next;
    }
    return null;
  }

  function describePath(ids) {
    return ids.map((id) => {
      const n = nodes.get(id);
      return n ? { id, type: n.type, label: n.label, risk: n.risk } : { id, type: "?", label: id, risk: "INFO" };
    });
  }

  // Evidence path analysis: from a selected node, return shortest paths to each
  // reachable finding (e.g. Session -> Domain -> Tracker -> Cookie -> Finding).
  function evidencePaths(id, opts = {}) {
    const limit = opts.limit || 12;
    const maxDepth = opts.maxDepth || 8;
    const out = [];
    for (const n of nodes.values()) {
      if (n.type !== "finding" || n.id === id) continue;
      const p = shortestPath(id, n.id, maxDepth);
      if (p) out.push({ target: n.id, severity: n.meta && n.meta.severity, steps: describePath(p) });
      if (out.length >= limit) break;
    }
    out.sort((a, b) => a.steps.length - b.steps.length);
    return out;
  }

  function pathBetween(from, to) {
    const p = shortestPath(from, to);
    return p ? describePath(p) : null;
  }

  /* -------------------------- cluster detection -------------------------- */

  // Connected components scored for tracker density, permission activity and
  // findings — flags high-risk clusters of repeated suspicious activity.
  function clusters(opts = {}) {
    const a = adjacency();
    const deg = degreeMap();
    const seen = new Set();
    const out = [];
    for (const start of nodes.keys()) {
      if (seen.has(start)) continue;
      const comp = [];
      const stack = [start];
      seen.add(start);
      while (stack.length) {
        const cur = stack.pop();
        comp.push(cur);
        const nb = a.get(cur);
        if (nb) for (const other of nb.keys()) if (!seen.has(other)) { seen.add(other); stack.push(other); }
      }
      if (comp.length < 2) continue;
      let trackers = 0, permissions = 0, findings = 0, downloads = 0, sessions = 0, cookies = 0;
      let maxRisk = "INFO"; let primary = null; let primaryDeg = -1;
      for (const id of comp) {
        const n = nodes.get(id);
        if (!n) continue;
        if (n.type === "tracker") trackers++;
        else if (n.type === "permission") permissions++;
        else if (n.type === "finding") findings++;
        else if (n.type === "download") downloads++;
        else if (n.type === "session") sessions++;
        else if (n.type === "cookie") cookies++;
        maxRisk = higher(maxRisk, n.risk);
        const d = deg.get(id) || 0;
        if ((n.type === "domain" || n.type === "session") && d > primaryDeg) { primaryDeg = d; primary = n.label; }
      }
      const score = trackers * 2 + permissions * 3 + findings * 5 + downloads * 2;
      const highRisk = score >= (opts.threshold || 12) || rank(maxRisk) >= RANK.HIGH || findings > 0;
      out.push({
        id: `cluster:${start}`,
        label: primary || comp[0],
        size: comp.length,
        trackers, permissions, findings, downloads, sessions, cookies,
        maxRisk, score, highRisk,
        nodeIds: comp.slice(0, 80),
      });
    }
    out.sort((x, y) => Number(y.highRisk) - Number(x.highRisk) || y.score - x.score || y.size - x.size);
    return out.slice(0, opts.limit || 50);
  }

  /* -------------------------------- stats -------------------------------- */

  function stats() {
    const byType = {};
    const byRisk = { INFO: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
    for (const n of nodes.values()) {
      byType[n.type] = (byType[n.type] || 0) + 1;
      byRisk[n.risk] = (byRisk[n.risk] || 0) + 1;
    }
    const byEdge = {};
    for (const e of edges.values()) byEdge[e.type] = (byEdge[e.type] || 0) + 1;
    return { nodes: nodes.size, edges: edges.size, byType, byRisk, byEdge };
  }

  /* ------------------------------ maintenance ---------------------------- */

  // Cap total node count for very large datasets: drop the least-connected,
  // lowest-risk, oldest non-finding nodes (and their edges) first.
  function trim(maxNodes) {
    if (nodes.size <= maxNodes) return 0;
    const deg = degreeMap();
    const removable = [...nodes.values()]
      .filter((n) => n.type !== "finding")
      .sort((a, b) =>
        rank(a.risk) - rank(b.risk) ||
        (deg.get(a.id) || 0) - (deg.get(b.id) || 0) ||
        (a.lastSeen || 0) - (b.lastSeen || 0));
    let toDrop = nodes.size - maxNodes;
    const dropped = new Set();
    for (const n of removable) { if (toDrop <= 0) break; dropped.add(n.id); nodes.delete(n.id); toDrop--; }
    if (dropped.size) {
      for (const [id, e] of edges) if (dropped.has(e.from) || dropped.has(e.to)) edges.delete(id);
      invalidate();
    }
    return dropped.size;
  }

  function clear() { nodes.clear(); edges.clear(); invalidate(); }

  /* ------------------------------- exports ------------------------------- */

  function toJSON() { return { nodes: [...nodes.values()], edges: [...edges.values()] }; }

  function toGraphML() {
    const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (m) => (
      { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&apos;" }[m]
    ));
    const nodeXml = [...nodes.values()].map((n) => `
    <node id="${esc(n.id)}">
      <data key="type">${esc(n.type)}</data>
      <data key="label">${esc(n.label)}</data>
      <data key="risk">${esc(n.risk)}</data>
      <data key="score">${n.score || 0}</data>
    </node>`).join("");
    const edgeXml = [...edges.values()].map((e, i) => `
    <edge id="e${i}" source="${esc(e.from)}" target="${esc(e.to)}">
      <data key="etype">${esc(e.type)}</data>
      <data key="weight">${e.weight || 1}</data>
    </edge>`).join("");
    return `<?xml version="1.0" encoding="UTF-8"?>
<graphml xmlns="http://graphml.graphdrawing.org/xmlns">
  <key id="type" for="node" attr.name="type" attr.type="string"/>
  <key id="label" for="node" attr.name="label" attr.type="string"/>
  <key id="risk" for="node" attr.name="risk" attr.type="string"/>
  <key id="score" for="node" attr.name="score" attr.type="int"/>
  <key id="etype" for="edge" attr.name="etype" attr.type="string"/>
  <key id="weight" for="edge" attr.name="weight" attr.type="int"/>
  <graph id="G" edgedefault="directed">${nodeXml}${edgeXml}
  </graph>
</graphml>`;
  }

  return {
    upsertNode, upsertEdge, ingestSession, ingestFinding,
    subgraph, neighbors, evidencePaths, pathBetween, clusters, stats,
    trim, clear, toJSON, toGraphML,
    get size() { return { nodes: nodes.size, edges: edges.size }; },
  };
}

module.exports = { createGraphStore };
