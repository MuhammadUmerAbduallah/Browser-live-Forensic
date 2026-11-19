// renderer.js — dashboard logic (runs in the sandboxed window, uses window.api)

const $ = (id) => document.getElementById(id);
const RISK_ORDER = { INFO: 0, MEDIUM: 1, HIGH: 2 };

const state = {
  paused: false,
  liveRiskMin: "",
  historyOffset: 0,
  historyPageSize: 100,
  lastSearchFilters: {},
};

/* ------------------------------ formatting -------------------------------- */

function esc(s) {
  return String(s ?? "").replace(/[&<>"]/g, (m) => (
    { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[m]
  ));
}
function fmtTime(ts) {
  if (!ts) return "—";
  const d = new Date(ts);
  return d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function fmtDateTime(ts) { return ts ? new Date(ts).toLocaleString() : "—"; }

function entryEl(e) {

  const div = document.createElement("div");

  div.className = `entry ${e.risk}`;

  const dom =
    e.domain
      ? `<span class="edomain">${esc(e.domain)}</span>`
      : "";

  div.innerHTML = `
    <div class="entry-top">
      <span class="badge ${e.risk}">${e.risk}</span>
      <span class="etype">${esc(e.type)}</span>
      ${dom}
      <span class="etime">${fmtTime(e.ts)}</span>
    </div>

    <div class="edetail">${esc(e.detail)}</div>

    <div class="ereasons">
      ${esc(e.reasons.join(" · "))}
    </div>
  `;

  div.style.cursor = "pointer";

  div.addEventListener("click", () => {
    if (e.domain) {
      renderInvestigation(e.domain);
    } else {
      showEventDetail(e);
    }
  });

  return div;

}

// Fallback panel for events that have no domain (e.g. some resource events).
function showEventDetail(e) {
  switchTab("investigation");
  const panel = $("investigationPanel");
  panel.innerHTML = `
    <div class="inv-head">
      <h2>${esc(e.type)} event</h2>
    </div>
    <div class="inv-section">
      <p><b>Risk:</b> <span class="pill ${e.risk}">${e.risk}</span> (score ${e.score ?? "—"})</p>
      <p><b>Time:</b> ${fmtDateTime(e.ts)}</p>
      <p><b>Detail:</b></p>
      <pre>${esc(e.detail)}</pre>
      <p><b>Reasons:</b></p>
      <pre>${esc((e.reasons || []).join("\n"))}</pre>
    </div>`;
}

/* --------------------------------- KPIs ----------------------------------- */

async function refreshKpis() {
  const s = await window.api.stats();
  $("kpiTotal").textContent = s.total;
  $("kpiHigh").textContent = s.byRisk.HIGH || 0;
  $("kpiMed").textContent = s.byRisk.MEDIUM || 0;
  $("kpiInfo").textContent = s.byRisk.INFO || 0;
}

/* --------------------------------- LIVE ----------------------------------- */

function passesLiveFilter(e) {
  if (!state.liveRiskMin) return true;
  return RISK_ORDER[e.risk] >= RISK_ORDER[state.liveRiskMin];
}

function pushLive(e) {
  if (state.paused || !passesLiveFilter(e)) return;
  const feed = $("liveFeed");
  feed.prepend(entryEl(e));
  while (feed.children.length > 300) feed.removeChild(feed.lastChild);
}

async function seedLive() {
  const rows = await window.api.recent(80);
  const feed = $("liveFeed");
  feed.innerHTML = "";
  rows.reverse().forEach((e) => { if (passesLiveFilter(e)) feed.prepend(entryEl(e)); });
}

/* -------------------------------- HISTORY --------------------------------- */

async function loadHistory(reset) {
  if (reset) { state.historyOffset = 0; $("historyFeed").innerHTML = ""; }
  const { rows, total } = await window.api.search({
    limit: state.historyPageSize, offset: state.historyOffset,
  });
  rows.forEach((e) => $("historyFeed").appendChild(entryEl(e)));
  state.historyOffset += rows.length;
  $("historyCount").textContent = `${state.historyOffset} of ${total}`;
  $("historyMore").style.display = state.historyOffset < total ? "" : "none";
}

/* --------------------------------- SEARCH --------------------------------- */

function readFilters() {
  const sinceVal = $("fSince").value;
  const untilVal = $("fUntil").value;
  const since = sinceVal ? Date.parse(sinceVal) : undefined;
  const until = untilVal ? Date.parse(untilVal) : undefined;
  return {
    q: $("fQ").value.trim() || undefined,
    type: $("fType").value || undefined,
    risk: $("fRisk").value || undefined,
    domain: $("fDomain").value.trim() || undefined,
    since: Number.isFinite(since) ? since : undefined,
    until: Number.isFinite(until) ? until : undefined,
  };
}

async function runSearch() {
  const filters = readFilters();
  state.lastSearchFilters = filters;
  const { rows, total } = await window.api.search({ ...filters, limit: 1000 });
  const feed = $("searchFeed");
  feed.innerHTML = `<div class="muted" style="margin-bottom:8px">${total} match${total === 1 ? "" : "es"}</div>`;
  rows.forEach((e) => feed.appendChild(entryEl(e)));
}

/* ---------------------------- COOKIES / DOMAINS --------------------------- */

async function loadCookies() {
  const rows = await window.api.cookies(80);
  $("cookieRows").innerHTML = rows.map((r) => `
    <tr>
      <td><span class="pill ${r.risk}">${r.risk}</span></td>
      <td>${esc(r.name)}</td>
      <td class="edomain">${esc(r.domain)}</td>
      <td>${r.count}</td>
      <td class="muted">${r.last ? new Date(r.last).toLocaleString() : "—"}</td>
    </tr>`).join("") || `<tr><td colspan="5" class="muted">No cookie activity yet.</td></tr>`;
}

async function loadDomains() {

  const rows = await window.api.domains(80);

  const tbody = $("domainRows");

  tbody.innerHTML = rows.map((r) => `
    <tr data-domain="${esc(r.domain)}" class="domain-row">
      <td><span class="pill ${r.risk}">${r.risk}</span></td>
      <td class="edomain">${esc(r.domain)}</td>
      <td>${r.count}</td>
    </tr>
  `).join("") || `
    <tr>
      <td colspan="3" class="muted">
        No domain activity yet.
      </td>
    </tr>
  `;

  tbody.querySelectorAll(".domain-row").forEach((row) => {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => renderInvestigation(row.dataset.domain));
  });

}

/* ----------------------------- INVESTIGATION ------------------------------ */

async function renderInvestigation(domain) {
  switchTab("investigation");
  const panel = $("investigationPanel");
  panel.innerHTML = `<div class="muted">Investigating ${esc(domain)}…</div>`;

  const d = await window.api.investigate(domain);
  if (!d || !d.domain) {
    panel.innerHTML = `<div class="muted">No activity recorded for this domain.</div>`;
    return;
  }

  const ov = d.riskOverview;
  const su = d.summary;
  const flags = [
    ov.isTracker ? `<span class="pill HIGH">known tracker</span>` : "",
    ov.suspiciousTld ? `<span class="pill MEDIUM">suspicious TLD</span>` : "",
  ].filter(Boolean).join(" ");

  const typeBits = Object.entries(su.byType)
    .map(([k, v]) => `${esc(k)}: ${v}`).join(" · ") || "none";

  const reasonRows = ov.topReasons.length
    ? ov.topReasons.map((r) => `<li>${esc(r.reason)} <span class="muted">×${r.count}</span></li>`).join("")
    : `<li class="muted">No notable reasons</li>`;

  const trackerRows = d.trackers.length
    ? d.trackers.map((t) => `
      <tr>
        <td><span class="pill ${t.risk}">${t.risk}</span></td>
        <td class="edomain">${esc(t.domain)}</td>
        <td>${t.analytics ? "analytics" : "tracker"}</td>
        <td>${t.count}</td>
        <td class="muted">${t.last ? new Date(t.last).toLocaleString() : "—"}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="muted">No trackers observed on this domain.</td></tr>`;

  const relatedRows = d.relatedDomains.length
    ? d.relatedDomains.map((r) => `
      <tr class="related-row" data-domain="${esc(r.domain)}">
        <td class="edomain">${esc(r.domain)}${r.tracker ? ` <span class="pill HIGH">tracker</span>` : ""}</td>
        <td>${r.count}</td>
        <td>${r.asParent}</td>
        <td>${r.asChild}</td>
      </tr>`).join("")
    : `<tr><td colspan="4" class="muted">No related domains.</td></tr>`;

  const chainBlocks = d.chains.length
    ? d.chains.map((ch) => `
      <div class="chain ${ch.risk}">
        <div class="chain-head">
          <span class="badge ${ch.risk}">${ch.risk}</span>
          <b>${esc(ch.label)}</b>
          <span class="muted">${fmtDateTime(ch.since)} → ${fmtDateTime(ch.until)} · ${Math.round(ch.span / 1000)}s · ${ch.steps.length} steps</span>
        </div>
        <ol class="chain-steps">
          ${ch.steps.map((s) => `<li><span class="etype">${esc(s.type)}</span> ${esc(s.detail)} <span class="edomain">${esc(s.domain)}</span></li>`).join("")}
        </ol>
      </div>`).join("")
    : `<div class="muted">No correlation chains detected.</div>`;

  panel.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(d.domain)}</h2>
        <div class="muted">${flags || "no special flags"}</div>
      </div>
      <button class="btn" id="invExport">Export report</button>
    </div>

    <div class="inv-cards">
      <div class="inv-card">
        <div class="inv-card-label">Activity</div>
        <div class="inv-card-num">${su.total}</div>
        <div class="muted">${fmtDateTime(su.firstSeen)}<br>→ ${fmtDateTime(su.lastSeen)}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Peak risk</div>
        <div class="inv-card-num ${ov.maxRisk}">${ov.maxRisk}</div>
        <div class="muted">score ${ov.maxScore}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Risk mix</div>
        <div>
          <span class="pill HIGH">HIGH ${ov.byRisk.HIGH}</span>
          <span class="pill MEDIUM">MED ${ov.byRisk.MEDIUM}</span>
          <span class="pill INFO">INFO ${ov.byRisk.INFO}</span>
        </div>
        <div class="muted" style="margin-top:6px">${esc(typeBits)}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Top reasons</div>
        <ul class="inv-reasons">${reasonRows}</ul>
      </div>
    </div>

    <h3 class="inv-h3">Tracker intelligence</h3>
    <table class="grid"><thead>
      <tr><th>Risk</th><th>Endpoint</th><th>Kind</th><th>Hits</th><th>Last seen</th></tr>
    </thead><tbody>${trackerRows}</tbody></table>

    <h3 class="inv-h3">Related domains</h3>
    <table class="grid"><thead>
      <tr><th>Domain</th><th>Links</th><th>As parent</th><th>As child</th></tr>
    </thead><tbody id="invRelated">${relatedRows}</tbody></table>

    <h3 class="inv-h3">Correlation chains</h3>
    <div class="chains">${chainBlocks}</div>

    <h3 class="inv-h3">Timeline</h3>
    <div class="feed inv-timeline"></div>
  `;

  const tl = panel.querySelector(".inv-timeline");
  if (d.timeline.length) {
    [...d.timeline].reverse().forEach((e) => tl.appendChild(entryEl(e)));
  } else {
    tl.innerHTML = `<div class="muted">No events.</div>`;
  }

  panel.querySelectorAll(".related-row").forEach((row) =>
    row.addEventListener("click", () => renderInvestigation(row.dataset.domain)));

  $("invExport").addEventListener("click", async () => {
    const btn = $("invExport");
    const res = await window.api.exportInvestigation(d.domain);
    if (res.ok) btn.textContent = "Saved ✓";
    else if (res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  });
}
/* ---------------------------------- CASES --------------------------------- */

let pendingCaseSpec = null;

function openCaseModal(spec, scopeText) {
  pendingCaseSpec = spec;
  $("caseTitle").value = "";
  $("caseNotes").value = "";
  $("caseScope").textContent = scopeText;
  $("caseModal").classList.remove("hidden");
  $("caseTitle").focus();
}

async function confirmCase() {
  const spec = { ...pendingCaseSpec, title: $("caseTitle").value.trim() || "Untitled case", notes: $("caseNotes").value.trim() };
  await window.api.createCase(spec);
  $("caseModal").classList.add("hidden");
  await loadCases();
}

async function loadCases() {
  const cases = await window.api.cases();
  $("caseDetail").classList.add("hidden");
  $("caseList").innerHTML = cases.map((c) => {
    const scope = [
      c.filters.type, c.filters.risk, c.filters.domain && `domain~${c.filters.domain}`,
      c.filters.q && `"${c.filters.q}"`,
    ].filter(Boolean).join(" · ") || "all activity";
    return `
      <div class="case-card">
        <h4>${esc(c.title)}</h4>
        <div class="meta">${esc(c.id)}</div>
        <div class="muted" style="margin-top:6px">${esc(scope)}</div>
        ${c.notes ? `<div style="margin-top:8px;font-size:12.5px">${esc(c.notes)}</div>` : ""}
        <div class="actions">
          <button class="btn ghost" data-open="${c.id}">Open</button>
          <button class="btn" data-export="${c.id}">Export</button>
        </div>
      </div>`;
  }).join("") || `<div class="muted">No cases yet. Create one from the Search tab or the button above.</div>`;

  $("caseList").querySelectorAll("[data-open]").forEach((b) =>
    b.addEventListener("click", () => openCase(b.dataset.open)));
  $("caseList").querySelectorAll("[data-export]").forEach((b) =>
    b.addEventListener("click", async () => {
      const res = await window.api.exportCase(b.dataset.export);
      if (res.ok) b.textContent = "Saved ✓";
      else if (res.error !== "Cancelled") b.textContent = res.error;
    }));
}

async function openCase(id) {
  const d = await window.api.case(id);
  if (!d) return;
  const s = d.summary;
  const typeBits = Object.entries(s.byType).map(([k, v]) => `${k}: ${v}`).join(" · ") || "none";
  const domBits = s.topDomains.map((x) => `${x.domain} (${x.c})`).join(", ") || "none";
  const detail = $("caseDetail");
  detail.classList.remove("hidden");
  detail.innerHTML = `
    <h3>${esc(d.case.title)}</h3>
    <div class="sumrow">
      <div><b>${s.total}</b> events</div>
      <div><span class="pill HIGH">HIGH ${s.byRisk.HIGH}</span>
           <span class="pill MEDIUM">MED ${s.byRisk.MEDIUM}</span>
           <span class="pill INFO">INFO ${s.byRisk.INFO}</span></div>
      <div class="muted">${fmtDateTime(s.since)} → ${fmtDateTime(s.until)}</div>
    </div>
    <div class="muted" style="margin-bottom:6px">Types: ${esc(typeBits)}</div>
    <div class="muted" style="margin-bottom:14px">Top domains: ${esc(domBits)}</div>
    <div class="feed" style="max-height:420px"></div>`;
  const feed = detail.querySelector(".feed");
  d.events.forEach((e) => feed.appendChild(entryEl(e)));
}

/* -------------------------------- SESSIONS -------------------------------- */

function fmtDuration(ms) {
  if (!ms) return "0s";
  const s = Math.round(ms / 1000), m = Math.floor(s / 60), h = Math.floor(m / 60);
  return h ? `${h}h ${m % 60}m` : m ? `${m}m ${s % 60}s` : `${s}s`;
}

async function loadSessions() {
  const sessions = await window.api.sessions();
  $("sessionDetail").classList.add("hidden");
  $("sessionCount").textContent = `${sessions.length} session${sessions.length === 1 ? "" : "s"}`;
  $("sessionRows").innerHTML = sessions.map((s) => `
    <tr class="session-row" data-id="${esc(s.sessionId)}">
      <td><span class="pill ${s.risk}">${s.risk}</span></td>
      <td class="muted">${esc(s.sessionId)}</td>
      <td class="edomain">${esc(s.primaryDomain || "—")}</td>
      <td>${fmtDateTime(s.startTime)}</td>
      <td>${fmtDuration(s.duration)}</td>
      <td>${s.visitedDomains.length}</td>
      <td>${s.trackerDomains.length}</td>
      <td>${s.eventCount}</td>
    </tr>`).join("") || `<tr><td colspan="8" class="muted">No sessions reconstructed yet.</td></tr>`;

  $("sessionRows").querySelectorAll(".session-row").forEach((row) => {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => openSession(row.dataset.id));
  });
}

async function openSession(id) {
  const s = await window.api.session(id);
  const detail = $("sessionDetail");
  if (!s) { detail.classList.add("hidden"); return; }
  detail.classList.remove("hidden");

  const flags = [
    s.risk === "HIGH" ? `<span class="pill HIGH">high risk</span>` : "",
    s.trackerDomains.length ? `<span class="pill MEDIUM">${s.trackerDomains.length} trackers</span>` : "",
  ].filter(Boolean).join(" ");

  const trackerList = s.trackerDomains.length
    ? s.trackerDomains.map((d) => `<span class="tag">${esc(d)}</span>`).join(" ")
    : `<span class="muted">none</span>`;
  const visitedList = s.visitedDomains.length
    ? s.visitedDomains.map((d) => `<span class="tag clickable" data-domain="${esc(d)}">${esc(d)}</span>`).join(" ")
    : `<span class="muted">none</span>`;

  const permRows = s.permissionsRequested.length
    ? s.permissionsRequested.map((p) => `
      <tr><td><span class="pill ${p.risk}">${p.risk}</span></td><td>${esc(p.permission)}</td>
      <td class="edomain">${esc(p.domain)}</td><td class="muted">${fmtDateTime(p.ts)}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">No permission requests.</td></tr>`;
  const dlRows = s.downloads.length
    ? s.downloads.map((d) => `
      <tr><td><span class="pill ${d.risk}">${d.risk}</span></td><td>${esc(d.filename || d.url)}</td>
      <td class="edomain">${esc(d.domain)}</td><td class="muted">${fmtDateTime(d.ts)}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">No downloads.</td></tr>`;
  const relatedRows = s.relatedDomains.length
    ? s.relatedDomains.map((r) => `
      <tr class="related-row" data-domain="${esc(r.domain)}">
        <td class="edomain">${esc(r.domain)}${r.tracker ? ` <span class="pill HIGH">tracker</span>` : ""}</td>
        <td>${r.count}</td><td>${r.asParent}</td><td>${r.asChild}</td></tr>`).join("")
    : `<tr><td colspan="4" class="muted">No related domains.</td></tr>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h3>${esc(s.primaryDomain || "Session")}</h3>
        <div class="muted">${esc(s.sessionId)} · ${flags || "no flags"}</div>
      </div>
      <button class="btn" id="sessionExport">Export report</button>
    </div>

    <div class="inv-cards">
      <div class="inv-card">
        <div class="inv-card-label">Window</div>
        <div class="muted">${fmtDateTime(s.startTime)}<br>→ ${fmtDateTime(s.endTime)}</div>
        <div class="inv-card-num" style="font-size:18px;margin-top:6px">${fmtDuration(s.duration)}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Session risk</div>
        <div class="inv-card-num ${s.risk}">${s.risk}</div>
        <div class="muted">cumulative ${s.riskScore} · peak ${s.peakRisk}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Footprint</div>
        <div class="muted">${s.eventCount} events<br>
          ${s.cookiesCreated} cookies · ${s.storageWrites} storage<br>
          ${s.permissionsRequested.length} permissions · ${s.downloads.length} downloads</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Trackers observed (${s.trackerDomains.length})</div>
        <div class="tags">${trackerList}</div>
      </div>
    </div>

    <h3 class="inv-h3">Domains visited (${s.visitedDomains.length})</h3>
    <div class="tags">${visitedList}</div>

    <h3 class="inv-h3">Activity chain</h3>
    <div class="phases">
      ${s.phases.map((p) => `
        <div class="phase">
          <div class="phase-head"><b>${esc(p.phase)}</b> <span class="muted">${p.count}</span></div>
          ${p.count ? `<ul class="phase-list">${p.events.map((e) => `<li><span class="muted">${fmtTime(e.ts)}</span> ${esc(e.detail)} <span class="edomain">${esc(e.domain)}</span></li>`).join("")}</ul>` : `<div class="muted">none</div>`}
        </div>`).join("")}
    </div>

    <h3 class="inv-h3">Permissions</h3>
    <table class="grid"><thead><tr><th>Risk</th><th>Permission</th><th>Domain</th><th>Time</th></tr></thead>
      <tbody>${permRows}</tbody></table>

    <h3 class="inv-h3">Downloads</h3>
    <table class="grid"><thead><tr><th>Risk</th><th>File</th><th>Domain</th><th>Time</th></tr></thead>
      <tbody>${dlRows}</tbody></table>

    <h3 class="inv-h3">Related domains</h3>
    <table class="grid"><thead><tr><th>Domain</th><th>Links</th><th>As parent</th><th>As child</th></tr></thead>
      <tbody>${relatedRows}</tbody></table>

    <h3 class="inv-h3">Timeline</h3>
    <div class="feed inv-timeline"></div>
  `;

  const tl = detail.querySelector(".inv-timeline");
  if (s.timeline.length) {
    [...s.timeline].reverse().forEach((e) => tl.appendChild(entryEl(e)));
  } else {
    tl.innerHTML = `<div class="muted">No events.</div>`;
  }

  detail.querySelectorAll(".related-row, .tag.clickable").forEach((el) =>
    el.addEventListener("click", () => renderInvestigation(el.dataset.domain)));

  $("sessionExport").addEventListener("click", async () => {
    const btn = $("sessionExport");
    const res = await window.api.exportSession(s.sessionId);
    if (res.ok) btn.textContent = "Saved ✓";
    else if (res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  });

  detail.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* -------------------------------- FINDINGS -------------------------------- */

function sevPill(sev) { return `<span class="sev-pill ${sev}">${sev}</span>`; }

async function loadFindings() {
  const severity = $("findingSeverity").value || undefined;
  const findings = await window.api.findings({ severity });
  $("findingDetail").classList.add("hidden");
  $("findingCount").textContent = `${findings.length} finding${findings.length === 1 ? "" : "s"}`;
  $("findingRows").innerHTML = findings.map((f) => `
    <tr class="finding-row" data-id="${esc(f.id)}">
      <td>${sevPill(f.severity)}</td>
      <td>${esc(f.title)}</td>
      <td>${Math.round((f.confidence || 0) * 100)}%</td>
      <td class="edomain">${esc((f.affectedDomains || [])[0] || "—")}</td>
      <td class="muted">${esc((f.affectedSessions || [])[0] || "—")}</td>
      <td>${fmtDateTime(f.lastSeen)}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">No findings detected.</td></tr>`;

  $("findingRows").querySelectorAll(".finding-row").forEach((row) => {
    row.style.cursor = "pointer";
    row.addEventListener("click", () => openFinding(row.dataset.id));
  });
}

async function openFinding(id) {
  const d = await window.api.finding(id);
  const detail = $("findingDetail");
  if (!d) { detail.classList.add("hidden"); return; }
  detail.classList.remove("hidden");
  const f = d.finding;

  const evidence = f.evidence.map((s, i) => `
    <li>
      <span class="step-n">${i + 1}</span>
      <span class="etype">${esc(s.type)}</span>
      <span class="pill ${s.risk}">${s.risk}</span>
      ${esc(s.detail)}
      <span class="edomain">${esc(s.domain)}</span>
      <span class="muted">${fmtDateTime(s.ts)}</span>
    </li>`).join("");

  const sessionRows = d.relatedSessions.length
    ? d.relatedSessions.map((s) => `
      <tr class="related-session" data-id="${esc(s.sessionId)}">
        <td class="muted">${esc(s.sessionId)}</td>
        <td class="edomain">${esc(s.primaryDomain)}</td>
        <td><span class="pill ${s.risk}">${s.risk}</span></td>
        <td>${s.riskScore}</td>
        <td>${s.eventCount}</td>
      </tr>`).join("")
    : `<tr><td colspan="5" class="muted">No related sessions.</td></tr>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h3>${esc(f.title)} ${sevPill(f.severity)}</h3>
        <div class="muted">${esc(f.id)} · confidence ${Math.round((f.confidence || 0) * 100)}% · ${fmtDateTime(f.firstSeen)} → ${fmtDateTime(f.lastSeen)}</div>
      </div>
      <button class="btn" id="findingExport">Export finding</button>
    </div>

    <p>${esc(f.description)}</p>

    <div class="inv-cards">
      <div class="inv-card">
        <div class="inv-card-label">Detection logic</div>
        <div style="font-size:12.5px">${esc(d.logic)}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Affected domains</div>
        <div class="tags">${(f.affectedDomains || []).map((x) => `<span class="tag clickable" data-domain="${esc(x)}">${esc(x)}</span>`).join(" ") || '<span class="muted">none</span>'}</div>
      </div>
      <div class="inv-card">
        <div class="inv-card-label">Affected sessions</div>
        <div class="tags">${(f.affectedSessions || []).map((x) => `<span class="tag">${esc(x)}</span>`).join(" ") || '<span class="muted">none</span>'}</div>
      </div>
    </div>

    <h3 class="inv-h3">Evidence chain</h3>
    <ol class="evidence-chain">${evidence || "<li>none</li>"}</ol>

    <h3 class="inv-h3">Related events</h3>
    <div class="feed inv-timeline"></div>

    <h3 class="inv-h3">Related sessions</h3>
    <table class="grid"><thead>
      <tr><th>Session</th><th>Primary domain</th><th>Risk</th><th>Score</th><th>Events</th></tr>
    </thead><tbody>${sessionRows}</tbody></table>
  `;

  const tl = detail.querySelector(".inv-timeline");
  if (d.relatedEvents.length) {
    d.relatedEvents.forEach((e) => tl.appendChild(entryEl(e)));
  } else {
    tl.innerHTML = `<div class="muted">No related events resolved.</div>`;
  }

  detail.querySelectorAll(".tag.clickable").forEach((el) =>
    el.addEventListener("click", () => renderInvestigation(el.dataset.domain)));
  detail.querySelectorAll(".related-session").forEach((row) =>
    row.addEventListener("click", () => { switchTab("sessions"); openSession(row.dataset.id); }));

  $("findingExport").addEventListener("click", async () => {
    const btn = $("findingExport");
    const res = await window.api.exportFindings({ scope: "one", id: f.id });
    if (res.ok) btn.textContent = "Saved ✓";
    else if (res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  });

  detail.scrollIntoView({ behavior: "smooth", block: "start" });
}

/* ---------------------------------- GRAPH --------------------------------- */

const GRAPH_NODE_TYPES = [
  { type: "session", color: "#4ec9b0" },
  { type: "domain", color: "#5b9dd9" },
  { type: "tracker", color: "#e0a458" },
  { type: "cookie", color: "#c08cd6" },
  { type: "storage", color: "#6cc0a8" },
  { type: "permission", color: "#f0a93b" },
  { type: "download", color: "#d97b5b" },
  { type: "finding", color: "#f0584b" },
];
const GRAPH_RISKS = ["INFO", "MEDIUM", "HIGH", "CRITICAL"];
const RISK_STROKE = { INFO: "#5b9dd9", MEDIUM: "#e0a458", HIGH: "#f0584b", CRITICAL: "#ff5d73" };
const NODE_COLOR = Object.fromEntries(GRAPH_NODE_TYPES.map((t) => [t.type, t.color]));
const SVGNS = "http://www.w3.org/2000/svg";

const graphState = {
  inited: false,
  typeFilter: new Set(GRAPH_NODE_TYPES.map((t) => t.type)),
  riskFilter: new Set(GRAPH_RISKS),
  nodes: [], edges: [], pos: new Map(),
  focus: null, selected: null,
  zoom: 1, panX: 0, panY: 0,
  W: 800, H: 600,
  nodeEls: new Map(), edgeEls: [],
};

function initGraph() {
  if (graphState.inited) return;
  graphState.inited = true;

  $("graphTypeFilters").innerHTML = GRAPH_NODE_TYPES.map((t) =>
    `<label class="chk gflag"><input type="checkbox" data-type="${t.type}" checked>
      <span class="gdot" style="background:${t.color}"></span>${t.type}</label>`).join("");
  $("graphRiskFilters").innerHTML = GRAPH_RISKS.map((r) =>
    `<label class="chk gflag"><input type="checkbox" data-risk="${r}" checked>${r}</label>`).join("");
  $("graphLegend").innerHTML = GRAPH_NODE_TYPES.map((t) =>
    `<span class="leg"><span class="gdot" style="background:${t.color}"></span>${t.type}</span>`).join("");

  $("graphTypeFilters").querySelectorAll("input").forEach((cb) => cb.addEventListener("change", () => {
    cb.checked ? graphState.typeFilter.add(cb.dataset.type) : graphState.typeFilter.delete(cb.dataset.type);
    loadGraph();
  }));
  $("graphRiskFilters").querySelectorAll("input").forEach((cb) => cb.addEventListener("change", () => {
    cb.checked ? graphState.riskFilter.add(cb.dataset.risk) : graphState.riskFilter.delete(cb.dataset.risk);
    loadGraph();
  }));

  $("graphSearch").addEventListener("keydown", (e) => { if (e.key === "Enter") loadGraph(); });
  $("gZoomIn").addEventListener("click", () => setZoom(graphState.zoom * 1.25));
  $("gZoomOut").addEventListener("click", () => setZoom(graphState.zoom / 1.25));
  $("gZoomReset").addEventListener("click", () => { graphState.focus = null; $("graphSearch").value = ""; graphState.zoom = 1; graphState.panX = 0; graphState.panY = 0; loadGraph(); });
  $("graphClustersBtn").addEventListener("click", showClusters);
  $("graphRebuildBtn").addEventListener("click", async () => {
    const b = $("graphRebuildBtn"); b.textContent = "…"; await window.api.graphRebuild(); b.textContent = "Rebuild"; loadGraph();
  });
  $("graphExportJson").addEventListener("click", () => exportGraph("json", $("graphExportJson")));
  $("graphExportGraphml").addEventListener("click", () => exportGraph("graphml", $("graphExportGraphml")));
  $("graphExportHtml").addEventListener("click", () => exportGraph("html", $("graphExportHtml")));

  setupGraphInteractions();
}

async function exportGraph(fmt, btn) {
  const label = btn.textContent;
  const res = await window.api.exportGraph(fmt);
  if (res.ok) btn.textContent = "Saved ✓"; else if (res.error !== "Cancelled") btn.textContent = "Failed";
  setTimeout(() => { btn.textContent = label; }, 2000);
}

async function loadGraph() {
  const stage = $("graphStage");
  graphState.W = stage.clientWidth || 800;
  graphState.H = stage.clientHeight || 600;

  const opts = {
    nodeTypes: [...graphState.typeFilter],
    search: $("graphSearch").value.trim() || undefined,
    limit: 400,
  };
  if (graphState.focus) { opts.nodeId = graphState.focus; opts.depth = 2; }

  const data = await window.api.graphView(opts);
  // client-side risk filtering (UI supports multi-select; server uses a min-rank)
  let nodes = (data.nodes || []).filter((n) => graphState.riskFilter.has(n.risk));
  const keep = new Set(nodes.map((n) => n.id));
  // cap for layout responsiveness
  if (nodes.length > 260) nodes = nodes.slice(0, 260);
  const keep2 = new Set(nodes.map((n) => n.id));
  const edges = (data.edges || []).filter((e) => keep2.has(e.from) && keep2.has(e.to));

  graphState.nodes = nodes;
  graphState.edges = edges;
  $("graphMeta").textContent =
    `${nodes.length} nodes · ${edges.length} edges` +
    (data.truncated ? ` · showing top of ${data.total ? data.total.matching : "?"}` : "") +
    (graphState.focus ? " · focused" : "");

  runGraphLayout(nodes, edges, graphState.W, graphState.H);
  renderGraph();
}

function runGraphLayout(nodes, edges, W, H) {
  const pos = graphState.pos;
  const ids = nodes.map((n) => n.id);
  const idset = new Set(ids);
  nodes.forEach((n, i) => {
    if (!pos.has(n.id)) {
      const a = (i / Math.max(1, nodes.length)) * 2 * Math.PI;
      pos.set(n.id, { x: W / 2 + Math.cos(a) * Math.min(W, H) * 0.35, y: H / 2 + Math.sin(a) * Math.min(W, H) * 0.35 });
    }
  });
  const adj = edges.filter((e) => idset.has(e.from) && idset.has(e.to));
  const k = Math.sqrt((W * H) / Math.max(1, nodes.length));
  const iters = nodes.length > 120 ? 110 : 170;
  for (let iter = 0; iter < iters; iter++) {
    const disp = new Map(); ids.forEach((id) => disp.set(id, { x: 0, y: 0 }));
    for (let i = 0; i < ids.length; i++) {
      const pi = pos.get(ids[i]); const di = disp.get(ids[i]);
      for (let j = i + 1; j < ids.length; j++) {
        const pj = pos.get(ids[j]); const dj = disp.get(ids[j]);
        let dx = pi.x - pj.x, dy = pi.y - pj.y; let dist = Math.hypot(dx, dy) || 0.01;
        const rep = (k * k) / dist; const ux = dx / dist, uy = dy / dist;
        di.x += ux * rep; di.y += uy * rep; dj.x -= ux * rep; dj.y -= uy * rep;
      }
    }
    for (const e of adj) {
      const pa = pos.get(e.from), pb = pos.get(e.to); const da = disp.get(e.from), db = disp.get(e.to);
      let dx = pa.x - pb.x, dy = pa.y - pb.y; let dist = Math.hypot(dx, dy) || 0.01;
      const att = (dist * dist) / k; const ux = dx / dist, uy = dy / dist;
      da.x -= ux * att; da.y -= uy * att; db.x += ux * att; db.y += uy * att;
    }
    const temp = 1 - iter / iters; const maxStep = 30 * temp + 1;
    for (const id of ids) {
      const d = disp.get(id), p = pos.get(id);
      const dl = Math.hypot(d.x, d.y) || 0.01; const step = Math.min(dl, maxStep);
      p.x += (d.x / dl) * step; p.y += (d.y / dl) * step;
      p.x = Math.max(24, Math.min(W - 24, p.x)); p.y = Math.max(24, Math.min(H - 24, p.y));
    }
  }
  for (const id of [...pos.keys()]) if (!idset.has(id)) pos.delete(id);
}

function nodeRadius(n) { return 6 + Math.min(n.degree || 0, 10) + (n.type === "finding" || n.type === "session" ? 2 : 0); }

function renderGraph() {
  const svg = $("graphSvg");
  svg.setAttribute("viewBox", `0 0 ${graphState.W} ${graphState.H}`);
  svg.innerHTML = "";
  graphState.nodeEls.clear(); graphState.edgeEls = [];

  const root = document.createElementNS(SVGNS, "g");
  root.setAttribute("id", "graphRoot");
  svg.appendChild(root);

  const eg = document.createElementNS(SVGNS, "g");
  root.appendChild(eg);
  for (const e of graphState.edges) {
    const line = document.createElementNS(SVGNS, "line");
    line.setAttribute("class", "g-edge");
    eg.appendChild(line);
    graphState.edgeEls.push({ line, from: e.from, to: e.to, type: e.type });
  }

  const ng = document.createElementNS(SVGNS, "g");
  root.appendChild(ng);
  for (const n of graphState.nodes) {
    const g = document.createElementNS(SVGNS, "g");
    g.setAttribute("class", "g-node");
    const c = document.createElementNS(SVGNS, "circle");
    c.setAttribute("r", nodeRadius(n));
    c.setAttribute("fill", NODE_COLOR[n.type] || "#888");
    c.setAttribute("stroke", RISK_STROKE[n.risk] || "#555");
    c.setAttribute("stroke-width", n.risk === "HIGH" || n.risk === "CRITICAL" ? 3 : 1.5);
    const t = document.createElementNS(SVGNS, "text");
    t.setAttribute("class", "g-label");
    t.setAttribute("dy", -nodeRadius(n) - 4);
    t.textContent = n.label.length > 26 ? n.label.slice(0, 25) + "…" : n.label;
    g.appendChild(c); g.appendChild(t);
    ng.appendChild(g);
    graphState.nodeEls.set(n.id, { g, circle: c, label: t, node: n });
    attachNodeHandlers(n, g);
  }
  positionGraph();
  applyTransform();
}

function positionGraph() {
  const pos = graphState.pos;
  for (const [id, refs] of graphState.nodeEls) {
    const p = pos.get(id); if (!p) continue;
    refs.g.setAttribute("transform", `translate(${p.x},${p.y})`);
  }
  for (const e of graphState.edgeEls) {
    const a = pos.get(e.from), b = pos.get(e.to); if (!a || !b) continue;
    e.line.setAttribute("x1", a.x); e.line.setAttribute("y1", a.y);
    e.line.setAttribute("x2", b.x); e.line.setAttribute("y2", b.y);
  }
}

function applyTransform() {
  const root = document.getElementById("graphRoot");
  if (root) root.setAttribute("transform", `translate(${graphState.panX},${graphState.panY}) scale(${graphState.zoom})`);
}

function setZoom(z) { graphState.zoom = Math.max(0.2, Math.min(4, z)); applyTransform(); }

function setupGraphInteractions() {
  const svg = $("graphSvg");
  let panning = false, sx = 0, sy = 0, opx = 0, opy = 0;

  svg.addEventListener("mousedown", (e) => {
    if (e.target.closest(".g-node")) return; // node drag handles itself
    panning = true; sx = e.clientX; sy = e.clientY; opx = graphState.panX; opy = graphState.panY;
  });
  window.addEventListener("mousemove", (e) => {
    if (!panning) return;
    graphState.panX = opx + (e.clientX - sx); graphState.panY = opy + (e.clientY - sy); applyTransform();
  });
  window.addEventListener("mouseup", () => { panning = false; });

  svg.addEventListener("wheel", (e) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 1 / 1.12;
    setZoom(graphState.zoom * factor);
  }, { passive: false });
}

function attachNodeHandlers(n, g) {
  let dragging = false, moved = false, sx = 0, sy = 0, start = null;
  const svg = $("graphSvg");
  g.addEventListener("mousedown", (e) => {
    e.stopPropagation();
    dragging = true; moved = false; sx = e.clientX; sy = e.clientY;
    start = { ...graphState.pos.get(n.id) };
  });
  window.addEventListener("mousemove", (e) => {
    if (!dragging) return;
    const dx = (e.clientX - sx) / graphState.zoom, dy = (e.clientY - sy) / graphState.zoom;
    if (Math.abs(dx) + Math.abs(dy) > 2) moved = true;
    graphState.pos.set(n.id, { x: start.x + dx, y: start.y + dy });
    positionGraph();
  });
  window.addEventListener("mouseup", () => {
    if (dragging && !moved) selectGraphNode(n.id);
    dragging = false;
  });
}

async function selectGraphNode(id) {
  graphState.selected = id;
  for (const [nid, refs] of graphState.nodeEls) {
    refs.circle.setAttribute("opacity", nid === id ? 1 : 0.5);
  }
  const node = graphState.nodes.find((n) => n.id === id) || {};
  const panel = $("graphPanel");
  panel.classList.remove("hidden");
  panel.innerHTML = `<div class="muted">Loading evidence paths…</div>`;
  const paths = await window.api.graphPaths(id, { limit: 10 });

  const pathHtml = paths.length
    ? paths.map((p) => `<div class="gpath">${p.steps.map((s) =>
        `<span class="gstep ${s.risk}">${esc(s.type)}:${esc(s.label).slice(0, 18)}</span>`).join('<span class="garrow">→</span>')}</div>`).join("")
    : `<div class="muted">No evidence paths from this node.</div>`;

  panel.innerHTML = `
    <div class="gpanel-head">
      <div><b>${esc(node.label || id)}</b><div class="muted">${esc(node.type || "")} · ${esc(node.risk || "")}${node.score ? " · score " + node.score : ""}</div></div>
      <button class="btn ghost" id="gPanelClose">✕</button>
    </div>
    <div class="gpanel-actions">
      <button class="btn ghost" id="gFocus">Focus neighborhood</button>
      <button class="btn ghost" id="gClearFocus">Clear focus</button>
    </div>
    <h4 class="inv-h3" style="margin-top:12px">Evidence paths → findings</h4>
    ${pathHtml}
  `;
  $("gPanelClose").addEventListener("click", () => { panel.classList.add("hidden"); graphState.selected = null; for (const [, r] of graphState.nodeEls) r.circle.setAttribute("opacity", 1); });
  $("gFocus").addEventListener("click", () => { graphState.focus = id; loadGraph(); });
  $("gClearFocus").addEventListener("click", () => { graphState.focus = null; loadGraph(); });
}

async function showClusters() {
  const clusters = await window.api.graphClusters({ limit: 30 });
  const panel = $("graphPanel");
  panel.classList.remove("hidden");
  const rows = clusters.length
    ? clusters.map((c) => `
      <div class="gcluster ${c.highRisk ? "high" : ""}" data-node="${esc(c.nodeIds[0] || "")}">
        <div class="gcluster-head"><b>${esc(c.label)}</b>${c.highRisk ? '<span class="sev-pill HIGH">HIGH-RISK</span>' : ""}</div>
        <div class="muted">${c.size} nodes · ${c.trackers} trackers · ${c.permissions} perms · ${c.findings} findings · ${c.downloads} downloads · max ${c.maxRisk}</div>
      </div>`).join("")
    : `<div class="muted">No clusters yet.</div>`;
  panel.innerHTML = `
    <div class="gpanel-head"><b>High-risk clusters</b><button class="btn ghost" id="gPanelClose">✕</button></div>
    ${rows}`;
  $("gPanelClose").addEventListener("click", () => panel.classList.add("hidden"));
  panel.querySelectorAll(".gcluster").forEach((el) => el.addEventListener("click", () => {
    if (el.dataset.node) { graphState.focus = el.dataset.node; loadGraph(); }
  }));
}

/* -------------------------------- tabs/wiring ----------------------------- */

/* ------------------------------ acquisition ------------------------------- */

const acqState = { discovered: null, artifactTypes: null };

const ACQ_ARTIFACTS = [
  "history", "downloads", "cookies", "bookmarks", "extensions", "logins",
  "localStorage", "indexedDB", "favicons", "topsites", "preferences",
  "sessions", "serviceWorkers",
];

const ACQ_SEP = "\u241F"; // unit separator for "browserId<sep>profilePath" option values

async function loadAcquire() {
  renderArtifactToggles();
  await renderAcqRuns();
}

function renderArtifactToggles() {
  const host = $("acqArtifacts");
  if (!host) return;
  if (!acqState.artifactTypes) acqState.artifactTypes = new Set(ACQ_ARTIFACTS);
  host.innerHTML = `<div class="acq-art-label">Artifacts to acquire</div>` +
    ACQ_ARTIFACTS.map((t) => {
      const on = acqState.artifactTypes.has(t);
      return `<label class="acq-chip ${on ? "on" : ""}"><input type="checkbox" data-art="${esc(t)}" ${on ? "checked" : ""}/> ${esc(t)}</label>`;
    }).join("");
  host.querySelectorAll("input[data-art]").forEach((cb) =>
    cb.addEventListener("change", () => {
      const t = cb.dataset.art;
      if (cb.checked) acqState.artifactTypes.add(t); else acqState.artifactTypes.delete(t);
      cb.closest(".acq-chip").classList.toggle("on", cb.checked);
    }));
}

async function discoverBrowsers() {
  const btn = $("acqDiscover");
  btn.textContent = "Scanning…"; btn.disabled = true;
  const res = await window.api.acqBrowsers();
  btn.textContent = "Discover browsers"; btn.disabled = false;
  acqState.discovered = res;
  $("acqHostMeta").textContent = `${res.host} · ${res.platform} · ${res.browsers.length} browser(s)`;

  const sel = $("acqProfile");
  const opts = [];
  for (const b of res.browsers) {
    for (const p of b.profiles) {
      const v = `${b.id}${ACQ_SEP}${p.profilePath}`;
      const label = `${b.name} — ${p.profile}${p.browserVersion ? ` (v${p.browserVersion})` : ""}`;
      opts.push(`<option value="${esc(v)}">${esc(label)}</option>`);
    }
  }
  sel.innerHTML = opts.length ? opts.join("") : `<option value="">No browsers / profiles found on this machine</option>`;
  $("acqRun").disabled = !opts.length;
}

async function runAcquisition() {
  const val = $("acqProfile").value;
  if (!val) return;
  const idx = val.indexOf(ACQ_SEP);
  const browserId = val.slice(0, idx);
  const profilePath = val.slice(idx + 1);
  const artifactTypes = acqState.artifactTypes ? [...acqState.artifactTypes] : null;

  const btn = $("acqRun");
  btn.disabled = true; btn.textContent = "Acquiring…";
  $("acqRunStatus").textContent = "reading (read-only)…";
  const res = await window.api.acqRun({ browserId, profilePath, artifactTypes });
  btn.disabled = false; btn.textContent = "Acquire selected →";
  if (res.ok) {
    $("acqRunStatus").textContent =
      `done · ${res.summary.recordCount} records · ${res.summary.artifactsOk}/${res.summary.artifactCount} artifacts ok`;
    await renderAcqRuns();
    openAcquisition(res.summary.runId);
  } else {
    $("acqRunStatus").textContent = res.error || "failed";
  }
}

function acqShort(h) { return h ? `${String(h).slice(0, 12)}…` : "—"; }

async function renderAcqRuns() {
  const tbody = $("acqRows");
  if (!tbody) return;
  const runs = await window.api.acqList();
  tbody.innerHTML = runs.map((r) => `
    <tr class="acq-row" data-id="${esc(r.runId)}">
      <td>${fmtDateTime(r.acquiredAt)}</td>
      <td>${esc(r.browser)}</td>
      <td>${esc(r.browserVersion || "?")}</td>
      <td>${esc(r.profile)}</td>
      <td>${esc(r.host)}</td>
      <td>${r.artifactsOk}/${r.artifactCount}${r.artifactsFailed ? ` · ${r.artifactsFailed} failed` : ""}</td>
      <td>${r.recordCount}</td>
      <td><button class="btn ghost acq-del" data-del="${esc(r.runId)}" title="Delete run">✕</button></td>
    </tr>`).join("") ||
    `<tr><td colspan="8" class="muted">No acquisitions yet. Discover a browser and acquire a profile.</td></tr>`;

  tbody.querySelectorAll(".acq-row").forEach((row) =>
    row.addEventListener("click", (e) => {
      if (e.target.closest(".acq-del")) return;
      openAcquisition(row.dataset.id);
    }));
  tbody.querySelectorAll(".acq-del").forEach((b) =>
    b.addEventListener("click", async (e) => {
      e.stopPropagation();
      if (!confirm("Delete this acquisition run?")) return;
      await window.api.acqRemove(b.dataset.del);
      await renderAcqRuns();
      $("acqDetail").classList.add("hidden");
    }));
}

async function openAcquisition(id) {
  const d = await window.api.acqDetail(id);
  const detail = $("acqDetail");
  if (!d) { detail.classList.add("hidden"); return; }
  const r = d.run;
  const arts = d.artifacts || [];

  const artRows = arts.map((a) => `
    <tr class="${a.errors && a.errors.length ? "art-bad" : "art-ok"}">
      <td>${esc(a.artifactType)}</td>
      <td>${a.recordCount || 0}</td>
      <td>${a.locked ? "yes" : "no"}</td>
      <td>${a.copied ? "yes" : "no"}</td>
      <td class="hashcell">${esc(acqShort(a.sha256))}</td>
      <td>${esc(a.hashScope || "")}</td>
      <td>${a.errors && a.errors.length ? esc(a.errors.join("; ")) : "—"}</td>
    </tr>`).join("") || `<tr><td colspan="7">No artifacts.</td></tr>`;

  const recs = await window.api.acqRecords(id, { limit: 300 });
  const recRows = recs.rows.map((e) => `
    <tr><td>${fmtTime(e.ts)}</td><td>${esc(e.type)}</td>
        <td class="edomain">${esc(e.domain)}</td><td>${esc(e.detail)}</td></tr>`)
    .join("") || `<tr><td colspan="4">No normalized records.</td></tr>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(r.browser)} · ${esc(r.profile)}</h2>
        <div class="muted">${esc(r.runId)}</div>
      </div>
      <button id="acqExport" class="btn ghost">Export report</button>
    </div>
    <div class="inv-cards">
      <div class="inv-card"><div class="inv-card-label">Source</div>
        <div>${esc(r.browser)} <span class="muted">(${esc(r.browserFamily)})</span></div>
        <div>v${esc(r.browserVersion || "?")} <span class="muted">${esc(r.versionSource)}</span></div></div>
      <div class="inv-card"><div class="inv-card-label">Provenance</div>
        <div>${esc(r.host)} · ${esc(r.platform)}</div>
        <div class="muted">${fmtDateTime(r.startedAt)} → ${fmtDateTime(r.finishedAt)}</div></div>
      <div class="inv-card"><div class="inv-card-label">Records</div>
        <div class="inv-card-num">${d.summary.recordCount}</div>
        <div class="muted">${d.summary.artifactsOk}/${d.summary.artifactCount} artifacts ok</div></div>
      <div class="inv-card"><div class="inv-card-label">Profile hash</div>
        <div class="hashcell">${esc(acqShort(r.profileHash))}</div>
        <div class="muted">sha256(browser|path|version)</div></div>
    </div>

    <h3 class="inv-h3">Artifacts</h3>
    <table class="grid"><thead>
      <tr><th>Artifact</th><th>Records</th><th>Locked</th><th>Copied</th><th>SHA-256</th><th>Scope</th><th>Errors</th></tr>
    </thead><tbody>${artRows}</tbody></table>

    <h3 class="inv-h3">Normalized records <span class="muted">(${recs.total} total, showing ${recs.rows.length})</span></h3>
    <table class="grid inv-timeline"><thead>
      <tr><th>Time</th><th>Type</th><th>Domain</th><th>Detail</th></tr>
    </thead><tbody>${recRows}</tbody></table>
    <p class="muted" style="margin-top:12px">Read-only · credentials never decrypted (encrypted-field presence &amp; length only).</p>
  `;
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });

  $("acqExport").addEventListener("click", async () => {
    const btn = $("acqExport");
    const res = await window.api.exportAcquisition(id);
    if (res.ok) btn.textContent = "Saved ✓";
    else if (res.error !== "Cancelled") btn.textContent = res.error || "Failed";
    setTimeout(() => { btn.textContent = "Export report"; }, 2500);
  });
}

/* --------------------------- timeline engine ------------------------------ */

const timelineState = {
  offset: 0,
  pageSize: 200,
  total: 0,
  built: false,
  selected: null,
  facetsLoaded: false,
};

function tlReadFilters() {
  const f = {};
  const q = $("tlQ").value.trim(); if (q) f.q = q;
  const src = $("tlSource").value; if (src) f.sourceType = src;
  const art = $("tlArtifact").value; if (art) f.artifactType = art;
  const sev = $("tlSeverity").value; if (sev) f.severity = sev;
  const br = $("tlBrowser").value; if (br) f.browser = br;
  const pr = $("tlProfile").value; if (pr) f.profile = pr;
  const dom = $("tlDomain").value.trim(); if (dom) f.domain = dom;
  const since = $("tlSince").value; if (since) f.since = new Date(since).getTime();
  const until = $("tlUntil").value; if (until) f.until = new Date(until).getTime();
  if ($("tlCorrelated").checked) f.correlatedOnly = true;
  return f;
}

function tlFillSelect(sel, values, current) {
  const first = sel.querySelector("option");
  const head = first ? first.outerHTML : `<option value="">Any</option>`;
  sel.innerHTML = head + values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
  if (current && values.includes(current)) sel.value = current;
}

function tlApplyFacets(filters) {
  if (!filters) return;
  tlFillSelect($("tlSource"), filters.sourceTypes || [], $("tlSource").value);
  tlFillSelect($("tlArtifact"), filters.artifactTypes || [], $("tlArtifact").value);
  tlFillSelect($("tlBrowser"), filters.browsers || [], $("tlBrowser").value);
  tlFillSelect($("tlProfile"), filters.profiles || [], $("tlProfile").value);
  timelineState.facetsLoaded = true;
}

function tlSeverityRank(s) {
  return { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[s] != null
    ? { INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }[s] : 0;
}

function tlSevPill(sev) { return `<span class="sev-pill ${esc(sev)}">${esc(sev)}</span>`; }

function tlCorrCell(e) {
  if (!e.correlationType) return `<span class="corr-none">—</span>`;
  const n = (e.relatedTimelineIds || []).length;
  return `<span class="corr-badge">${esc(e.correlationType)} · ${Math.round((e.confidenceScore || 0) * 100)}%</span>` +
    `<div class="muted" style="margin-top:3px">${n} link${n === 1 ? "" : "s"}</div>`;
}

function tlRowHtml(e) {
  return `
    <tr class="tl-row" data-id="${esc(e.timelineId)}">
      <td>${fmtDateTime(e.ts)}${e.approxTs ? ` <span class="tl-approx" title="approximate — placed at acquisition time">~</span>` : ""}</td>
      <td><span class="tl-src ${esc(e.sourceType)}">${esc(e.sourceType)}</span></td>
      <td>${esc(e.category)}${e.artifactType ? ` <span class="muted">(${esc(e.artifactType)})</span>` : ""}</td>
      <td>${tlSevPill(e.severity)}</td>
      <td class="tl-title">${esc(e.title)}${e.detail ? `<span class="muted">${esc(e.detail)}</span>` : ""}</td>
      <td class="edomain">${esc(e.domain || "—")}</td>
      <td>${tlCorrCell(e)}</td>
    </tr>`;
}

function tlBindRows() {
  $("timelineRows").querySelectorAll(".tl-row").forEach((row) =>
    row.addEventListener("click", () => openTimelineEntry(row.dataset.id)));
}

async function loadTimeline(reset = true) {
  const meta = $("timelineMeta");
  if (reset) {
    timelineState.offset = 0;
    $("timelineRows").innerHTML = "";
    $("timelineDetail").classList.add("hidden");
    timelineState.selected = null;
  }
  const filter = tlReadFilters();
  filter.limit = timelineState.pageSize;
  filter.offset = timelineState.offset;
  filter.order = "desc";

  const res = await window.api.timelineList(filter);
  timelineState.total = res.total || 0;
  timelineState.built = !!(res.stats && res.stats.built);

  if (!timelineState.facetsLoaded || reset) tlApplyFacets(res.filters);

  if (!timelineState.built) {
    $("timelineRows").innerHTML = `<tr><td colspan="7" class="muted">Timeline not built yet. Click “Build / rebuild” to merge live events, findings and acquisitions.</td></tr>`;
    meta.textContent = "not built";
    $("timelineMore").classList.add("hidden");
    return;
  }

  const rowsHtml = res.rows.map(tlRowHtml).join("");
  if (reset) {
    $("timelineRows").innerHTML = rowsHtml ||
      `<tr><td colspan="7" class="muted">No entries match these filters.</td></tr>`;
  } else if (rowsHtml) {
    $("timelineRows").insertAdjacentHTML("beforeend", rowsHtml);
  }
  tlBindRows();

  timelineState.offset += res.rows.length;
  const s = res.stats || {};
  const corr = s.correlationEdges || 0;
  meta.textContent =
    `${timelineState.total} entries · ${s.correlated || 0} correlated · ${corr} links · built ${fmtDateTime(s.builtAt)}`;

  $("timelineMore").classList.toggle("hidden", timelineState.offset >= timelineState.total);
}

async function buildTimeline() {
  const btn = $("timelineBuild");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Building…";
  const res = await window.api.timelineBuild();
  btn.disabled = false; btn.textContent = prev;
  if (res && res.ok) {
    timelineState.facetsLoaded = false;
    await loadTimeline(true);
  } else {
    $("timelineMeta").textContent = (res && res.error) || "build failed";
  }
}

async function openTimelineEntry(id) {
  const d = await window.api.timelineDetail(id);
  const detail = $("timelineDetail");
  if (!d || !d.entry) { detail.classList.add("hidden"); return; }
  const e = d.entry;
  timelineState.selected = id;
  $("timelineRows").querySelectorAll(".tl-row").forEach((r) =>
    r.classList.toggle("selected", r.dataset.id === id));

  const tags = (e.tags || []).map((t) => `<span class="tag">${esc(t)}</span>`).join(" ") || `<span class="muted">none</span>`;

  const relRows = (d.related || []).map((r) => `
    <tr class="tl-rel-row" data-id="${esc(r.timelineId)}">
      <td>${fmtDateTime(r.ts)}</td>
      <td><span class="tl-src ${esc(r.sourceType)}">${esc(r.sourceType)}</span></td>
      <td>${esc(r.category)}</td>
      <td>${tlSevPill(r.severity)}</td>
      <td class="tl-title">${esc(r.title)}</td>
      <td class="edomain">${esc(r.domain || "—")}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">No correlated entries.</td></tr>`;

  const corrSummary = (d.correlations || []).reduce((m, c) => {
    m[c.type] = m[c.type] || { type: c.type, count: 0, conf: 0 };
    m[c.type].count++; m[c.type].conf = Math.max(m[c.type].conf, c.confidence);
    return m;
  }, {});
  const corrBits = Object.values(corrSummary)
    .map((c) => `<span class="corr-badge">${esc(c.type)} · ${Math.round(c.conf * 100)}% · ${c.count}</span>`)
    .join(" ") || `<span class="muted">none</span>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(e.title)} ${tlSevPill(e.severity)}</h2>
        <div class="muted">${esc(e.timelineId)} · ${esc(e.sourceType)}${e.artifactType ? ` · ${esc(e.artifactType)}` : ""}</div>
      </div>
    </div>
    <div class="inv-cards">
      <div class="inv-card"><div class="inv-card-label">When</div>
        <div>${fmtDateTime(e.ts)}</div>
        <div class="muted">${esc(e.tsKind || "")}${e.approxTs ? " · approx (acquisition time)" : ""}</div></div>
      <div class="inv-card"><div class="inv-card-label">Where</div>
        <div class="edomain">${esc(e.domain || "—")}</div>
        <div class="muted">${esc(e.url || "")}</div></div>
      <div class="inv-card"><div class="inv-card-label">Source</div>
        <div>${esc(e.sourceType)}</div>
        <div class="muted">${e.browser ? esc(e.browser) : "live capture"}${e.profile ? " · " + esc(e.profile) : ""}</div></div>
      <div class="inv-card"><div class="inv-card-label">Correlation</div>
        <div>${e.correlationType ? `${esc(e.correlationType)} · ${Math.round((e.confidenceScore || 0) * 100)}%` : "none"}</div>
        <div class="muted">${(e.relatedTimelineIds || []).length} linked entr${(e.relatedTimelineIds || []).length === 1 ? "y" : "ies"}</div></div>
    </div>

    <h3 class="inv-h3">Detail</h3>
    <p style="font-size:13px">${esc(e.detail || "—")}</p>
    <div class="muted">runId ${esc(e.runId || "—")} · artifactId ${esc(e.artifactId || "—")} · eventId ${esc(e.eventId || "—")}</div>
    <div class="tl-tags">${tags}</div>

    <h3 class="inv-h3">Correlations</h3>
    <div class="tl-detail-corr">${corrBits}</div>

    <h3 class="inv-h3">Correlated entries <span class="muted">(${(d.related || []).length})</span></h3>
    <table class="grid inv-timeline"><thead>
      <tr><th>Time</th><th>Source</th><th>Category</th><th>Severity</th><th>Title</th><th>Domain</th></tr>
    </thead><tbody>${relRows}</tbody></table>
  `;
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });

  detail.querySelectorAll(".tl-rel-row").forEach((r) =>
    r.addEventListener("click", () => openTimelineEntry(r.dataset.id)));
}

function tlResetFilters() {
  ["tlQ", "tlDomain", "tlSince", "tlUntil"].forEach((id) => { $(id).value = ""; });
  ["tlSource", "tlArtifact", "tlSeverity", "tlBrowser", "tlProfile"].forEach((id) => { $(id).value = ""; });
  $("tlCorrelated").checked = false;
  loadTimeline(true);
}

async function exportTimeline() {
  const btn = $("timelineExport");
  const prev = btn.textContent;
  const res = await window.api.exportTimeline("html", tlReadFilters());
  if (res && res.ok) btn.textContent = "Saved ✓";
  else if (res && res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  setTimeout(() => { btn.textContent = prev; }, 2500);
}

/* -------------------------- extension forensics --------------------------- */

const extState = { offset: 0, pageSize: 300, total: 0, scanned: false, facetsLoaded: false, selected: null };

function exReadFilters() {
  const f = {};
  const q = $("exQ").value.trim(); if (q) f.q = q;
  const risk = $("exRisk").value; if (risk) f.riskLevel = risk;
  const br = $("exBrowser").value; if (br) f.browser = br;
  const st = $("exState").value; if (st) f.enabledState = st;
  if ($("exCorrelated").checked) f.correlatedOnly = true;
  return f;
}

function exFillSelect(sel, values) {
  const first = sel.querySelector("option");
  const head = first ? first.outerHTML : `<option value="">Any</option>`;
  const cur = sel.value;
  sel.innerHTML = head + values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
  if (cur && values.includes(cur)) sel.value = cur;
}

function exRiskPill(lvl) { return `<span class="sev-pill ${esc(lvl)}">${esc(lvl)}</span>`; }

function exAge(ms) { return ms == null ? "—" : `${Math.max(0, Math.round(ms / 86400000))}d`; }

function exPermBits(p) {
  const ps = p.permissionsSummary || {};
  const bits = [];
  if (ps.allUrls) bits.push(`<span class="pill HIGH">all_urls</span>`);
  else if (ps.wildcardHosts) bits.push(`<span class="pill MEDIUM">wildcard</span>`);
  if (ps.fileAccess) bits.push(`<span class="pill HIGH">file://</span>`);
  if ((ps.dangerous || []).length) bits.push(`<span class="pill HIGH">${ps.dangerous.length} dangerous</span>`);
  return bits.join(" ");
}

function extRowHtml(p) {
  const ps = p.permissionsSummary || {};
  return `
    <tr class="ext-row" data-key="${esc(p.key)}" data-id="${esc(p.extensionId)}">
      <td>${exRiskPill(p.riskLevel)}<div class="muted">score ${p.riskScore}</div></td>
      <td class="ext-name">${esc(p.name)}<div class="muted">${esc(p.extensionId)}</div></td>
      <td>${esc(p.browser || "—")}<div class="muted">${esc(p.profile || "")}</div></td>
      <td>v${esc(p.version)}<div class="muted">mv${esc(p.manifestVersion)}</div></td>
      <td>${esc(p.enabledState)}</td>
      <td>${(ps.api || []).length} api · ${(ps.host || []).length} host<div class="ext-flags">${exPermBits(p)}</div></td>
      <td>${(p.relatedTimelineIds || []).length} tl · ${(p.relatedFindingIds || []).length} find</td>
    </tr>`;
}

function extBindRows() {
  $("extRows").querySelectorAll(".ext-row").forEach((row) =>
    row.addEventListener("click", () => openExtension(row.dataset.id, row.dataset.key)));
}

function exRenderCards(stats) {
  const host = $("extCards");
  if (!host) return;
  if (!stats || !stats.scanned) { host.innerHTML = ""; return; }
  const lv = stats.byRiskLevel || {};
  const card = (label, val, cls) =>
    `<div class="ext-card ${cls || ""}"><div class="ext-card-num">${val || 0}</div><div class="ext-card-label">${esc(label)}</div></div>`;
  host.innerHTML =
    card("extensions", stats.total) +
    card("critical", lv.CRITICAL, "CRITICAL") +
    card("high", lv.HIGH, "HIGH") +
    card("medium", lv.MEDIUM, "MEDIUM") +
    card("disabled", stats.disabled) +
    card("findings", stats.findingCount) +
    card("correlated", stats.correlated);
}

async function loadExtensions(reset = true) {
  if (reset) {
    extState.offset = 0;
    $("extRows").innerHTML = "";
    $("extDetail").classList.add("hidden");
    extState.selected = null;
  }
  const filter = exReadFilters();
  filter.limit = extState.pageSize;
  filter.offset = extState.offset;

  const res = await window.api.extList(filter);
  extState.total = res.total || 0;
  extState.scanned = !!(res.stats && res.stats.scanned);

  if (res.filters && (!extState.facetsLoaded || reset)) {
    exFillSelect($("exBrowser"), res.filters.browsers || []);
    extState.facetsLoaded = true;
  }
  exRenderCards(res.stats);

  if (!extState.scanned) {
    $("extRows").innerHTML = `<tr><td colspan="7" class="muted">Not scanned yet. Click “Scan extensions” to analyze acquired extension artifacts (no reacquisition).</td></tr>`;
    $("extMeta").textContent = "not scanned";
    return;
  }

  const rowsHtml = res.rows.map(extRowHtml).join("");
  if (reset) {
    $("extRows").innerHTML = rowsHtml || `<tr><td colspan="7" class="muted">No extensions match these filters.</td></tr>`;
  } else if (rowsHtml) {
    $("extRows").insertAdjacentHTML("beforeend", rowsHtml);
  }
  extBindRows();
  extState.offset += res.rows.length;

  const s = res.stats || {};
  $("extMeta").textContent =
    `${extState.total} extensions · ${s.findingCount || 0} findings · ${s.correlated || 0} correlated · scanned ${fmtDateTime(s.scannedAt)}`;
}

async function scanExtensions() {
  const btn = $("extScan");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Scanning…";
  const res = await window.api.extScan();
  btn.disabled = false; btn.textContent = prev;
  if (res && res.ok) {
    extState.facetsLoaded = false;
    await loadExtensions(true);
  } else {
    $("extMeta").textContent = (res && res.error) || "scan failed";
  }
}

async function openExtension(extensionId, key) {
  const d = await window.api.extDetail(extensionId, key);
  const detail = $("extDetail");
  if (!d || !d.profile) { detail.classList.add("hidden"); return; }
  const p = d.profile;
  extState.selected = key || extensionId;
  $("extRows").querySelectorAll(".ext-row").forEach((r) =>
    r.classList.toggle("selected", r.dataset.key === (key || r.dataset.key) && r.dataset.id === extensionId));

  const ps = p.permissionsSummary || {};
  const apiTags = (ps.api || []).map((x) => `<span class="tag">${esc(x)}</span>`).join(" ") || `<span class="muted">none</span>`;
  const hostTags = (ps.host || []).map((x) => `<span class="tag ${/(\*|<all_urls>|file:)/i.test(x) ? "tag-warn" : ""}">${esc(x)}</span>`).join(" ") || `<span class="muted">none</span>`;
  const domTags = (ps.domains || []).map((x) => `<span class="tag clickable" data-domain="${esc(x)}">${esc(x)}</span>`).join(" ") || `<span class="muted">none</span>`;

  const findingRows = (d.findings || []).map((f) => `
    <tr class="sev-row ${esc(f.severity)}">
      <td>${exRiskPill(f.severity)}</td>
      <td>${esc(f.reason)}</td>
      <td>${esc(f.evidence)}</td>
      <td class="muted">${fmtDateTime(f.ts)}</td>
    </tr>`).join("") || `<tr><td colspan="4" class="muted">No risk findings.</td></tr>`;

  const tlRows = (d.relatedTimeline || []).map((e) => `
    <tr class="tl-rel-row" data-id="${esc(e.timelineId)}">
      <td>${fmtDateTime(e.ts)}</td>
      <td><span class="tl-src ${esc(e.sourceType)}">${esc(e.sourceType)}</span></td>
      <td>${esc(e.category)}</td>
      <td>${esc(e.relation)}</td>
      <td class="edomain">${esc(e.domain || "—")}</td>
      <td>${esc(e.title)}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">No correlated timeline events.</td></tr>`;

  const relFindRows = (d.relatedFindings || []).map((f) => `
    <tr><td>${exRiskPill(f.severity)}</td><td>${esc(f.title)}</td><td class="muted">${fmtDateTime(f.lastSeen)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="muted">No correlated behavioral findings.</td></tr>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(p.name)} ${exRiskPill(p.riskLevel)}</h2>
        <div class="muted">${esc(p.extensionId)} · ${esc(p.browser || "")}${p.profile ? " · " + esc(p.profile) : ""}</div>
      </div>
    </div>
    <div class="inv-cards">
      <div class="inv-card"><div class="inv-card-label">Risk</div>
        <div class="inv-card-num ${["HIGH","CRITICAL"].includes(p.riskLevel) ? "HIGH" : (p.riskLevel === "MEDIUM" ? "MEDIUM" : "INFO")}">${p.riskScore}</div>
        <div class="muted">${esc(p.riskLevel)} · ${p.findingCount} finding(s)</div></div>
      <div class="inv-card"><div class="inv-card-label">Version</div>
        <div>v${esc(p.version)}</div><div class="muted">manifest v${esc(p.manifestVersion)}</div></div>
      <div class="inv-card"><div class="inv-card-label">State</div>
        <div>${esc(p.enabledState)}</div>
        <div class="muted">install ${exAge(p.installAge)} · update ${exAge(p.updateAge)}</div></div>
      <div class="inv-card"><div class="inv-card-label">Correlation</div>
        <div>${(p.relatedTimelineIds || []).length} timeline · ${(p.relatedServiceWorkerIds || []).length} sw</div>
        <div class="muted">${(p.relatedFindingIds || []).length} finding link(s)</div></div>
    </div>

    <h3 class="inv-h3">Risk findings <span class="muted">(${(d.findings || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Severity</th><th>Reason</th><th>Evidence</th><th>When</th></tr>
    </thead><tbody>${findingRows}</tbody></table>

    <h3 class="inv-h3">Permissions</h3>
    <div class="ext-perm-block"><div class="ext-perm-label">API (${(ps.api || []).length})</div><div class="tags">${apiTags}</div></div>
    <div class="ext-perm-block"><div class="ext-perm-label">Host (${(ps.host || []).length})</div><div class="tags">${hostTags}</div></div>
    <div class="ext-perm-block"><div class="ext-perm-label">Domains</div><div class="tags">${domTags}</div></div>
    <div class="muted" style="margin-top:8px">source: ${esc(p.sourcePath || "—")}</div>

    <h3 class="inv-h3">Correlated timeline events <span class="muted">(${(d.relatedTimeline || []).length})</span></h3>
    <table class="grid inv-timeline"><thead>
      <tr><th>Time</th><th>Source</th><th>Category</th><th>Relation</th><th>Domain</th><th>Title</th></tr>
    </thead><tbody>${tlRows}</tbody></table>

    <h3 class="inv-h3">Correlated behavioral findings <span class="muted">(${(d.relatedFindings || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Severity</th><th>Finding</th><th>Last seen</th></tr>
    </thead><tbody>${relFindRows}</tbody></table>
  `;
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });

  detail.querySelectorAll(".tag.clickable").forEach((el) =>
    el.addEventListener("click", () => renderInvestigation(el.dataset.domain)));
  detail.querySelectorAll(".tl-rel-row").forEach((row) =>
    row.addEventListener("click", () => { switchTab("timeline"); if (typeof openTimelineEntry === "function") openTimelineEntry(row.dataset.id); }));
}

function exResetFilters() {
  $("exQ").value = "";
  ["exRisk", "exBrowser", "exState"].forEach((id) => { $(id).value = ""; });
  $("exCorrelated").checked = false;
  loadExtensions(true);
}

async function exportExtensions() {
  const btn = $("extExport");
  const prev = btn.textContent;
  const res = await window.api.exportExtensions("html", exReadFilters());
  if (res && res.ok) btn.textContent = "Saved ✓";
  else if (res && res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  setTimeout(() => { btn.textContent = prev; }, 2500);
}

/* ---------------------------- cache forensics ----------------------------- */

const cacheState = { offset: 0, pageSize: 300, total: 0, scanned: false, facetsLoaded: false, selected: null };

function caBytes(n) {
  if (n == null) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1048576).toFixed(1)} MB`;
}

function caReadFilters() {
  const f = {};
  const q = $("caQ").value.trim(); if (q) f.q = q;
  const risk = $("caRisk").value; if (risk) f.riskLevel = risk;
  const ty = $("caType").value; if (ty) f.cacheType = ty;
  const br = $("caBrowser").value; if (br) f.browser = br;
  if ($("caCorrelated").checked) f.correlatedOnly = true;
  return f;
}

function caFillSelect(sel, values) {
  const first = sel.querySelector("option");
  const head = first ? first.outerHTML : `<option value="">Any</option>`;
  const cur = sel.value;
  sel.innerHTML = head + values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
  if (cur && values.includes(cur)) sel.value = cur;
}

function caRiskPill(lvl) { return `<span class="sev-pill ${esc(lvl)}">${esc(lvl)}</span>`; }

function cacheRowHtml(p) {
  return `
    <tr class="ext-row" data-id="${esc(p.cacheId)}">
      <td>${caRiskPill(p.riskLevel)}<div class="muted">score ${p.riskScore}</div></td>
      <td class="ext-name">${esc(p.cacheName)}<div class="muted">${esc(p.cacheType)}${p.scope ? " · " + esc(p.scope) : ""}</div></td>
      <td>${esc(p.browser || "—")}<div class="muted">${esc(p.profile || "")}</div></td>
      <td>${p.entryCount}</td>
      <td>${caBytes(p.totalSize)}</td>
      <td>${p.domainCount}<div class="muted">${esc((p.domainSample || []).slice(0, 3).join(", "))}</div></td>
      <td>${(p.relatedTimelineIds || []).length} tl · ${(p.relatedExtensionIds || []).length} ext · ${(p.relatedFindingIds || []).length} find</td>
    </tr>`;
}

function cacheBindRows() {
  $("cacheRows").querySelectorAll(".ext-row").forEach((row) =>
    row.addEventListener("click", () => openCache(row.dataset.id)));
}

function caRenderCards(stats) {
  const host = $("cacheCards");
  if (!host) return;
  if (!stats || !stats.scanned) { host.innerHTML = ""; return; }
  const lv = stats.byRiskLevel || {};
  const card = (label, val, cls) =>
    `<div class="ext-card ${cls || ""}"><div class="ext-card-num">${val}</div><div class="ext-card-label">${esc(label)}</div></div>`;
  host.innerHTML =
    card("stores", stats.total) +
    card("critical", lv.CRITICAL || 0, "CRITICAL") +
    card("high", lv.HIGH || 0, "HIGH") +
    card("medium", lv.MEDIUM || 0, "MEDIUM") +
    card("entries", stats.entryTotal || 0) +
    card("size", caBytes(stats.sizeTotal || 0)) +
    card("findings", stats.findingCount || 0);
}

async function loadCache(reset = true) {
  if (reset) {
    cacheState.offset = 0;
    $("cacheRows").innerHTML = "";
    $("cacheDetail").classList.add("hidden");
    cacheState.selected = null;
  }
  const filter = caReadFilters();
  filter.limit = cacheState.pageSize;
  filter.offset = cacheState.offset;

  const res = await window.api.cacheList(filter);
  cacheState.total = res.total || 0;
  cacheState.scanned = !!(res.stats && res.stats.scanned);

  if (res.filters && (!cacheState.facetsLoaded || reset)) {
    caFillSelect($("caBrowser"), res.filters.browsers || []);
    caFillSelect($("caType"), res.filters.cacheTypes || []);
    cacheState.facetsLoaded = true;
  }
  caRenderCards(res.stats);

  if (!cacheState.scanned) {
    $("cacheRows").innerHTML = `<tr><td colspan="7" class="muted">Not scanned yet. Click “Scan cache” to analyze acquired cache artifacts (metadata only — no cached content is read).</td></tr>`;
    $("cacheMeta").textContent = "not scanned";
    $("cacheMore").classList.add("hidden");
    return;
  }

  const rowsHtml = res.rows.map(cacheRowHtml).join("");
  if (reset) {
    $("cacheRows").innerHTML = rowsHtml || `<tr><td colspan="7" class="muted">No cache stores match these filters.</td></tr>`;
  } else if (rowsHtml) {
    $("cacheRows").insertAdjacentHTML("beforeend", rowsHtml);
  }
  cacheBindRows();
  cacheState.offset += res.rows.length;

  const s = res.stats || {};
  $("cacheMeta").textContent =
    `${cacheState.total} stores · ${s.entryTotal || 0} entries · ${caBytes(s.sizeTotal || 0)} · ${s.findingCount || 0} findings · scanned ${fmtDateTime(s.scannedAt)}`;
  $("cacheMore").classList.toggle("hidden", cacheState.offset >= cacheState.total);
}

async function scanCache() {
  const btn = $("cacheScan");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Scanning…";
  const res = await window.api.cacheScan();
  btn.disabled = false; btn.textContent = prev;
  if (res && res.ok) {
    cacheState.facetsLoaded = false;
    await loadCache(true);
  } else {
    $("cacheMeta").textContent = (res && res.error) || "scan failed";
  }
}

async function openCache(cacheId) {
  const d = await window.api.cacheDetail(cacheId);
  const detail = $("cacheDetail");
  if (!d || !d.profile) { detail.classList.add("hidden"); return; }
  const p = d.profile;
  cacheState.selected = cacheId;
  $("cacheRows").querySelectorAll(".ext-row").forEach((r) =>
    r.classList.toggle("selected", r.dataset.id === cacheId));

  const findingRows = (d.findings || []).map((f) => `
    <tr class="sev-row ${esc(f.severity)}">
      <td>${caRiskPill(f.severity)}</td>
      <td>${esc(f.reason)}</td>
      <td>${esc(f.evidence)}</td>
      <td class="muted">${fmtDateTime(f.ts)}</td>
    </tr>`).join("") || `<tr><td colspan="4" class="muted">No risk findings.</td></tr>`;

  const entryRows = (d.entries || []).slice(0, 200).map((e) => `
    <tr>
      <td class="edomain">${esc(e.domain || "—")}</td>
      <td class="ext-name">${esc(e.url || e.key || "—")}</td>
      <td>${esc(e.contentType || "—")}</td>
      <td>${e.statusCode != null ? e.statusCode : "—"}</td>
      <td>${caBytes(e.size)}</td>
      <td class="muted">${fmtDateTime(e.cacheTime)}</td>
      <td>${(e.tags || []).map((t) => `<span class="tag tag-warn">${esc(t)}</span>`).join(" ")}</td>
    </tr>`).join("") || `<tr><td colspan="7" class="muted">No cached entries captured.</td></tr>`;

  const tlRows = (d.relatedTimeline || []).map((e) => `
    <tr class="tl-rel-row" data-id="${esc(e.timelineId)}">
      <td>${fmtDateTime(e.ts)}</td>
      <td><span class="tl-src ${esc(e.sourceType)}">${esc(e.sourceType)}</span></td>
      <td>${esc(e.category)}</td>
      <td>${esc(e.relation)}</td>
      <td class="edomain">${esc(e.domain || "—")}</td>
      <td>${esc(e.title)}</td>
    </tr>`).join("") || `<tr><td colspan="6" class="muted">No correlated timeline events.</td></tr>`;

  const extRows = (d.relatedExtensions || []).map((x) => `
    <tr class="ext-rel-row" data-id="${esc(x.extensionId)}">
      <td>${caRiskPill(x.riskLevel || "INFO")}</td><td>${esc(x.name)}</td><td class="muted">${esc(x.extensionId)}</td>
    </tr>`).join("") || `<tr><td colspan="3" class="muted">No correlated extensions.</td></tr>`;

  const relFindRows = (d.relatedFindings || []).map((f) => `
    <tr><td>${caRiskPill(f.severity)}</td><td>${esc(f.title)}</td><td class="muted">${fmtDateTime(f.lastSeen)}</td></tr>`).join("")
    || `<tr><td colspan="3" class="muted">No correlated behavioral findings.</td></tr>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(p.cacheName)} ${caRiskPill(p.riskLevel)}</h2>
        <div class="muted">${esc(p.cacheType)}${p.scope ? " · " + esc(p.scope) : ""} · ${esc(p.browser || "")}${p.profile ? " · " + esc(p.profile) : ""}</div>
      </div>
    </div>
    <div class="inv-cards">
      <div class="inv-card"><div class="inv-card-label">Risk</div>
        <div class="inv-card-num ${["HIGH","CRITICAL"].includes(p.riskLevel) ? "HIGH" : (p.riskLevel === "MEDIUM" ? "MEDIUM" : "INFO")}">${p.riskScore}</div>
        <div class="muted">${esc(p.riskLevel)} · ${p.findingCount} finding(s)</div></div>
      <div class="inv-card"><div class="inv-card-label">Entries</div>
        <div>${p.entryCount}</div><div class="muted">${caBytes(p.totalSize)} · ${p.domainCount} domain(s)</div></div>
      <div class="inv-card"><div class="inv-card-label">Source</div>
        <div>${esc(p.cacheType)}</div><div class="muted">${esc(p.sourcePath || "acquisition records")}</div></div>
      <div class="inv-card"><div class="inv-card-label">Correlation</div>
        <div>${(p.relatedTimelineIds || []).length} timeline · ${(p.relatedExtensionIds || []).length} ext</div>
        <div class="muted">${(p.relatedFindingIds || []).length} finding link(s)</div></div>
    </div>

    <h3 class="inv-h3">Risk findings <span class="muted">(${(d.findings || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Severity</th><th>Reason</th><th>Evidence</th><th>When</th></tr>
    </thead><tbody>${findingRows}</tbody></table>

    <h3 class="inv-h3">Cached entries <span class="muted">(showing ${Math.min(200, (d.entries || []).length)} of ${p.entryCount})</span></h3>
    <table class="grid ext-table"><thead>
      <tr><th>Domain</th><th>URL / key</th><th>Content-Type</th><th>Status</th><th>Size</th><th>Cached</th><th>Tags</th></tr>
    </thead><tbody>${entryRows}</tbody></table>

    <h3 class="inv-h3">Correlated timeline events <span class="muted">(${(d.relatedTimeline || []).length})</span></h3>
    <table class="grid inv-timeline"><thead>
      <tr><th>Time</th><th>Source</th><th>Category</th><th>Relation</th><th>Domain</th><th>Title</th></tr>
    </thead><tbody>${tlRows}</tbody></table>

    <h3 class="inv-h3">Correlated extensions <span class="muted">(${(d.relatedExtensions || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Risk</th><th>Extension</th><th>ID</th></tr>
    </thead><tbody>${extRows}</tbody></table>

    <h3 class="inv-h3">Correlated behavioral findings <span class="muted">(${(d.relatedFindings || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Severity</th><th>Finding</th><th>Last seen</th></tr>
    </thead><tbody>${relFindRows}</tbody></table>
  `;
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });

  detail.querySelectorAll(".tl-rel-row").forEach((row) =>
    row.addEventListener("click", () => { switchTab("timeline"); if (typeof openTimelineEntry === "function") openTimelineEntry(row.dataset.id); }));
  detail.querySelectorAll(".ext-rel-row").forEach((row) =>
    row.addEventListener("click", () => { switchTab("extensions"); if (typeof openExtension === "function") openExtension(row.dataset.id); }));
}

function caResetFilters() {
  $("caQ").value = "";
  ["caRisk", "caType", "caBrowser"].forEach((id) => { $(id).value = ""; });
  $("caCorrelated").checked = false;
  loadCache(true);
}

async function exportCache() {
  const btn = $("cacheExport");
  const prev = btn.textContent;
  const res = await window.api.exportCache("html", caReadFilters());
  if (res && res.ok) btn.textContent = "Saved ✓";
  else if (res && res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  setTimeout(() => { btn.textContent = prev; }, 2500);
}

/* --------------------------- evidence integrity --------------------------- */

const integrityState = { offset: 0, pageSize: 300, total: 0, built: false, facetsLoaded: false, selected: null };

function inReadFilters() {
  const f = {};
  const q = $("inQ").value.trim(); if (q) f.q = q;
  const ty = $("inType").value; if (ty) f.evidenceType = ty;
  const st = $("inStatus").value; if (st) f.verificationStatus = st;
  return f;
}

function inFillSelect(sel, values) {
  const first = sel.querySelector("option");
  const head = first ? first.outerHTML : `<option value="">Any</option>`;
  const cur = sel.value;
  sel.innerHTML = head + values.map((v) => `<option value="${esc(v)}">${esc(v)}</option>`).join("");
  if (cur && values.includes(cur)) sel.value = cur;
}

function inStatusPill(s) { return `<span class="st-pill ${esc(s)}">${esc(s)}</span>`; }
function inShortHash(h) { return h ? `${esc(h.slice(0, 16))}…` : "—"; }

function integrityRowHtml(r) {
  return `
    <tr class="ext-row" data-id="${esc(r.integrityId)}">
      <td>${inStatusPill(r.verificationStatus)}</td>
      <td>${esc(r.evidenceType)}</td>
      <td class="ext-name">${esc(r.label)}<div class="muted">${esc(r.evidenceId)}</div></td>
      <td class="hashcell">${inShortHash(r.sha256)}</td>
      <td class="muted">${r.verifiedAt ? fmtDateTime(r.verifiedAt) : "—"}</td>
      <td>${(r.relatedEvidenceIds || []).length}</td>
    </tr>`;
}

function integrityBindRows() {
  $("integrityRows").querySelectorAll(".ext-row").forEach((row) =>
    row.addEventListener("click", () => openIntegrity(row.dataset.id)));
}

function inRenderCards(stats) {
  const host = $("integrityCards");
  if (!host) return;
  if (!stats || !stats.built) { host.innerHTML = ""; return; }
  const st = stats.byStatus || {};
  const card = (label, val, cls) =>
    `<div class="ext-card ${cls || ""}"><div class="ext-card-num">${val || 0}</div><div class="ext-card-label">${esc(label)}</div></div>`;
  host.innerHTML =
    card("evidence", stats.total) +
    card("valid", st.VALID || 0, "VALID") +
    card("modified", st.MODIFIED || 0, "MODIFIED") +
    card("missing", st.MISSING || 0, "MISSING") +
    card("unknown", st.UNKNOWN || 0) +
    card("custody", stats.custodyCount || 0);
}

async function loadIntegrity(reset = true) {
  if (reset) {
    integrityState.offset = 0;
    $("integrityRows").innerHTML = "";
    $("integrityDetail").classList.add("hidden");
    integrityState.selected = null;
  }
  const filter = inReadFilters();
  filter.limit = integrityState.pageSize;
  filter.offset = integrityState.offset;

  const res = await window.api.integrityList(filter);
  integrityState.total = res.total || 0;
  integrityState.built = !!(res.stats && res.stats.built);

  if (res.filters && (!integrityState.facetsLoaded || reset)) {
    inFillSelect($("inType"), res.filters.evidenceTypes || []);
    integrityState.facetsLoaded = true;
  }
  inRenderCards(res.stats);

  if (!integrityState.built) {
    $("integrityRows").innerHTML = `<tr><td colspan="6" class="muted">No integrity baseline yet. Click “Verify all” to register SHA256 baselines and verify every evidence item.</td></tr>`;
    $("integrityMeta").textContent = "no baseline";
    $("integrityMore").classList.add("hidden");
    return;
  }

  const rowsHtml = res.rows.map(integrityRowHtml).join("");
  if (reset) {
    $("integrityRows").innerHTML = rowsHtml || `<tr><td colspan="6" class="muted">No evidence matches these filters.</td></tr>`;
  } else if (rowsHtml) {
    $("integrityRows").insertAdjacentHTML("beforeend", rowsHtml);
  }
  integrityBindRows();
  integrityState.offset += res.rows.length;

  const s = res.stats || {};
  $("integrityMeta").textContent =
    `${integrityState.total} evidence items · ${s.custodyCount || 0} custody events · last verified ${s.lastVerifiedAt ? fmtDateTime(s.lastVerifiedAt) : "never"}`;
  $("integrityMore").classList.toggle("hidden", integrityState.offset >= integrityState.total);
}

async function verifyAllIntegrity() {
  const btn = $("integrityVerifyAll");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Verifying…";
  const res = await window.api.integrityVerifyAll();
  btn.disabled = false; btn.textContent = prev;
  if (res && res.ok) {
    integrityState.facetsLoaded = false;
    await loadIntegrity(true);
  } else {
    $("integrityMeta").textContent = (res && res.error) || "verify failed";
  }
}

async function verifyOneIntegrity(integrityId) {
  await window.api.integrityVerify(integrityId);
  await loadIntegrity(false);
  openIntegrity(integrityId);
}

async function openIntegrity(integrityId) {
  const d = await window.api.integrityDetail(integrityId);
  const detail = $("integrityDetail");
  if (!d || !d.record) { detail.classList.add("hidden"); return; }
  const r = d.record;
  integrityState.selected = integrityId;
  $("integrityRows").querySelectorAll(".ext-row").forEach((row) =>
    row.classList.toggle("selected", row.dataset.id === integrityId));

  const baselineMatch = r.currentSha256 && r.sha256 && r.currentSha256 === r.sha256;
  const custodyRows = (d.custody || []).map((c) => `
    <tr>
      <td><span class="cust-action ${esc(c.action)}">${esc(c.action)}</span></td>
      <td class="muted">${fmtDateTime(c.ts)}</td>
      <td>${esc(c.actor)}</td>
      <td class="hashcell">${inShortHash(c.hash)}</td>
      <td class="muted">${esc(c.note || "")}</td>
    </tr>`).join("") || `<tr><td colspan="5" class="muted">No custody events.</td></tr>`;

  const relRows = (d.related || []).map((x) => `
    <tr class="in-rel-row" data-id="${esc(x.integrityId)}">
      <td>${inStatusPill(x.verificationStatus)}</td>
      <td>${esc(x.evidenceType)}</td>
      <td>${esc(x.label)}<div class="muted">${esc(x.evidenceId)}</div></td>
    </tr>`).join("") || `<tr><td colspan="3" class="muted">No related evidence.</td></tr>`;

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(r.label)} ${inStatusPill(r.verificationStatus)}</h2>
        <div class="muted">${esc(r.evidenceType)} · ${esc(r.evidenceId)}</div>
      </div>
      <button class="btn" id="inVerifyOne">Verify</button>
    </div>

    <h3 class="inv-h3">Verification</h3>
    <div class="inv-cards">
      <div class="inv-card"><div class="inv-card-label">Status</div>
        <div>${esc(r.verificationStatus)}</div>
        <div class="muted">${baselineMatch ? "current hash matches baseline" : (r.currentSha256 ? "current hash differs" : "not recomputed")}</div></div>
      <div class="inv-card"><div class="inv-card-label">Baseline SHA256</div>
        <div class="hashcell">${esc(r.sha256 || "—")}</div>
        <div class="muted">registered ${fmtDateTime(r.baselineAt || r.createdAt)}</div></div>
      <div class="inv-card"><div class="inv-card-label">Current SHA256</div>
        <div class="hashcell">${esc(r.currentSha256 || "—")}</div>
        <div class="muted">verified ${r.verifiedAt ? fmtDateTime(r.verifiedAt) : "never"}</div></div>
      <div class="inv-card"><div class="inv-card-label">Custody</div>
        <div>${r.custodyCount || 0} events</div>
        <div class="muted">last: ${esc(r.lastAction || "—")}${r.lastActor ? " · " + esc(r.lastActor) : ""}</div></div>
    </div>
    ${r.source ? `<div class="muted">source: ${esc(r.source)}</div>` : ""}

    <h3 class="inv-h3">Chain of custody <span class="muted">(${(d.custody || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Action</th><th>When</th><th>Actor</th><th>Hash</th><th>Note</th></tr>
    </thead><tbody>${custodyRows}</tbody></table>

    <h3 class="inv-h3">Related evidence <span class="muted">(${(d.related || []).length})</span></h3>
    <table class="grid"><thead>
      <tr><th>Status</th><th>Type</th><th>Evidence</th></tr>
    </thead><tbody>${relRows}</tbody></table>
  `;
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });

  const vb = $("inVerifyOne");
  if (vb) vb.addEventListener("click", () => verifyOneIntegrity(integrityId));
  detail.querySelectorAll(".in-rel-row").forEach((row) =>
    row.addEventListener("click", () => openIntegrity(row.dataset.id)));
}

function inResetFilters() {
  $("inQ").value = "";
  ["inType", "inStatus"].forEach((id) => { $(id).value = ""; });
  loadIntegrity(true);
}

async function exportIntegrity() {
  const btn = $("integrityExport");
  const prev = btn.textContent;
  const res = await window.api.exportIntegrity("html", inReadFilters());
  if (res && res.ok) btn.textContent = "Saved ✓";
  else if (res && res.error !== "Cancelled") btn.textContent = res.error || "Failed";
  setTimeout(() => { btn.textContent = prev; }, 2500);
}

/* ------------------------------ reporting --------------------------------- */

const reportState = { selected: null, facetsLoaded: false };

const REPORT_TEMPLATES = [
  { type: "executive", label: "Executive Summary", desc: "High-level findings, risk & integrity" },
  { type: "full-case", label: "Full Case Report", desc: "Everything, court-ready" },
  { type: "investigation", label: "Investigation", desc: "Evidence, domains, findings" },
  { type: "timeline", label: "Timeline", desc: "Chronological + correlations" },
  { type: "integrity", label: "Integrity", desc: "Verification & custody" },
];

function rlReadFilters() {
  const f = {};
  const q = $("rlQ").value.trim(); if (q) f.q = q;
  const ty = $("rlType").value; if (ty) f.reportType = ty;
  return f;
}

function rlFillSelect(sel, values, labels) {
  const first = sel.querySelector("option");
  const head = first ? first.outerHTML : `<option value="">Any</option>`;
  const cur = sel.value;
  sel.innerHTML = head + values.map((v) => `<option value="${esc(v)}">${esc((labels && labels[v]) || v)}</option>`).join("");
  if (cur && values.includes(cur)) sel.value = cur;
}

function rpIntegrityPill(s) {
  const o = (s && s.overall) || "UNVERIFIED";
  return `<span class="integ-pill ${esc(o)}">${esc(o)}</span>`;
}

function reportRowHtml(r) {
  return `
    <tr class="ext-row" data-id="${esc(r.reportId)}">
      <td>${esc(r.reportTypeLabel || r.reportType)}</td>
      <td class="ext-name">${esc(r.title)}<div class="muted">${esc(r.reportId)}</div></td>
      <td>${esc(r.reportScope)}</td>
      <td>${r.evidenceCount}</td>
      <td>${rpIntegrityPill(r.integrityStatus)}</td>
      <td class="muted">${fmtDateTime(r.createdAt)}</td>
    </tr>`;
}

function reportBindRows() {
  $("reportRows").querySelectorAll(".ext-row").forEach((row) =>
    row.addEventListener("click", () => openReport(row.dataset.id)));
}

function rpRenderTemplates() {
  const host = $("rpTemplates");
  if (!host) return;
  host.innerHTML = REPORT_TEMPLATES.map((t) =>
    `<button class="rtpl" data-type="${esc(t.type)}"><b>${esc(t.label)}</b><span>${esc(t.desc)}</span></button>`).join("");
  host.querySelectorAll(".rtpl").forEach((b) =>
    b.addEventListener("click", () => { $("rpType").value = b.dataset.type; createReport(); }));
}

function rpRenderCards(stats) {
  const host = $("reportCards");
  if (!host) return;
  if (!stats || !stats.total) { host.innerHTML = ""; return; }
  const bt = stats.byType || {};
  const card = (label, val, cls) =>
    `<div class="ext-card ${cls || ""}"><div class="ext-card-num">${val || 0}</div><div class="ext-card-label">${esc(label)}</div></div>`;
  host.innerHTML =
    card("reports", stats.total) +
    card("executive", bt.executive || 0) +
    card("full case", bt["full-case"] || 0) +
    card("investigation", bt.investigation || 0) +
    card("integrity", bt.integrity || 0);
}

async function loadReports(reset = true) {
  if (reset) {
    $("reportDetail").classList.add("hidden");
    reportState.selected = null;
  }
  const res = await window.api.reportList(rlReadFilters());
  const stats = res.stats || {};
  if (stats.types && (!reportState.facetsLoaded || reset)) {
    rlFillSelect($("rlType"), stats.types || [], stats.labels || {});
    reportState.facetsLoaded = true;
  }
  rpRenderCards(stats);

  const rowsHtml = (res.rows || []).map(reportRowHtml).join("");
  $("reportRows").innerHTML = rowsHtml ||
    `<tr><td colspan="6" class="muted">No reports yet. Pick a type and click “Generate report”.</td></tr>`;
  reportBindRows();
  $("reportMeta").textContent = `${res.total || 0} report${(res.total || 0) === 1 ? "" : "s"}`;
}

async function createReport() {
  const btn = $("rpCreate");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Generating…";
  const options = { reportType: $("rpType").value };
  const scopeType = $("rpScopeType").value;
  if (scopeType !== "all") {
    options.scope = { type: scopeType, value: $("rpScopeValue").value.trim() };
  } else {
    options.scope = { type: "all" };
  }
  const res = await window.api.reportCreate(options);
  btn.disabled = false; btn.textContent = prev;
  if (res && res.ok) {
    await loadReports(true);
    openReport(res.report.reportId);
  } else {
    $("reportMeta").textContent = (res && res.error) || "create failed";
  }
}

function rpRenderSection(s) {
  const d = s.data || {};
  let body = "";
  if (s.type === "cards") {
    body = `<div class="ext-cards">` + (d.items || []).map((c) =>
      `<div class="ext-card"><div class="ext-card-num">${esc(c.value)}</div><div class="ext-card-label">${esc(c.label)}</div></div>`).join("") + `</div>`;
  } else if (s.type === "keyval") {
    body = `<table class="grid"><tbody>` + (d.pairs || []).map(([k, v]) =>
      `<tr><th style="width:200px">${esc(k)}</th><td>${esc(v)}</td></tr>`).join("") + `</tbody></table>`;
  } else if (s.type === "table") {
    const head = (d.columns || []).map((c) => `<th>${esc(c)}</th>`).join("");
    const rows = (d.rows || []).map((r) => `<tr>${r.map((c) => `<td>${esc(c)}</td>`).join("")}</tr>`).join("") ||
      `<tr><td colspan="${(d.columns || []).length || 1}" class="muted">none</td></tr>`;
    body = `<table class="grid ext-table"><thead><tr>${head}</tr></thead><tbody>${rows}</tbody></table>`;
  } else if (s.type === "list") {
    body = (d.items || []).map((it) =>
      `<div class="sev-row ${esc(it.severity)}" style="padding:6px 0;border-bottom:1px solid var(--line)"><span class="sev-pill ${esc(it.severity)}">${esc(it.severity || "")}</span> <b>${esc(it.title || "")}</b>${it.meta ? ` <span class="muted">${esc(it.meta)}</span>` : ""}${it.detail ? `<div class="muted">${esc(it.detail)}</div>` : ""}</div>`).join("") ||
      `<div class="muted">none</div>`;
  } else if (s.type === "text") {
    body = `<p style="font-size:13px">${esc(d.body || "")}</p>`;
  }
  return `<div class="report-section"><h3 class="inv-h3">${esc(s.title)}</h3>${s.note ? `<div class="muted">${esc(s.note)}</div>` : ""}${body}</div>`;
}

async function openReport(reportId) {
  const r = await window.api.reportDetail(reportId);
  const detail = $("reportDetail");
  if (!r) { detail.classList.add("hidden"); return; }
  reportState.selected = reportId;
  $("reportRows").querySelectorAll(".ext-row").forEach((row) =>
    row.classList.toggle("selected", row.dataset.id === reportId));
  const integ = r.integrityStatus || {};

  detail.innerHTML = `
    <div class="inv-head">
      <div>
        <h2>${esc(r.title)} ${rpIntegrityPill(integ)}</h2>
        <div class="muted">${esc(r.reportTypeLabel || r.reportType)} · ${esc(r.reportId)} · created ${fmtDateTime(r.createdAt)} by ${esc(r.generatedBy)}</div>
      </div>
      <div class="row-controls">
        <button class="btn" id="rpExportHtml">Export HTML</button>
        <button class="btn ghost" id="rpExportJson">JSON</button>
        <button class="btn ghost" id="rpExportPdf">PDF</button>
      </div>
    </div>
    <div class="inv-cards">
      <div class="inv-card"><div class="inv-card-label">Scope</div><div>${esc(r.reportScope)}</div></div>
      <div class="inv-card"><div class="inv-card-label">Evidence count</div><div>${esc(r.evidenceCount)}</div></div>
      <div class="inv-card"><div class="inv-card-label">Integrity</div><div>${esc(integ.overall || "UNVERIFIED")}</div><div class="muted">${esc(integ.valid || 0)} valid · ${esc(integ.modified || 0)} modified · ${esc(integ.missing || 0)} missing</div></div>
      <div class="inv-card"><div class="inv-card-label">Sections</div><div>${(r.sections || []).length}</div></div>
    </div>
    ${(r.sections || []).map(rpRenderSection).join("")}
  `;
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });

  $("rpExportHtml").addEventListener("click", () => exportReport(reportId, "html"));
  $("rpExportJson").addEventListener("click", () => exportReport(reportId, "json"));
  $("rpExportPdf").addEventListener("click", () => exportReport(reportId, "pdf"));
}

async function exportReport(reportId, format) {
  const res = await window.api.exportReport(reportId, format);
  const meta = $("reportMeta");
  if (res && res.ok) meta.textContent = `exported ${format.toUpperCase()} ✓`;
  else if (res && res.error !== "Cancelled") meta.textContent = (res && res.error) || "export failed";
}

function rlResetFilters() {
  $("rlQ").value = "";
  $("rlType").value = "";
  loadReports(true);
}

/* --------------------------- threat hunting ------------------------------- */

const huntState = { scanned: false, facetsLoaded: false, selected: null };

function huReadFilters() {
  const f = {};
  const q = $("huQ").value.trim(); if (q) f.q = q;
  const h = $("huHunt").value; if (h) f.huntType = h;
  const s = $("huSeverity").value; if (s) f.severity = s;
  return f;
}

function huFillSelect(sel, values, labels) {
  const first = sel.querySelector("option");
  const head = first ? first.outerHTML : `<option value="">Any</option>`;
  const cur = sel.value;
  sel.innerHTML = head + values.map((v) => `<option value="${esc(v)}">${esc((labels && labels[v]) || v)}</option>`).join("");
  if (cur && values.includes(cur)) sel.value = cur;
}

function huSevPill(s) { return `<span class="sev-pill ${esc(s)}">${esc(s)}</span>`; }
function huPct(c) { return `${Math.round((c || 0) * 100)}%`; }

function huntChainRowHtml(c) {
  return `
    <tr class="ext-row hunt-chain" data-id="${esc(c.chainId)}">
      <td>${huSevPill(c.severity)}<div class="muted">${huPct(c.confidenceScore)}</div></td>
      <td class="ext-name">${esc(c.title)}<div class="muted">${esc((c.huntTypes || []).join(" → "))}</div></td>
      <td class="edomain">${esc(c.domain)}</td>
      <td>${(c.indicators || []).length} ind · ${(c.relatedTimelineIds || []).length} tl · ${(c.relatedExtensions || []).length} ext</td>
    </tr>`;
}

function huntFindingRowHtml(f) {
  return `
    <tr class="ext-row" data-id="${esc(f.findingId)}">
      <td>${huSevPill(f.severity)}</td>
      <td>${esc(f.huntType)}</td>
      <td class="ext-name">${esc(f.title)}<div class="muted">${esc(f.evidence)}</div></td>
      <td class="edomain">${esc((f.relatedDomains || []).slice(0, 2).join(", ") || "—")}</td>
      <td>${huPct(f.confidenceScore)}</td>
    </tr>`;
}

function huBindRows() {
  $("huntRows").querySelectorAll(".ext-row").forEach((row) =>
    row.addEventListener("click", () => openHunt(row.dataset.id)));
  $("huntChainRows").querySelectorAll(".ext-row").forEach((row) =>
    row.addEventListener("click", () => openHunt(row.dataset.id)));
}

function huRenderCards(stats) {
  const host = $("huntCards");
  if (!host) return;
  if (!stats || !stats.scanned) { host.innerHTML = ""; return; }
  const bs = stats.bySeverity || {};
  const card = (label, val, cls) =>
    `<div class="ext-card ${cls || ""}"><div class="ext-card-num">${val || 0}</div><div class="ext-card-label">${esc(label)}</div></div>`;
  host.innerHTML =
    card("findings", stats.findingCount) +
    card("critical", bs.CRITICAL || 0, "CRITICAL") +
    card("high", bs.HIGH || 0, "HIGH") +
    card("medium", bs.MEDIUM || 0, "MEDIUM") +
    card("chains", stats.chainCount) +
    card("indicators", stats.indicatorCount);
}

async function loadHunt(reset = true) {
  if (reset) {
    $("huntDetail").classList.add("hidden");
    huntState.selected = null;
  }
  const [res, chainRes] = await Promise.all([
    window.api.huntList(huReadFilters()),
    window.api.huntChains({}),
  ]);
  huntState.scanned = !!(res.stats && res.stats.scanned);

  if (res.filters && (!huntState.facetsLoaded || reset)) {
    huFillSelect($("huHunt"), res.filters.huntTypes || [], res.filters.labels || {});
    huntState.facetsLoaded = true;
  }
  huRenderCards(res.stats);

  if (!huntState.scanned) {
    $("huntRows").innerHTML = `<tr><td colspan="5" class="muted">No hunt results yet. Click “Run hunt” to hunt across all evidence sources.</td></tr>`;
    $("huntChainRows").innerHTML = `<tr><td colspan="4" class="muted">—</td></tr>`;
    $("huntMeta").textContent = "not scanned";
    return;
  }

  $("huntChainRows").innerHTML = (chainRes.rows || []).map(huntChainRowHtml).join("") ||
    `<tr><td colspan="4" class="muted">No multi-stage chains correlated.</td></tr>`;
  $("huntRows").innerHTML = (res.rows || []).map(huntFindingRowHtml).join("") ||
    `<tr><td colspan="5" class="muted">No threat findings match these filters.</td></tr>`;
  huBindRows();

  const s = res.stats || {};
  const integ = s.integrity || {};
  $("huntMeta").textContent =
    `${s.findingCount || 0} findings · ${s.chainCount || 0} chains · max ${s.maxSeverity || "INFO"} · integrity ${integ.overall || "—"} · scanned ${fmtDateTime(s.scannedAt)}`;
}

async function scanHunt() {
  const btn = $("huntScan");
  const prev = btn.textContent;
  btn.disabled = true; btn.textContent = "Hunting…";
  const res = await window.api.huntScan();
  btn.disabled = false; btn.textContent = prev;
  if (res && res.ok) {
    huntState.facetsLoaded = false;
    await loadHunt(true);
  } else {
    $("huntMeta").textContent = (res && res.error) || "hunt failed";
  }
}

async function openHunt(id) {
  const d = await window.api.huntDetail(id);
  const detail = $("huntDetail");
  if (!d) { detail.classList.add("hidden"); return; }
  huntState.selected = id;
  document.querySelectorAll("#huntRows .ext-row, #huntChainRows .ext-row").forEach((r) =>
    r.classList.toggle("selected", r.dataset.id === id));

  if (d.kind === "chain") {
    const c = d.chain;
    const indRows = (c.indicators || []).map((i) => `
      <tr><td>${huSevPill(i.severity)}</td><td>${esc(i.huntType)}</td><td>${esc(i.type)}</td><td>${esc(i.evidence)}</td><td class="muted">${fmtDateTime(i.ts)}</td></tr>`).join("") ||
      `<tr><td colspan="5" class="muted">none</td></tr>`;
    const fRows = (d.findings || []).map((f) => `
      <tr class="hunt-fnd-row" data-id="${esc(f.findingId)}"><td>${huSevPill(f.severity)}</td><td>${esc(f.huntType)}</td><td>${esc(f.title)}</td><td>${huPct(f.confidenceScore)}</td></tr>`).join("") ||
      `<tr><td colspan="4" class="muted">none</td></tr>`;
    detail.innerHTML = `
      <div class="inv-head"><div>
        <h2>${esc(c.title)} ${huSevPill(c.severity)}</h2>
        <div class="muted">multi-stage chain · ${esc(c.chainId)} · confidence ${huPct(c.confidenceScore)}</div>
      </div></div>
      <div class="inv-cards">
        <div class="inv-card"><div class="inv-card-label">Stages</div><div>${(c.huntTypes || []).length}</div><div class="muted">${esc((c.huntTypes || []).join(", "))}</div></div>
        <div class="inv-card"><div class="inv-card-label">Window</div><div>${fmtDateTime(c.startTs)}</div><div class="muted">→ ${fmtDateTime(c.endTs)}</div></div>
        <div class="inv-card"><div class="inv-card-label">Correlation</div><div>${(c.relatedTimelineIds || []).length} timeline</div><div class="muted">${(c.relatedFindingIds || []).length} findings · ${(c.relatedExtensions || []).length} ext</div></div>
        <div class="inv-card"><div class="inv-card-label">Domain</div><div class="edomain">${esc(c.domain)}</div></div>
      </div>
      <h3 class="inv-h3">Indicators <span class="muted">(${(c.indicators || []).length})</span></h3>
      <table class="grid ext-table"><thead><tr><th>Severity</th><th>Hunt</th><th>Type</th><th>Evidence</th><th>When</th></tr></thead><tbody>${indRows}</tbody></table>
      <h3 class="inv-h3">Member findings <span class="muted">(${(d.findings || []).length})</span></h3>
      <table class="grid"><thead><tr><th>Severity</th><th>Hunt</th><th>Finding</th><th>Confidence</th></tr></thead><tbody>${fRows}</tbody></table>
    `;
    detail.querySelectorAll(".hunt-fnd-row").forEach((r) =>
      r.addEventListener("click", () => openHunt(r.dataset.id)));
  } else {
    const f = d.finding;
    const chainRows = (d.chains || []).map((c) => `
      <tr class="hunt-chain-row" data-id="${esc(c.chainId)}"><td>${huSevPill(c.severity)}</td><td>${esc(c.title)}</td><td>${huPct(c.confidenceScore)}</td></tr>`).join("") ||
      `<tr><td colspan="3" class="muted">not part of a multi-stage chain</td></tr>`;
    detail.innerHTML = `
      <div class="inv-head"><div>
        <h2>${esc(f.title)} ${huSevPill(f.severity)}</h2>
        <div class="muted">${esc(f.huntType)} · ${esc(f.findingId)} · confidence ${huPct(f.confidenceScore)}</div>
      </div></div>
      <div class="inv-cards">
        <div class="inv-card"><div class="inv-card-label">Evidence</div><div style="font-size:13px">${esc(f.evidence)}</div></div>
        <div class="inv-card"><div class="inv-card-label">Recommendation</div><div style="font-size:13px">${esc(f.recommendation)}</div></div>
        <div class="inv-card"><div class="inv-card-label">When</div><div>${fmtDateTime(f.ts)}</div></div>
        <div class="inv-card"><div class="inv-card-label">Correlation</div><div>${(f.relatedTimelineIds || []).length} timeline</div><div class="muted">${(f.relatedExtensions || []).length} ext · ${(f.relatedFindingIds || []).length} find</div></div>
      </div>
      <div class="hunt-tags">${(f.relatedDomains || []).map((dm) => `<span class="tag clickable" data-domain="${esc(dm)}">${esc(dm)}</span>`).join(" ") || `<span class="muted">no domains</span>`}</div>
      <h3 class="inv-h3">Part of chains <span class="muted">(${(d.chains || []).length})</span></h3>
      <table class="grid"><thead><tr><th>Severity</th><th>Chain</th><th>Confidence</th></tr></thead><tbody>${chainRows}</tbody></table>
    `;
    detail.querySelectorAll(".tag.clickable").forEach((el) =>
      el.addEventListener("click", () => renderInvestigation(el.dataset.domain)));
    detail.querySelectorAll(".hunt-chain-row").forEach((r) =>
      r.addEventListener("click", () => openHunt(r.dataset.id)));
  }
  detail.classList.remove("hidden");
  detail.scrollIntoView({ behavior: "smooth", block: "start" });
}

function huResetFilters() {
  $("huQ").value = "";
  ["huHunt", "huSeverity"].forEach((id) => { $(id).value = ""; });
  loadHunt(true);
}

async function exportHunt(format) {
  const res = await window.api.exportHunt(format, huReadFilters());
  const meta = $("huntMeta");
  if (res && res.ok) meta.textContent = `exported ${format.toUpperCase()} ✓`;
  else if (res && res.error !== "Cancelled") meta.textContent = (res && res.error) || "export failed";
}

/* ----------------------------- clear-data modal --------------------------- */

function openClearModal() {
  $("scopeEvents").checked = false;
  $("scopeAcq").checked = false;
  $("clearModal").classList.remove("hidden");
}

async function confirmClear() {
  const events = $("scopeEvents").checked;
  const acquisitions = $("scopeAcq").checked;
  if (!events && !acquisitions) { $("clearModal").classList.add("hidden"); return; }
  const done = await window.api.clearScope({ events, acquisitions });
  $("clearModal").classList.add("hidden");

  if (done.events) {
    $("liveFeed").innerHTML = "";
    $("historyFeed").innerHTML = "";
    $("searchFeed").innerHTML = "";
    $("investigationPanel").innerHTML = `<div class="muted">Select an event or domain to investigate.</div>`;
    if ($("sessionRows")) $("sessionRows").innerHTML = "";
    if ($("sessionDetail")) $("sessionDetail").classList.add("hidden");
    if ($("findingRows")) $("findingRows").innerHTML = "";
    if ($("findingDetail")) $("findingDetail").classList.add("hidden");
    if ($("graphSvg")) $("graphSvg").innerHTML = "";
    if ($("graphPanel")) $("graphPanel").classList.add("hidden");
    graphState.pos.clear(); graphState.focus = null; graphState.selected = null;
    await refreshKpis();
  }
  if (done.acquisitions) {
    if ($("acqRows")) await renderAcqRuns();
    if ($("acqDetail")) $("acqDetail").classList.add("hidden");
  }
  const active = document.querySelector(".tab.active");
  if (active) switchTab(active.dataset.tab);
}

function switchTab(name) {
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.tab === name));
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("active", v.id === `view-${name}`));
  if (name === "history") loadHistory(true);
  if (name === "cookies") loadCookies();
  if (name === "domains") loadDomains();
  if (name === "sessions") loadSessions();
  if (name === "findings") loadFindings();
  if (name === "timeline") loadTimeline(true);
  if (name === "extensions") loadExtensions(true);
  if (name === "cache") loadCache(true);
  if (name === "integrity") loadIntegrity(true);
  if (name === "reports") { rpRenderTemplates(); loadReports(true); }
  if (name === "hunting") loadHunt(true);
  if (name === "graph") { initGraph(); loadGraph(); }
  if (name === "cases") loadCases();
  if (name === "acquire") loadAcquire();
}

function wire() {
  $("tabs").addEventListener("click", (e) => {
    if (e.target.dataset.tab) switchTab(e.target.dataset.tab);
  });
  $("pauseLive").addEventListener("change", (e) => { state.paused = e.target.checked; });
  $("liveRisk").addEventListener("change", (e) => { state.liveRiskMin = e.target.value; seedLive(); });
  $("historyMore").addEventListener("click", () => loadHistory(false));
  $("runSearch").addEventListener("click", runSearch);
  $("fQ").addEventListener("keydown", (e) => { if (e.key === "Enter") runSearch(); });

  $("saveCase").addEventListener("click", () => {
    const f = readFilters();
    const scope = Object.entries(f).filter(([, v]) => v).map(([k, v]) => `${k}: ${v}`).join(" · ") || "all activity";
    openCaseModal(f, `Scope: ${scope}`);
  });
  $("newCase").addEventListener("click", () => {
    const since = Date.now() - 24 * 3600 * 1000;
    openCaseModal({ since }, "Scope: all activity in the last 24 hours");
  });
  $("caseCancel").addEventListener("click", () => $("caseModal").classList.add("hidden"));
  $("caseConfirm").addEventListener("click", confirmCase);

  $("clearData").addEventListener("click", openClearModal);
  $("clearCancel").addEventListener("click", () => $("clearModal").classList.add("hidden"));
  $("clearConfirm").addEventListener("click", confirmClear);

  $("acqDiscover").addEventListener("click", discoverBrowsers);
  $("acqRun").addEventListener("click", runAcquisition);

  $("timelineBuild").addEventListener("click", buildTimeline);
  $("timelineExport").addEventListener("click", exportTimeline);
  $("tlApply").addEventListener("click", () => loadTimeline(true));
  $("tlReset").addEventListener("click", tlResetFilters);
  $("timelineMore").addEventListener("click", () => loadTimeline(false));
  $("tlQ").addEventListener("keydown", (e) => { if (e.key === "Enter") loadTimeline(true); });
  $("tlDomain").addEventListener("keydown", (e) => { if (e.key === "Enter") loadTimeline(true); });
  ["tlSource", "tlArtifact", "tlSeverity", "tlBrowser", "tlProfile"].forEach((id) =>
    $(id).addEventListener("change", () => loadTimeline(true)));
  $("tlCorrelated").addEventListener("change", () => loadTimeline(true));

  $("extScan").addEventListener("click", scanExtensions);
  $("extExport").addEventListener("click", exportExtensions);
  $("exApply").addEventListener("click", () => loadExtensions(true));
  $("exReset").addEventListener("click", exResetFilters);
  $("exQ").addEventListener("keydown", (e) => { if (e.key === "Enter") loadExtensions(true); });
  ["exRisk", "exBrowser", "exState"].forEach((id) =>
    $(id).addEventListener("change", () => loadExtensions(true)));
  $("exCorrelated").addEventListener("change", () => loadExtensions(true));

  $("cacheScan").addEventListener("click", scanCache);
  $("cacheExport").addEventListener("click", exportCache);
  $("caApply").addEventListener("click", () => loadCache(true));
  $("caReset").addEventListener("click", caResetFilters);
  $("cacheMore").addEventListener("click", () => loadCache(false));
  $("caQ").addEventListener("keydown", (e) => { if (e.key === "Enter") loadCache(true); });
  ["caRisk", "caType", "caBrowser"].forEach((id) =>
    $(id).addEventListener("change", () => loadCache(true)));
  $("caCorrelated").addEventListener("change", () => loadCache(true));

  $("integrityVerifyAll").addEventListener("click", verifyAllIntegrity);
  $("integrityExport").addEventListener("click", exportIntegrity);
  $("inApply").addEventListener("click", () => loadIntegrity(true));
  $("inReset").addEventListener("click", inResetFilters);
  $("integrityMore").addEventListener("click", () => loadIntegrity(false));
  $("inQ").addEventListener("keydown", (e) => { if (e.key === "Enter") loadIntegrity(true); });
  ["inType", "inStatus"].forEach((id) =>
    $(id).addEventListener("change", () => loadIntegrity(true)));

  $("rpCreate").addEventListener("click", createReport);
  $("rpScopeType").addEventListener("change", () => {
    $("rpScopeValue").classList.toggle("hidden", $("rpScopeType").value === "all");
  });
  $("rlApply").addEventListener("click", () => loadReports(true));
  $("rlReset").addEventListener("click", rlResetFilters);
  $("rlQ").addEventListener("keydown", (e) => { if (e.key === "Enter") loadReports(true); });
  $("rlType").addEventListener("change", () => loadReports(true));

  $("huntScan").addEventListener("click", scanHunt);
  $("huntExportHtml").addEventListener("click", () => exportHunt("html"));
  $("huntExportJson").addEventListener("click", () => exportHunt("json"));
  $("huntExportPdf").addEventListener("click", () => exportHunt("pdf"));
  $("huApply").addEventListener("click", () => loadHunt(true));
  $("huReset").addEventListener("click", huResetFilters);
  $("huQ").addEventListener("keydown", (e) => { if (e.key === "Enter") loadHunt(true); });
  ["huHunt", "huSeverity"].forEach((id) =>
    $(id).addEventListener("change", () => loadHunt(true)));

  $("findingSeverity").addEventListener("change", loadFindings);
  $("runDetection").addEventListener("click", async () => {
    const btn = $("runDetection");
    btn.textContent = "Scanning…";
    await window.api.runDetection();
    btn.textContent = "Re-scan";
    await loadFindings();
  });
  $("exportAllFindings").addEventListener("click", async () => {
    const btn = $("exportAllFindings");
    const res = await window.api.exportFindings({ scope: "all" });
    if (res.ok) btn.textContent = "Saved ✓"; else if (res.error !== "Cancelled") btn.textContent = res.error || "Failed";
    setTimeout(() => { btn.textContent = "Export all"; }, 2500);
  });
  $("exportSevFindings").addEventListener("click", async () => {
    const severity = $("findingSeverity").value;
    if (!severity) { alert("Pick a severity to export."); return; }
    const btn = $("exportSevFindings");
    const res = await window.api.exportFindings({ scope: "severity", severity });
    if (res.ok) btn.textContent = "Saved ✓"; else if (res.error !== "Cancelled") btn.textContent = res.error || "Failed";
    setTimeout(() => { btn.textContent = "Export severity"; }, 2500);
  });

  window.api.onEvent((e) => {
    pushLive(e);
    refreshKpis();
  });

  window.api.onFindings(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "findings") loadFindings();
  });

  let graphRefreshTimer = null;
  window.api.onGraph(() => {
    const active = document.querySelector(".tab.active");
    if (!active || active.dataset.tab !== "graph") return;
    if (graphRefreshTimer) return;
    graphRefreshTimer = setTimeout(() => { graphRefreshTimer = null; loadGraph(); }, 3000);
  });

  window.api.onAcq(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "acquire") renderAcqRuns();
  });

  window.api.onTimeline(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "timeline") loadTimeline(true);
  });

  window.api.onExtensions(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "extensions") loadExtensions(true);
  });

  window.api.onCache(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "cache") loadCache(true);
  });

  window.api.onIntegrity(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "integrity") loadIntegrity(true);
  });

  window.api.onReports(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "reports") loadReports(true);
  });

  window.api.onHunt(() => {
    const active = document.querySelector(".tab.active");
    if (active && active.dataset.tab === "hunting") loadHunt(true);
  });
}

async function init() {
  const meta = await window.api.meta();
  $("backendTag").textContent = meta.backend === "sqlite" ? "sqlite · local" : "jsonl · local";
  wire();
  await refreshKpis();
  await seedLive();
}

init();
