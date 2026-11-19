// background.js — MV3 service worker.
// Collects browser activity and POSTs it to the local listener.
// Everything stays on this machine: the only network call is to localhost:9000.

const LISTENER = "http://localhost:9000/log";

// Serialize read/modify/write operations so concurrent events cannot lose counts.
let statsWrite = Promise.resolve();

function recordCapture(outcome, type) {
  statsWrite = statsWrite.then(async () => {
    const { captureStats } = await chrome.storage.session.get("captureStats");
    const stats = captureStats || { delivered: 0, rejected: 0, unavailable: 0, suppressed: 0, byType: {} };
    stats[outcome]++;
    if (outcome === "delivered") {
      stats.byType[type] = (stats.byType[type] || 0) + 1;
    }
    await chrome.storage.session.set({ captureStats: stats });
  }).catch((error) => {
    console.warn("Unable to save capture statistics", error);
  });
  return statsWrite;
}

async function sendLog(data) {
  let response;
  try {
    response = await fetch(LISTENER, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(5000),
    });
  } catch {
    return recordCapture("unavailable");
  }
  return recordCapture(response.ok ? "delivered" : "rejected", data.type);
}

const now = () => new Date().toLocaleTimeString();

/* --------------------------------- tabs ----------------------------------- */
chrome.tabs.onActivated.addListener(async (info) => {
  try {
    const tab = await chrome.tabs.get(info.tabId);
    sendLog({ type: "tab", title: tab.title, url: tab.url, time: now() });
  } catch { /* tab may be gone */ }
});

/* ------------------------------ navigation -------------------------------- */
chrome.webNavigation.onCompleted.addListener((d) => {


  if (d.frameId !== 0) return; // top frame only
  sendLog({ type: "navigation", url: d.url, time: now() });
});

/* -------------------------------- cookies --------------------------------- */
chrome.cookies.onChanged.addListener((change) => {
  const c = change.cookie;
  sendLog({
    type: "cookie", name: c.name, domain: c.domain,
    removed: change.removed, cause: change.cause, time: now(),
  });
});

/* ---------------------------- network requests ---------------------------- */
// webRequest can be very chatty, so we debounce per-domain (one event / 10s)
// and only report request types that matter for forensics.
const REPORT_TYPES = new Set([
  "xmlhttprequest",
  "websocket",
  "ping"
]);

const TRACKER_DOMAINS = [

  "doubleclick.net",
  "google-analytics.com",
  "googletagmanager.com",
  "googleadservices.com",
  "facebook.net",
  "clarity.ms",
  "hotjar.com",
  "mixpanel.com",
  "segment.io"

];

const lastSeen = new Map();
const DEBOUNCE_MS = 10000;

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

chrome.webRequest.onCompleted.addListener(
  (d) => {
    if (
      d.url.startsWith("http://localhost:9000") ||
      d.url.startsWith("http://127.0.0.1:9000")
    ) {
      return;
    }
    if (!REPORT_TYPES.has(d.type)) return;

    const domain = hostOf(d.url);
    if (!domain) return;

    const initiatorHost = hostOf(d.initiator || "");
    const thirdParty = initiatorHost && initiatorHost !== domain;
    const trackerDetected = TRACKER_DOMAINS.some((t) => domain.includes(t));

    if (!trackerDetected && !thirdParty) return;

    const key = domain;
    const last = lastSeen.get(key) || 0;
    if (Date.now() - last < DEBOUNCE_MS) {
      recordCapture("suppressed");
      return;
    }
    lastSeen.set(key, Date.now());

    sendLog({
      type: trackerDetected ? "tracker" : "request",
      requestUrl: d.url,
      domain,
      requestType: d.type,
      method: d.method,
      statusCode: d.statusCode,
      initiator: d.initiator || "",
      thirdParty,
      trackerDetected,
      time: now(),
    });
  },
  { urls: ["<all_urls>"] }
);
/* -------------------------------- downloads ------------------------------- */
chrome.downloads.onCreated.addListener((item) => {
  sendLog({
    type: "download",
    url: item.finalUrl || item.url,
    filename: item.filename || "",
    domain: hostOf(item.finalUrl || item.url),
    mime: item.mime || "",
    time: now(),
  });
});

/* -------------------- relay from page-world content script ---------------- */
// content.js (MAIN world) -> relay.js (isolated) -> here.
const PAGE_FIELDS = {
  storage: ["storageArea", "action", "key"],
  permission: ["permission"],
  fingerprint: ["method"],
};

chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.__bf !== true || !sender?.tab || !msg.payload) return;
  const { type } = msg.payload;
  if (typeof type !== "string" || !Object.hasOwn(PAGE_FIELDS, type)) return;

  const url = sender.tab.url;
  const event = { type, time: now(), url, domain: hostOf(url || ""), source: "page-observation" };
  for (const field of PAGE_FIELDS[type]) {
    if (typeof msg.payload[field] === "string") event[field] = msg.payload[field];
  }
  sendLog(event);
});
