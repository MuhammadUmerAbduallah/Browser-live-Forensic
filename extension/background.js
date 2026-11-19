// background.js — MV3 service worker.
// Collects browser activity and POSTs it to the local listener.
// Everything stays on this machine: the only network call is to localhost:9000.

const LISTENER = "http://localhost:9000/log";

// --- session counters shown in the popup ---
async function bump(kind) {
  const k = "counts";
  const cur = (await chrome.storage.session.get(k))[k] || { total: 0, byType: {} };
  cur.total++;
  cur.byType[kind] = (cur.byType[kind] || 0) + 1;
  cur.lastSent = Date.now();
  await chrome.storage.session.set({ [k]: cur });
}

async function sendLog(data) {
  try {
    await fetch(LISTENER, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(data),
    });
    bump(data.type);
  } catch (err) {
    // Listener not running yet — fail quietly, the user just hasn't opened the app.
  }
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
// webRequest can be very chatty, so we debounce per-domain (one event / 4s)
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
    if (Date.now() - last < DEBOUNCE_MS) return;
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
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.__bf !== true) return;
  const base = { time: now(), url: sender?.tab?.url, domain: hostOf(sender?.tab?.url || "") };
  sendLog({ ...base, ...msg.payload });
});
