// risk.js
// Pure, dependency-free risk engine + domain helpers.
// Used by the local store (db.js). No network, no state of its own.

const TRACKER_SUBSTRINGS = [
  "doubleclick", "google-analytics", "googletagmanager", "googlesyndication",
  "googleadservices", "adservice.google", "facebook.net", "fbcdn", "connect.facebook",
  "scorecardresearch", "criteo", "taboola", "outbrain", "hotjar", "segment.io",
  "segment.com", "mixpanel", "amplitude", "quantserve", "adnxs", "rubiconproject",
  "pubmatic", "casalemedia", "openx", "bidswitch", "adsrvr", "branch.io",
  "fullstory", "clarity.ms", "yandex.ru/metrika", "matomo", "newrelic",
  "sentry.io", "datadog", "snowplow", "bat.bing", "ads.linkedin", "px.ads",
];

const ANALYTICS_SUBSTRINGS = [
  "/collect", "/analytics", "/track", "/telemetry", "/beacon", "/pixel",
  "/g/collect", "/v1/track", "/i/adsct", "/gtm.js", "/gtag/js", "/event",
];

const SUSPICIOUS_TLDS = [
  ".tk", ".gq", ".ml", ".cf", ".ga", ".zip", ".mov", ".top", ".xyz",
  ".click", ".country", ".kim", ".work", ".loan", ".download",
];

const EXECUTABLE_RE = /\.(exe|msi|bat|cmd|scr|ps1|jar|dmg|sh|apk|deb|vbs)(\?|$)/i;
const SENSITIVE_PERMS = ["camera", "microphone", "geolocation", "location", "midi", "usb", "hid"];

function hostOf(value) {
  if (!value) return "";
  try {
    return new URL(value).hostname;
  } catch {
    // Maybe it's already a bare host or a cookie ".domain.com"
    return String(value).replace(/^https?:\/\//, "").split("/")[0];
  }
}

function normalizeDomain(value) {
  return hostOf(value).replace(/^\./, "").toLowerCase();
}

function matchesAny(haystack, needles) {
  const h = (haystack || "").toLowerCase();
  return needles.some((n) => h.includes(n));
}

function isTracker(domainOrUrl) {
  const d = (domainOrUrl || "").toLowerCase();
  return matchesAny(d, TRACKER_SUBSTRINGS);
}

function isAnalytics(url) {
  return matchesAny(url, ANALYTICS_SUBSTRINGS) || isTracker(url);
}

function suspiciousTld(domain) {
  const d = (domain || "").toLowerCase();
  return SUSPICIOUS_TLDS.some((t) => d.endsWith(t));
}

function levelFromScore(score) {
  if (score >= 50) return "HIGH";
  if (score >= 20) return "MEDIUM";
  return "INFO";
}

// Build a short human-readable label for an event (shown in lists/exports).
function describe(event) {
  switch (event.type) {
    case "cookie":
      return `${event.removed ? "Removed" : "Set"} cookie ${event.name || "?"} on ${event.domain || "?"}`;
    case "request":
      return `${event.method || "GET"} ${event.requestType || "request"} → ${normalizeDomain(event.requestUrl) || "?"}`;
    case "tracker":
      return `Tracker contacted: ${normalizeDomain(event.requestUrl) || event.domain || "?"}`;
    case "storage":
      return `${event.storageArea || "storage"} ${event.action || "write"} "${event.key || ""}" on ${event.domain || normalizeDomain(event.url)}`;
    case "permission":
      return `Permission requested: ${event.permission} on ${event.domain || normalizeDomain(event.url)}`;
    case "fingerprint":
      return `Fingerprinting: ${event.method || "unknown"} access on ${event.domain || normalizeDomain(event.url)}`;
    case "download":
      return `Download: ${event.filename || event.url || "?"}`;
    case "navigation":
      return `Navigated: ${event.title || event.url || "?"}`;
    case "tab":
      return `Tab: ${event.title || event.url || "?"}`;
    case "resource":
      return `Resources: CPU ${event.cpu ?? "?"}% · RAM ${event.ram ?? "?"}%`;
    default:
      return event.title || event.type || "event";
  }
}

// assess(event, context) -> { risk, score, reasons }
// context may include { count } where count = how many times this entity
// (cookie key / request domain) has been seen, including the current event.
function assess(event, context = {}) {
  const reasons = [];
  let score = 0;
  const count = context.count || 1;

  const domain =
    normalizeDomain(event.domain) ||
    normalizeDomain(event.url) ||
    normalizeDomain(event.requestUrl);

  const thirdParty = isTracker(domain) || isTracker(event.requestUrl) || isTracker(event.url);

  switch (event.type) {
    case "cookie": {
      score += Math.min(count, 12) * 3;
      if (count > 5) reasons.push(`Cookie changed ${count} times`);
      if (thirdParty) { score += 18; reasons.push("Known tracking / ad domain"); }
      if (event.removed) reasons.push("Cookie removed");
      break;
    }
    case "request": {
      if (isAnalytics(event.requestUrl)) { score += 25; reasons.push("Analytics / telemetry endpoint"); }
      if (thirdParty) { score += 22; reasons.push("Third-party tracker request"); }
      if (count > 20) { score += 18; reasons.push(`${count} requests to this domain`); }
      else if (count > 8) { score += 8; }
      if ((event.statusCode || 0) >= 400) reasons.push(`HTTP ${event.statusCode}`);
      break;
    }
    case "tracker": {
      score += 30; reasons.push("Known tracker / ad endpoint");
      if (isAnalytics(event.requestUrl)) { score += 15; reasons.push("Analytics / telemetry endpoint"); }
      if (count > 20) { score += 18; reasons.push(`${count} tracker calls to this domain`); }
      else if (count > 8) { score += 8; }
      if ((event.statusCode || 0) >= 400) reasons.push(`HTTP ${event.statusCode}`);
      break;
    }
    case "storage": {
      score += 14; reasons.push(`${event.storageArea || "Storage"} ${event.action || "write"}`);
      if (thirdParty) { score += 20; reasons.push("Third-party storage write"); }
      break;
    }
    case "permission": {
      const sensitive = SENSITIVE_PERMS.includes((event.permission || "").toLowerCase());
      score += sensitive ? 60 : 25;
      reasons.push(`Permission: ${event.permission || "unknown"}`);
      if (thirdParty) { score += 10; reasons.push("Requested by third-party context"); }
      break;
    }
    case "fingerprint": {
      score += 28; reasons.push(`Fingerprinting vector: ${event.method || "unknown"}`);
      if (thirdParty) { score += 10; reasons.push("Third-party fingerprinting context"); }
      break;
    }
    case "download": {
      score += 22; reasons.push("File download");
      if (EXECUTABLE_RE.test(event.filename || event.url || "")) {
        score += 45; reasons.push("Executable / installer download");
      }
      break;
    }
    case "navigation":
    case "tab": {
      score += 2;
      if (suspiciousTld(domain)) { score += 25; reasons.push("Suspicious top-level domain"); }
      if (thirdParty) { score += 6; }
      break;
    }
    case "resource": {
      if (Number(event.cpu) >= 80) { score += 30; reasons.push(`High CPU ${event.cpu}%`); }
      else if (Number(event.cpu) >= 60) { score += 12; }
      if (Number(event.ram) >= 85) { score += 20; reasons.push(`High memory ${event.ram}%`); }
      break;
    }
    default:
      score += 1;
  }

  if (reasons.length === 0) reasons.push("Routine activity");
  return { risk: levelFromScore(score), score, reasons };
}

module.exports = {
  assess,
  describe,
  hostOf,
  normalizeDomain,
  isTracker,
  isAnalytics,
  suspiciousTld,
  levelFromScore,
  // Seed data shared with the IOC database.
  TRACKER_SUBSTRINGS,
  ANALYTICS_SUBSTRINGS,
  SUSPICIOUS_TLDS,
  EXECUTABLE_RE,
};
