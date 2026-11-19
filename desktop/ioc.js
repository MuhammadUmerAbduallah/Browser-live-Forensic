// ioc.js
// Local Indicator-of-Compromise database. Pure, dependency-free (uses risk.js
// only for seed lists and host helpers). Holds four expandable categories:
//   - suspiciousTlds        (e.g. ".tk", ".zip")
//   - suspiciousDomains     (operator-supplied known-bad domains)
//   - trackingDomains       (ad / analytics / tracker substrings)
//   - executableExtensions  (download payload extensions)
//
// Everything is local. No network. The database can be seeded from a persisted
// snapshot and extended at runtime via add()/remove(); snapshot() returns a
// plain object suitable for writing back to disk.

const risk = require("./risk");

const DEFAULT_EXECUTABLE_EXTS = [
  "exe", "msi", "bat", "cmd", "scr", "ps1", "jar", "dmg", "sh", "apk", "deb", "vbs",
];

// A small starter set of domains commonly abused for delivery / C2-style hosting.
// Intentionally conservative; operators expand this list over time.
const DEFAULT_SUSPICIOUS_DOMAINS = [];

const CATEGORIES = ["suspiciousTlds", "suspiciousDomains", "trackingDomains", "executableExtensions"];

function toSet(arr) { return new Set((arr || []).map((s) => String(s).toLowerCase())); }

function createIoc(seed = {}) {
  const db = {
    suspiciousTlds: toSet([...(risk.SUSPICIOUS_TLDS || []), ...(seed.suspiciousTlds || [])]),
    suspiciousDomains: toSet([...DEFAULT_SUSPICIOUS_DOMAINS, ...(seed.suspiciousDomains || [])]),
    trackingDomains: toSet([...(risk.TRACKER_SUBSTRINGS || []), ...(seed.trackingDomains || [])]),
    executableExtensions: toSet([...DEFAULT_EXECUTABLE_EXTS, ...(seed.executableExtensions || [])]),
  };

  const lc = (s) => String(s || "").toLowerCase();

  function isSuspiciousTld(domain) {
    const d = lc(domain);
    for (const t of db.suspiciousTlds) if (d.endsWith(t)) return true;
    return false;
  }

  function isSuspiciousDomain(domain) {
    const d = lc(domain);
    if (!d) return false;
    for (const bad of db.suspiciousDomains) if (d === bad || d.endsWith("." + bad) || d.includes(bad)) return true;
    return false;
  }

  function isTracker(domainOrUrl) {
    const d = lc(domainOrUrl);
    if (!d) return false;
    if (risk.isTracker(d)) return true;
    for (const t of db.trackingDomains) if (d.includes(t)) return true;
    return false;
  }

  // True for any captured event that represents tracker / analytics contact.
  function isTrackerEvent(e) {
    if (!e) return false;
    const url = (e.raw && e.raw.requestUrl) || e.url || "";
    return e.type === "tracker" ||
      (e.raw && e.raw.trackerDetected) ||
      isTracker(e.domain) || isTracker(url) || risk.isAnalytics(url);
  }

  function isExecutable(nameOrUrl) {
    const s = lc(nameOrUrl);
    if (!s) return false;
    const m = s.match(/\.([a-z0-9]+)(?:\?|#|$)/);
    if (m && db.executableExtensions.has(m[1])) return true;
    return risk.EXECUTABLE_RE ? risk.EXECUTABLE_RE.test(s) : false;
  }

  // Return the list of IOC categories a domain matches.
  function matchDomain(domain) {
    const hits = [];
    if (isTracker(domain)) hits.push("trackingDomains");
    if (isSuspiciousTld(domain)) hits.push("suspiciousTlds");
    if (isSuspiciousDomain(domain)) hits.push("suspiciousDomains");
    return hits;
  }

  function add(category, value) {
    if (!CATEGORIES.includes(category)) throw new Error(`Unknown IOC category: ${category}`);
    const v = lc(value).trim();
    if (!v) return false;
    if (db[category].has(v)) return false;
    db[category].add(v);
    return true;
  }

  function remove(category, value) {
    if (!CATEGORIES.includes(category)) return false;
    return db[category].delete(lc(value).trim());
  }

  function snapshot() {
    return {
      suspiciousTlds: [...db.suspiciousTlds],
      suspiciousDomains: [...db.suspiciousDomains],
      trackingDomains: [...db.trackingDomains],
      executableExtensions: [...db.executableExtensions],
    };
  }

  function counts() {
    return {
      suspiciousTlds: db.suspiciousTlds.size,
      suspiciousDomains: db.suspiciousDomains.size,
      trackingDomains: db.trackingDomains.size,
      executableExtensions: db.executableExtensions.size,
    };
  }

  return {
    isSuspiciousTld, isSuspiciousDomain, isTracker, isTrackerEvent, isExecutable,
    matchDomain, add, remove, snapshot, counts, categories: CATEGORIES,
  };
}

module.exports = { createIoc, CATEGORIES };
