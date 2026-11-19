// browsers.js
// Browser discovery + on-disk location maps for read-only forensic acquisition.
//
// This module is pure location/metadata logic. It knows:
//   - where each supported browser keeps its user data, per OS,
//   - how to enumerate the profiles inside a user-data directory,
//   - how to read the installed browser version (and where that came from),
//   - the per-family artifact "plan": which file(s) back each artifact type and
//     which reader in acquire.js should parse them.
//
// It performs NO writes and opens NO databases. It only stats/reads small text
// or JSON marker files (Local State, Last Version, profiles.ini, compatibility.ini)
// to discover what exists. All heavy reading/hashing lives in acquire.js.
//
// Supported browsers: Chrome, Edge, Brave, Opera (Chromium family) and
// Firefox (Gecko family).

const fs = require("fs");
const path = require("path");
const os = require("os");

const CHROMIUM = "chromium";
const GECKO = "gecko";

/* ----------------------------- location tables ---------------------------- */
// Each entry resolves a user-data root from { home, env, platform }.
// For Chromium browsers this is the "User Data" directory that contains the
// profile sub-directories. For Opera the resolved directory IS a profile root.
// For Firefox this is the directory that contains profiles.ini + Profiles/.

function envPath(env, name, fallback) {
  const v = env && env[name];
  return v && String(v).trim() ? v : fallback;
}

const BROWSERS = [
  {
    id: "chrome",
    name: "Google Chrome",
    family: CHROMIUM,
    userDataDir({ home, env, platform }) {
      if (platform === "win32") {
        return path.join(envPath(env, "LOCALAPPDATA", path.join(home, "AppData", "Local")), "Google", "Chrome", "User Data");
      }
      if (platform === "darwin") {
        return path.join(home, "Library", "Application Support", "Google", "Chrome");
      }
      return path.join(home, ".config", "google-chrome");
    },
  },
  {
    id: "edge",
    name: "Microsoft Edge",
    family: CHROMIUM,
    userDataDir({ home, env, platform }) {
      if (platform === "win32") {
        return path.join(envPath(env, "LOCALAPPDATA", path.join(home, "AppData", "Local")), "Microsoft", "Edge", "User Data");
      }
      if (platform === "darwin") {
        return path.join(home, "Library", "Application Support", "Microsoft Edge");
      }
      return path.join(home, ".config", "microsoft-edge");
    },
  },
  {
    id: "brave",
    name: "Brave",
    family: CHROMIUM,
    userDataDir({ home, env, platform }) {
      if (platform === "win32") {
        return path.join(envPath(env, "LOCALAPPDATA", path.join(home, "AppData", "Local")), "BraveSoftware", "Brave-Browser", "User Data");
      }
      if (platform === "darwin") {
        return path.join(home, "Library", "Application Support", "BraveSoftware", "Brave-Browser");
      }
      return path.join(home, ".config", "BraveSoftware", "Brave-Browser");
    },
  },
  {
    id: "opera",
    name: "Opera",
    family: CHROMIUM,
    // Opera Stable's data directory is itself the default profile root.
    userDataDir({ home, env, platform }) {
      if (platform === "win32") {
        return path.join(envPath(env, "APPDATA", path.join(home, "AppData", "Roaming")), "Opera Software", "Opera Stable");
      }
      if (platform === "darwin") {
        return path.join(home, "Library", "Application Support", "com.operasoftware.Opera");
      }
      return path.join(home, ".config", "opera");
    },
  },
  {
    id: "firefox",
    name: "Mozilla Firefox",
    family: GECKO,
    userDataDir({ home, env, platform }) {
      if (platform === "win32") {
        return path.join(envPath(env, "APPDATA", path.join(home, "AppData", "Roaming")), "Mozilla", "Firefox");
      }
      if (platform === "darwin") {
        return path.join(home, "Library", "Application Support", "Firefox");
      }
      return path.join(home, ".mozilla", "firefox");
    },
  },
];

function byId(id) {
  return BROWSERS.find((b) => b.id === id) || null;
}

/* ------------------------------ small helpers ----------------------------- */

function existsDir(p) {
  try { return fs.statSync(p).isDirectory(); } catch { return false; }
}
function existsFile(p) {
  try { return fs.statSync(p).isFile(); } catch { return false; }
}
function readJsonSafe(p) {
  try { return JSON.parse(fs.readFileSync(p, "utf8")); } catch { return null; }
}
function readTextSafe(p) {
  try { return fs.readFileSync(p, "utf8"); } catch { return null; }
}

/* --------------------------- profile enumeration -------------------------- */

// Chromium: a profile is any sub-directory containing a "Preferences" file.
// The user-data directory itself can also be a profile (Opera Stable). The
// "Local State" file may carry friendly names in profile.info_cache.
function chromiumProfiles(userDataDir) {
  const out = [];
  if (!existsDir(userDataDir)) return out;

  const localState = readJsonSafe(path.join(userDataDir, "Local State"));
  const friendly = {};
  const cache = localState && localState.profile && localState.profile.info_cache;
  if (cache && typeof cache === "object") {
    for (const [dir, info] of Object.entries(cache)) {
      if (info && info.name) friendly[dir] = info.name;
    }
  }

  const skip = new Set(["System Profile"]);
  let entries = [];
  try { entries = fs.readdirSync(userDataDir, { withFileTypes: true }); } catch { entries = []; }

  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    if (skip.has(ent.name)) continue;
    const dir = path.join(userDataDir, ent.name);
    if (existsFile(path.join(dir, "Preferences"))) {
      out.push({ profile: friendly[ent.name] || ent.name, profilePath: dir });
    }
  }

  // Opera-style: the user-data dir is itself a single profile.
  if (existsFile(path.join(userDataDir, "Preferences"))) {
    out.push({ profile: path.basename(userDataDir), profilePath: userDataDir });
  }

  // De-dupe by path.
  const seen = new Set();
  return out.filter((p) => (seen.has(p.profilePath) ? false : (seen.add(p.profilePath), true)));
}

// Firefox: parse profiles.ini if present, else scan the Profiles/ directory.
function firefoxProfiles(rootDir) {
  const out = [];
  if (!existsDir(rootDir)) return out;

  const iniText = readTextSafe(path.join(rootDir, "profiles.ini"));
  if (iniText) {
    let cur = null;
    for (const rawLine of iniText.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (/^\[Profile/i.test(line)) {
        if (cur && cur.path) out.push(cur);
        cur = { name: "", path: "", isRelative: true };
      } else if (cur) {
        const m = line.match(/^([^=]+)=(.*)$/);
        if (!m) continue;
        const key = m[1].trim().toLowerCase();
        const val = m[2].trim();
        if (key === "name") cur.name = val;
        else if (key === "path") cur.path = val;
        else if (key === "isrelative") cur.isRelative = val === "1";
      }
    }
    if (cur && cur.path) out.push(cur);
  }

  const resolved = out.map((p) => {
    const abs = p.isRelative ? path.join(rootDir, p.path) : p.path;
    return { profile: p.name || path.basename(abs), profilePath: abs };
  }).filter((p) => existsDir(p.profilePath));

  if (resolved.length) return resolved;

  // Fallback: scan Profiles/ for *.default* style directories.
  const profilesDir = path.join(rootDir, "Profiles");
  const scanDir = existsDir(profilesDir) ? profilesDir : rootDir;
  let entries = [];
  try { entries = fs.readdirSync(scanDir, { withFileTypes: true }); } catch { entries = []; }
  for (const ent of entries) {
    if (!ent.isDirectory()) continue;
    const dir = path.join(scanDir, ent.name);
    if (existsFile(path.join(dir, "prefs.js")) || existsFile(path.join(dir, "places.sqlite"))) {
      resolved.push({ profile: ent.name, profilePath: dir });
    }
  }
  return resolved;
}

function profilesFor(browser, userDataDir) {
  return browser.family === GECKO ? firefoxProfiles(userDataDir) : chromiumProfiles(userDataDir);
}

/* ----------------------------- version reading ---------------------------- */
// Returns { version, versionSource }. Read-only; never throws.

function detectVersion(browser, ctx, userDataDir, profilePath) {
  if (browser.family === CHROMIUM) {
    // 1) "Last Version" marker file in the user-data dir.
    const lv = readTextSafe(path.join(userDataDir, "Last Version"));
    if (lv && lv.trim()) return { version: lv.trim(), versionSource: "last_version_file" };

    // 2) Local State: variations_permanent_consistency_country / not reliable;
    //    but some channels persist "last_chrome_version" under "browser".
    const ls = readJsonSafe(path.join(userDataDir, "Local State"));
    const lsVer = ls && ls.browser && (ls.browser.last_chrome_version || ls.browser.last_version);
    if (lsVer) return { version: String(lsVer), versionSource: "local_state" };

    return { version: "", versionSource: "unknown" };
  }

  // Firefox: compatibility.ini in the profile carries LastVersion.
  const compat = readTextSafe(path.join(profilePath, "compatibility.ini"));
  if (compat) {
    const m = compat.match(/^LastVersion=([^_\r\n]+)/m);
    if (m) return { version: m[1].trim(), versionSource: "compatibility.ini" };
  }
  return { version: "", versionSource: "unknown" };
}

/* ------------------------------ artifact plan ----------------------------- */
// For a given family + profile path, expand the concrete list of artifact jobs.
// Each job: { artifactType, reader, candidates:[absPaths], pick }.
//   pick "first"  -> reader uses the first existing candidate (variant paths)
//   pick "all"    -> reader inventories every candidate that exists (dirs/loose files)
// The reader tag is dispatched in acquire.js. profilePath is also handed to
// readers that need sibling files (e.g. extensions need Preferences).

const ARTIFACT_TYPES = [
  "history", "downloads", "cookies", "bookmarks", "extensions", "logins",
  "localStorage", "indexedDB", "favicons", "topsites", "preferences",
  "sessions", "serviceWorkers",
];

function j(profilePath, artifactType, reader, rel, pick = "first") {
  const list = Array.isArray(rel) ? rel : [rel];
  return {
    artifactType,
    reader,
    pick,
    candidates: list.map((r) => path.join(profilePath, ...String(r).split("/"))),
  };
}

function chromiumJobs(profilePath) {
  return [
    j(profilePath, "history", "chromium_history", "History"),
    j(profilePath, "downloads", "chromium_downloads", "History"),
    j(profilePath, "cookies", "chromium_cookies", ["Network/Cookies", "Cookies"]),
    j(profilePath, "bookmarks", "chromium_bookmarks", "Bookmarks"),
    j(profilePath, "extensions", "chromium_extensions", "Extensions"),
    j(profilePath, "logins", "chromium_logins", ["Login Data", "Login Data For Account"]),
    j(profilePath, "localStorage", "inventory", "Local Storage/leveldb", "all"),
    j(profilePath, "indexedDB", "chromium_indexeddb", "IndexedDB", "all"),
    j(profilePath, "favicons", "chromium_favicons", "Favicons"),
    j(profilePath, "topsites", "chromium_topsites", "Top Sites"),
    j(profilePath, "preferences", "chromium_preferences", ["Preferences", "Secure Preferences"]),
    j(profilePath, "sessions", "inventory", ["Sessions", "Current Session", "Current Tabs", "Last Session", "Last Tabs"], "all"),
    j(profilePath, "serviceWorkers", "chromium_serviceworkers", "Service Worker"),
  ];
}

function firefoxJobs(profilePath) {
  return [
    j(profilePath, "history", "firefox_history", "places.sqlite"),
    j(profilePath, "downloads", "firefox_downloads", "places.sqlite"),
    j(profilePath, "cookies", "firefox_cookies", "cookies.sqlite"),
    j(profilePath, "bookmarks", "firefox_bookmarks", "places.sqlite"),
    j(profilePath, "extensions", "firefox_extensions", ["extensions.json", "addons.json"]),
    j(profilePath, "logins", "firefox_logins", "logins.json"),
    j(profilePath, "localStorage", "firefox_localstorage", ["webappsstore.sqlite", "storage/default"]),
    j(profilePath, "indexedDB", "firefox_indexeddb", "storage/default", "all"),
    j(profilePath, "favicons", "firefox_favicons", "favicons.sqlite"),
    j(profilePath, "topsites", "unsupported", "places.sqlite"),
    j(profilePath, "preferences", "firefox_prefs", ["prefs.js", "user.js"]),
    j(profilePath, "sessions", "inventory", ["sessionstore.jsonlz4", "sessionstore-backups"], "all"),
    j(profilePath, "serviceWorkers", "firefox_serviceworkers", "serviceworker.txt"),
  ];
}

function artifactJobs(family, profilePath) {
  return family === GECKO ? firefoxJobs(profilePath) : chromiumJobs(profilePath);
}

/* -------------------------------- discovery ------------------------------- */
// Enumerate installed browsers and their profiles on this host. Never throws;
// missing browsers simply do not appear. ctx defaults to the live machine.

function discover(ctx = {}) {
  const platform = ctx.platform || process.platform;
  const home = ctx.home || os.homedir();
  const env = ctx.env || process.env;
  const context = { home, env, platform };

  const found = [];
  for (const b of BROWSERS) {
    let userDataDir;
    try { userDataDir = b.userDataDir(context); } catch { continue; }
    if (!existsDir(userDataDir)) continue;

    const profiles = profilesFor(b, userDataDir).map((p) => {
      const ver = detectVersion(b, context, userDataDir, p.profilePath);
      return {
        profile: p.profile,
        profilePath: p.profilePath,
        browserVersion: ver.version,
        versionSource: ver.versionSource,
      };
    });

    if (!profiles.length) continue;
    found.push({
      id: b.id,
      name: b.name,
      family: b.family,
      userDataDir,
      profiles,
    });
  }
  return { platform, host: ctx.host || os.hostname(), browsers: found };
}

// Resolve a single { browserId, profilePath } into the full descriptor an
// acquisition needs, including version (re-read at acquisition time).
function resolveTarget(browserId, profilePath, ctx = {}) {
  const b = byId(browserId);
  if (!b) return null;
  const platform = ctx.platform || process.platform;
  const home = ctx.home || os.homedir();
  const env = ctx.env || process.env;
  const context = { home, env, platform };

  let userDataDir;
  try { userDataDir = b.userDataDir(context); } catch { userDataDir = ""; }

  const ver = detectVersion(b, context, userDataDir, profilePath);
  return {
    browser: b.id,
    name: b.name,
    browserFamily: b.family,
    userDataDir,
    profilePath,
    profile: path.basename(profilePath),
    browserVersion: ver.version,
    versionSource: ver.versionSource,
    platform,
    host: ctx.host || os.hostname(),
    jobs: artifactJobs(b.family, profilePath),
  };
}

module.exports = {
  CHROMIUM,
  GECKO,
  BROWSERS,
  ARTIFACT_TYPES,
  byId,
  discover,
  resolveTarget,
  artifactJobs,
  detectVersion,
  // exported for testing
  chromiumProfiles,
  firefoxProfiles,
};
