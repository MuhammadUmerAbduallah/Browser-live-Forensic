// content.js — runs in the PAGE (MAIN) world at document_start.
// Wraps a few sensitive web APIs so we can observe (never block) when a site
// writes to storage or asks for camera/mic/location/notifications.
// Every original function is still called, wrapped in try/catch, so pages
// keep working exactly as before. It cannot use chrome.* APIs (wrong world),
// so it forwards observations via window.postMessage to relay.js.

(function () {
  function report(payload) {
    try {
      window.postMessage({ __bf_relay: true, payload }, "*");
    } catch { /* ignore */ }
  }

  // ---- localStorage / sessionStorage writes ----
  function wrapStorage(storage, areaName) {
    if (!storage) return;
    try {
      const setItem = storage.setItem.bind(storage);
      const removeItem = storage.removeItem.bind(storage);
      const clear = storage.clear.bind(storage);
      storage.setItem = function (key, value) {
        report({ type: "storage", storageArea: areaName, action: "set", key: String(key) });
        return setItem(key, value);
      };
      storage.removeItem = function (key) {
        report({ type: "storage", storageArea: areaName, action: "remove", key: String(key) });
        return removeItem(key);
      };
      storage.clear = function () {
        report({ type: "storage", storageArea: areaName, action: "clear", key: "*" });
        return clear();
      };
    } catch { /* some pages disallow access; ignore */ }
  }
  wrapStorage(window.localStorage, "localStorage");
  wrapStorage(window.sessionStorage, "sessionStorage");

  // ---- IndexedDB open ----
  try {
    if (window.indexedDB && window.indexedDB.open) {
      const open = window.indexedDB.open.bind(window.indexedDB);
      window.indexedDB.open = function (name, ...rest) {
        report({ type: "storage", storageArea: "indexedDB", action: "open", key: String(name) });
        return open(name, ...rest);
      };
    }
  } catch { /* ignore */ }

  // ---- permission-style requests (observe only) ----
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      const gum = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
      navigator.mediaDevices.getUserMedia = function (constraints) {
        const perm = constraints && constraints.video ? "camera" : "microphone";
        report({ type: "permission", permission: perm });
        return gum(constraints);
      };
    }
  } catch { /* ignore */ }

  try {
    if (navigator.geolocation) {
      const get = navigator.geolocation.getCurrentPosition.bind(navigator.geolocation);
      navigator.geolocation.getCurrentPosition = function (...args) {
        report({ type: "permission", permission: "geolocation" });
        return get(...args);
      };
      const watch = navigator.geolocation.watchPosition.bind(navigator.geolocation);
      navigator.geolocation.watchPosition = function (...args) {
        report({ type: "permission", permission: "geolocation" });
        return watch(...args);
      };
    }
  } catch { /* ignore */ }

  try {
    if (window.Notification && Notification.requestPermission) {
      const req = Notification.requestPermission.bind(Notification);
      Notification.requestPermission = function (...args) {
        report({ type: "permission", permission: "notifications" });
        return req(...args);
      };
    }
  } catch { /* ignore */ }

  // ---- fingerprinting vectors (observe only, report once per method/page) ----
  const fpSeen = new Set();
  function reportFp(method) {
    if (fpSeen.has(method)) return;
    fpSeen.add(method);
    report({ type: "fingerprint", method });
  }

  // Canvas fingerprinting: toDataURL / getImageData on a 2D context.
  try {
    if (window.HTMLCanvasElement) {
      const proto = HTMLCanvasElement.prototype;
      if (proto.toDataURL) {
        const orig = proto.toDataURL;
        proto.toDataURL = function (...args) { reportFp("canvas"); return orig.apply(this, args); };
      }
    }
    if (window.CanvasRenderingContext2D) {
      const c2d = CanvasRenderingContext2D.prototype;
      if (c2d.getImageData) {
        const orig = c2d.getImageData;
        c2d.getImageData = function (...args) { reportFp("canvas"); return orig.apply(this, args); };
      }
      // Font enumeration commonly probes text metrics across many font-faces.
      if (c2d.measureText) {
        const orig = c2d.measureText;
        c2d.measureText = function (...args) { reportFp("font"); return orig.apply(this, args); };
      }
    }
  } catch { /* ignore */ }

  // WebGL fingerprinting: getParameter (renderer/vendor) on a WebGL context.
  try {
    const wrapGetParameter = (ctor) => {
      if (ctor && ctor.prototype && ctor.prototype.getParameter) {
        const orig = ctor.prototype.getParameter;
        ctor.prototype.getParameter = function (...args) { reportFp("webgl"); return orig.apply(this, args); };
      }
    };
    wrapGetParameter(window.WebGLRenderingContext);
    wrapGetParameter(window.WebGL2RenderingContext);
  } catch { /* ignore */ }

  // AudioContext fingerprinting: oscillator/analyser graph construction.
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    if (AC && AC.prototype && AC.prototype.createOscillator) {
      const orig = AC.prototype.createOscillator;
      AC.prototype.createOscillator = function (...args) { reportFp("audio"); return orig.apply(this, args); };
    }
    const OAC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
    if (OAC && OAC.prototype && OAC.prototype.createOscillator) {
      const orig = OAC.prototype.createOscillator;
      OAC.prototype.createOscillator = function (...args) { reportFp("audio"); return orig.apply(this, args); };
    }
  } catch { /* ignore */ }
})();
