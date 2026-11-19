// relay.js — runs in the ISOLATED world (has access to chrome.* APIs).
// Receives observations from content.js (page world) and forwards them
// to the background service worker, which sends them to the local listener.

window.addEventListener("message", (event) => {
  if (event.source !== window) return;
  const data = event.data;
  if (!data || data.__bf_relay !== true) return;
  try {
    chrome.runtime.sendMessage({ __bf: true, payload: data.payload });
  } catch { /* service worker asleep / context invalidated */ }
});
