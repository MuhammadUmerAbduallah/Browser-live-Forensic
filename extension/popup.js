// popup.js — shows whether the local listener is reachable and per-type counts.

async function render() {
  const { captureStats = {} } = await chrome.storage.session.get("captureStats");
  const { delivered = 0, rejected = 0, unavailable = 0, suppressed = 0, byType = {} } = captureStats;
  document.getElementById("delivered").textContent = delivered;
  document.getElementById("rejected").textContent = rejected;
  document.getElementById("unavailable").textContent = unavailable;
  document.getElementById("suppressed").textContent = suppressed;

  const rows = Object.entries(byType).sort((a, b) => b[1] - a[1]);
  const fragment = document.createDocumentFragment();
  for (const [type, count] of rows) {
    const row = document.createElement("div");
    row.className = "row";
    const label = document.createElement("span");
    label.textContent = type;
    const value = document.createElement("b");
    value.textContent = count;
    row.append(label, value);
    fragment.append(row);
  }
  document.getElementById("rows").replaceChildren(fragment);
}

async function checkListener() {
  const dot = document.getElementById("dot");
  const status = document.getElementById("status");
  try {
    const res = await fetch("http://localhost:9000/health", {
      cache: "no-store",
      signal: AbortSignal.timeout(3000),
    });
    if (!res.ok) throw new Error("Listener health check failed");
    const j = await res.json();
    if (j.ok !== true) throw new Error("Listener did not report ready");
    dot.classList.remove("off");
    status.textContent = `Listener online · store: ${j.backend}`;
  } catch {
    dot.classList.add("off");
    status.textContent = "Listener offline — open the desktop app.";
  }
}

chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "session" && changes.captureStats) render();
});
checkListener();
render();
