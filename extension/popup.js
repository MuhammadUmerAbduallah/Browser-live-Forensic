// popup.js — shows whether the local listener is reachable and per-type counts.

async function render() {
  const counts = (await chrome.storage.session.get("counts")).counts || { total: 0, byType: {} };
  document.getElementById("total").textContent = counts.total;
  const rows = Object.entries(counts.byType).sort((a, b) => b[1] - a[1]);
  document.getElementById("rows").innerHTML = rows.length
    ? rows.map(([k, v]) => `<div class="row"><span>${k}</span><b>${v}</b></div>`).join("")
    : `<div class="status">No events captured yet.</div>`;
}

async function checkListener() {
  const dot = document.getElementById("dot");
  const status = document.getElementById("status");
  try {
    const res = await fetch("http://localhost:9000/health", { cache: "no-store" });
    const j = await res.json();
    dot.classList.remove("off");
    status.textContent = `Listener online · store: ${j.backend}`;
  } catch {
    dot.classList.add("off");
    status.textContent = "Listener offline — open the desktop app.";
  }
}

checkListener();
render();
