# Browser Forensics

A completely local browser forensic and live-activity intelligence system.
Runs only on your PC — no cloud, no external APIs, no telemetry, no accounts,
no internet dependency. The only network traffic is the browser extension
talking to the desktop app on `localhost:9000`.

```
Chrome Extension ──▶ localhost:9000 ──▶ Electron app ──▶ Persistent store (SQLite)
   tabs/cookies          (listener)        dashboard          + risk engine
   navigation                              live + history      + evidence cases
   requests/storage                        search/filter
   permissions/downloads
        ▲
        │
  Python monitor (CPU/RAM/browser processes)
```

## What's in this build

This takes the proof-of-concept through the full roadmap (Phases 2–8):

| Area | Status |
|------|--------|
| Local listener + Electron dashboard | ✓ (kept, hardened to localhost-only) |
| **Persistent store (SQLite)** | ✓ **Phase 2** — built-in `node:sqlite`, no native build; auto-imports your old `events.jsonl` |
| Event history + search + filters | ✓ **Phase 3** |
| Storage monitoring (local/session/IndexedDB) | ✓ **Phase 4** |
| Network intelligence (requests, third-party trackers, analytics) | ✓ **Phase 5** |
| Permission intelligence (camera/mic/location/notifications) | ✓ **Phase 6** |
| Resource monitoring agent (Python + psutil) | ✓ **Phase 7** |
| Evidence engine (cases + exportable HTML report) | ✓ **Phase 8** |

The risk engine scores every event (INFO / MEDIUM / HIGH) using cookie-change
frequency, known tracker/analytics domains, third-party context, sensitive
permissions, executable downloads, suspicious TLDs, and resource spikes.

## Setup

### 1. Desktop app
```bash
cd desktop
npm install        # installs Electron + Express only — no native build step
npm start
```

The persistent store uses **Node's built-in SQLite** (`node:sqlite`), which is
compiled into the Node runtime inside Electron. There is no native module to
compile — no `better-sqlite3`, no `electron-rebuild`, no Visual Studio Build
Tools. The header shows `sqlite · local` when it's active.

If you're on an older Electron where `node:sqlite` is still behind a flag and
the header shows `jsonl · local`, start it with the flag instead:
```bash
npm run start:sqlite-flag
```
Either way the app runs: if SQLite isn't available it automatically falls back
to an on-disk JSONL store, so you never get a broken launch.

### 2. Browser extension
1. Go to `chrome://extensions`
2. Enable **Developer mode**
3. Click **Load unpacked** and select the `extension/` folder

The popup shows whether the listener is online and how many events it has sent.

### 3. Resource monitor (optional)
```bash
cd monitor
pip install -r requirements.txt
python monitor.py            # or: python monitor.py --interval 10
```

## Using it

- **Live** — real-time feed; pause or filter by risk.
- **History** — everything ever captured, paged.
- **Search** — filter by text, type, risk, or domain; save a query as a case.
- **Cookies / Domains** — aggregated activity with risk levels.
- **Cases** — create an evidence case (a saved time range + filter), open it to
  see a summary, and **Export** it to a standalone HTML report you can keep.

## Layout
```
desktop/    Electron app — main.js, db.js (store), risk.js (engine),
            preload.js, renderer.js, index.html, styles.css
extension/  MV3 extension — manifest, background, content + relay, popup
monitor/    Python resource agent — monitor.py, requirements.txt
data/       created at runtime (forensics.db or events.jsonl + cases.json)
```

## Privacy properties
Local only · no cloud · no external storage · no API keys · no telemetry ·
no third-party analytics · no accounts · no internet dependency. The listener
rejects any connection that isn't from `127.0.0.1`.
