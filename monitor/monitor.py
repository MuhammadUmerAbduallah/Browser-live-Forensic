#!/usr/bin/env python3
"""
monitor.py — local resource-monitoring agent (Phase 7).

Samples overall CPU/RAM and per-browser-process usage with psutil and POSTs
a "resource" event to the local listener every few seconds. No cloud, no
external calls — only http://localhost:9000/log.

Usage:
    pip install -r requirements.txt
    python monitor.py                 # default 5s interval
    python monitor.py --interval 10   # custom interval
"""

import argparse
import json
import time
import urllib.request
from datetime import datetime

import psutil

LISTENER = "http://localhost:9000/log"
BROWSER_HINTS = ("chrome", "chromium", "brave", "msedge", "edge", "opera")


def post(event: dict) -> None:
    data = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        LISTENER, data=data, headers={"Content-Type": "application/json"}, method="POST"
    )
    try:
        urllib.request.urlopen(req, timeout=2).read()
    except Exception:
        # Listener not running yet; skip this sample quietly.
        pass


def browser_usage() -> dict:
    """Aggregate CPU% and RAM (MB) across browser processes."""
    total_cpu = 0.0
    total_mem = 0.0
    procs = 0
    for p in psutil.process_iter(attrs=["name", "memory_info"]):
        name = (p.info.get("name") or "").lower()
        if any(h in name for h in BROWSER_HINTS):
            try:
                total_cpu += p.cpu_percent(interval=None)
                mem = p.info.get("memory_info")
                if mem:
                    total_mem += mem.rss / (1024 * 1024)
                procs += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return {
        "browserProcesses": procs,
        "browserCpu": round(total_cpu, 1),
        "browserRamMb": round(total_mem, 1),
    }


def main() -> None:
    ap = argparse.ArgumentParser(description="Local resource monitor")
    ap.add_argument("--interval", type=float, default=5.0, help="seconds between samples")
    args = ap.parse_args()

    # Prime CPU counters (first call always returns 0.0).
    psutil.cpu_percent(interval=None)
    for p in psutil.process_iter():
        try:
            p.cpu_percent(interval=None)
        except Exception:
            pass

    print(f"[monitor] sampling every {args.interval}s -> {LISTENER}  (Ctrl+C to stop)")
    try:
        while True:
            time.sleep(args.interval)
            cpu = psutil.cpu_percent(interval=None)
            vm = psutil.virtual_memory()
            event = {
                "type": "resource",
                "cpu": round(cpu, 1),
                "ram": round(vm.percent, 1),
                "ramUsedMb": round(vm.used / (1024 * 1024), 1),
                "time": datetime.now().strftime("%H:%M:%S"),
                **browser_usage(),
            }
            post(event)
            print(f"[monitor] CPU {event['cpu']}% RAM {event['ram']}% "
                  f"browser={event['browserProcesses']}proc/{event['browserRamMb']}MB")
    except KeyboardInterrupt:
        print("\n[monitor] stopped")


if __name__ == "__main__":
    main()
