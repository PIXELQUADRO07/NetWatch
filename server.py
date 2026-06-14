"""
server.py – NetWatch API server (v4)
Integrates: C++ capture, Nmap scanner, SQLite persistence, GeoIP enrichment,
advanced anomaly detection, SSE live streaming, JWT auth, structured logging,
historical analytics, config panel API, rate limiting, and full error recovery.

Run:
    python server.py --demo
    sudo python server.py --interface eth0
    docker compose up
"""

from __future__ import annotations

import argparse
import json
import math
import os
import queue
import subprocess
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from flask import Flask, Response, jsonify, request, g
from flask_cors import CORS

from db import Database
from geoip import GeoIPResolver, is_private
from nmap_scanner import NmapScanner, ScanScheduler, ScanType, local_subnet
from auth import register_auth_routes, require_auth, is_auth_enabled
from logger import get_logger

log = get_logger("server")

# ─── Config ──────────────────────────────────────────────────────────────────

CAPTURE_BINARY  = os.path.join(os.path.dirname(__file__), "capture", "packet_capture")
HISTORY_SIZE    = 300
PRUNE_INTERVAL  = 3600
DB_PATH         = os.getenv("NETWATCH_DB", str(Path(__file__).parent / "netwatch.db"))

RATE_LIMIT_WINDOW = 60
RATE_LIMIT_MAX    = 300

CAPTURE_MAX_RESTARTS   = 10
CAPTURE_RESTART_BACKOFF = [1, 2, 4, 8, 16, 30, 60, 60, 60, 60]

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ─── Shared state ─────────────────────────────────────────────────────────────

snapshot_history: deque[dict] = deque(maxlen=HISTORY_SIZE)
bandwidth_series: deque[dict] = deque(maxlen=60)
latest_snapshot:  dict        = {}
state_lock = threading.Lock()

SSE_CLIENTS: list[queue.Queue] = []
SSE_LOCK = threading.Lock()

_rate_buckets: dict[str, list] = defaultdict(list)
_rate_lock = threading.Lock()

db:        Optional[Database]       = None
geo:       Optional[GeoIPResolver]  = None
scanner:   Optional[NmapScanner]    = None
scheduler: Optional[ScanScheduler]  = None

_config = {
    "alert_threshold_bps":   5_000_000,
    "alert_threshold_flows": 300,
    "alert_cooldown_sec":    30,
    "geoip_enabled":         True,
    "suspicious_ports":      [6667, 6668, 6669, 4444, 1337, 31337, 12345, 9001],
    "interface":             "",
    "demo_mode":             False,
    "prune_keep_days":       7,
    "rate_limit_max":        RATE_LIMIT_MAX,
    "dark_mode":             True,
    "language":              "it",
}
_config_lock = threading.Lock()

_alert_cooldown: dict[tuple, float] = {}
_cooldown_lock = threading.Lock()                       # FIX: was unprotected

# LRU-bounded port tracking: max 2048 distinct source IPs to avoid unbounded RAM growth
_PORT_WINDOW_MAX_HOSTS = 2048
_port_window: dict[str, deque] = {}
_port_window_lock = threading.Lock()                    # FIX: was unprotected

# ── Adaptive Z-score baseline (per-host bandwidth, per-window bps) ───────────
# Stores (n, mean, M2) using Welford's online algorithm — no list of samples needed
_baseline_host: dict[str, tuple[int, float, float]] = {}   # ip → (n, mean, M2)
_baseline_global: tuple[int, float, float] = (0, 0.0, 0.0) # global bps baseline
_baseline_lock = threading.Lock()

BASELINE_MIN_SAMPLES = 30   # need at least 30 snapshots before firing Z-score alerts
BASELINE_Z_THRESH    = 3.0  # σ multiplier — alert when deviation > 3σ

# ── Beaconing detection ───────────────────────────────────────────────────────
# Tracks connection timestamps per (src_ip, dst_ip, dst_port) tuple
_beacon_timestamps: dict[tuple, deque] = {}
_beacon_lock = threading.Lock()
BEACON_MIN_CONNS     = 6    # need at least 6 connections to compute variance
BEACON_MAX_VARIANCE  = 4.0  # seconds² — if variance of intervals is this low, it's beaconing
BEACON_WINDOW_SEC    = 300  # look back 5 minutes

_capture_proc: Optional[subprocess.Popen] = None
_capture_lock = threading.Lock()


# ─── Rate limiting ────────────────────────────────────────────────────────────

def _check_rate_limit(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        _rate_buckets[ip] = [t for t in _rate_buckets[ip] if now - t < RATE_LIMIT_WINDOW]
        if len(_rate_buckets[ip]) >= _config["rate_limit_max"]:
            return False
        _rate_buckets[ip].append(now)
        return True


@app.before_request
def before_request():
    ip = request.remote_addr or "unknown"
    if not _check_rate_limit(ip):
        log.warn("Rate limit exceeded", ip=ip, path=request.path)
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429


# ─── Error handlers ───────────────────────────────────────────────────────────

@app.errorhandler(400)
def bad_request(e):   return jsonify({"error": "Bad request",       "detail": str(e)}), 400
@app.errorhandler(401)
def unauthorized(e):  return jsonify({"error": "Unauthorized"}),                        401
@app.errorhandler(404)
def not_found(e):     return jsonify({"error": "Not found"}),                           404
@app.errorhandler(Exception)
def handle_exception(e):
    log.error("Unhandled exception", error=str(e), tb=traceback.format_exc())
    return jsonify({"error": "Internal server error", "detail": str(e)}), 500


# ─── Anomaly detection ────────────────────────────────────────────────────────

def _check_cooldown(atype: str, detail: str) -> bool:
    """Thread-safe cooldown check. Returns True if alert should fire."""
    key = (atype, detail[:40])
    now = time.time()
    with _cooldown_lock:                                # FIX: was not locked
        if now - _alert_cooldown.get(key, 0) < _config.get("alert_cooldown_sec", 30):
            return False
        _alert_cooldown[key] = now
    return True


# ── Welford online algorithm helpers ─────────────────────────────────────────

def _welford_update(state: tuple[int, float, float], x: float) -> tuple[int, float, float]:
    """Update (n, mean, M2) with new sample x. Returns updated state."""
    n, mean, M2 = state
    n    += 1
    delta = x - mean
    mean += delta / n
    M2   += delta * (x - mean)
    return (n, mean, M2)

def _welford_stddev(state: tuple[int, float, float]) -> float:
    """Return sample stddev from Welford state, or 0 if n < 2."""
    n, mean, M2 = state
    if n < 2:
        return 0.0
    return math.sqrt(M2 / (n - 1))

def _welford_mean(state: tuple[int, float, float]) -> float:
    return state[1]

def _welford_n(state: tuple[int, float, float]) -> int:
    return state[0]


# ── Baseline update (called once per ingest) ──────────────────────────────────

def _update_baselines(snap: dict) -> None:
    """Update Welford baselines for global bps and per-host bps."""
    global _baseline_global
    window = max(snap.get("window_sec", 1.0), 0.001)
    global_bps = snap.get("total_bytes", 0) / window

    with _baseline_lock:
        _baseline_global = _welford_update(_baseline_global, global_bps)
        for h in snap.get("top_hosts", []):
            ip = h.get("ip", "")
            if not ip:
                continue
            host_bps = (h.get("bytes_sent", 0) + h.get("bytes_recv", 0)) / window
            prev = _baseline_host.get(ip, (0, 0.0, 0.0))
            _baseline_host[ip] = _welford_update(prev, host_bps)


# ── Beaconing helpers ─────────────────────────────────────────────────────────

def _update_beacon_timestamps(snap: dict) -> None:
    """Record each new connection for beaconing detection."""
    now_ts = time.time()
    with _beacon_lock:
        for f in snap.get("top_flows", []):
            src  = f.get("src_ip", "")
            dst  = f.get("dst_ip", "")
            dport= f.get("dst_port")
            if not (src and dst and dport):
                continue
            key = (src, dst, dport)
            if key not in _beacon_timestamps:
                _beacon_timestamps[key] = deque(maxlen=60)
            _beacon_timestamps[key].append(now_ts)
        # Evict stale keys (no activity in BEACON_WINDOW_SEC)
        cutoff = now_ts - BEACON_WINDOW_SEC
        stale = [k for k, ts in _beacon_timestamps.items() if not ts or ts[-1] < cutoff]
        for k in stale:
            del _beacon_timestamps[k]


def _check_beaconing() -> list[dict]:
    """Return BEACONING alerts for any flow with suspiciously regular intervals."""
    alerts = []
    now_ts = time.time()
    cutoff = now_ts - BEACON_WINDOW_SEC
    with _beacon_lock:
        for (src, dst, dport), timestamps in _beacon_timestamps.items():
            # Only timestamps within the window
            recent = [t for t in timestamps if t >= cutoff]
            if len(recent) < BEACON_MIN_CONNS:
                continue
            intervals = [recent[i+1] - recent[i] for i in range(len(recent) - 1)]
            if not intervals:
                continue
            mean_interval = sum(intervals) / len(intervals)
            variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
            if variance < BEACON_MAX_VARIANCE and mean_interval > 0:
                detail = (f"{src} → {dst}:{dport} "
                          f"every {mean_interval:.1f}s ±{math.sqrt(variance):.1f}s "
                          f"({len(recent)} conns/5m)")
                if _check_cooldown("BEACONING", f"{src}{dst}{dport}"):
                    alerts.append({
                        "type": "BEACONING",
                        "detail": detail,
                        "severity": "high",
                    })
    return alerts


# ── Main detection function ───────────────────────────────────────────────────

def detect_anomalies(snap: dict) -> list[dict]:
    alerts = []
    now_ts  = time.time()
    window  = max(snap.get("window_sec", 1.0), 0.001)
    threshold_bps   = _config.get("alert_threshold_bps",   5_000_000)
    threshold_flows = _config.get("alert_threshold_flows",  300)
    susp_ports      = set(_config.get("suspicious_ports",   []))

    # ── HIGH_BANDWIDTH: static threshold + Z-score adaptive ──────────────────
    with _baseline_lock:
        g_n    = _welford_n(_baseline_global)
        g_mean = _welford_mean(_baseline_global)
        g_std  = _welford_stddev(_baseline_global)

    for h in snap.get("top_hosts", []):
        ip        = h.get("ip", "")
        total_bps = (h.get("bytes_sent", 0) + h.get("bytes_recv", 0)) / window

        # Static threshold (always active)
        if total_bps > threshold_bps:
            detail = f"{ip} @ {total_bps/1e6:.1f} MB/s (above threshold)"
            if _check_cooldown("HIGH_BANDWIDTH", ip):
                alerts.append({"type": "HIGH_BANDWIDTH", "detail": detail, "severity": "medium"})
            continue  # don't double-alert on same host

        # Z-score per-host (fires only after BASELINE_MIN_SAMPLES)
        with _baseline_lock:
            h_state = _baseline_host.get(ip, (0, 0.0, 0.0))
        h_n   = _welford_n(h_state)
        h_mean= _welford_mean(h_state)
        h_std = _welford_stddev(h_state)
        if h_n >= BASELINE_MIN_SAMPLES and h_std > 0:
            z = (total_bps - h_mean) / h_std
            if z > BASELINE_Z_THRESH:
                detail = (f"{ip} @ {total_bps/1e6:.1f} MB/s "
                          f"(+{z:.1f}σ above normal {h_mean/1e6:.1f} MB/s)")
                if _check_cooldown("HIGH_BANDWIDTH_ZSCORE", ip):
                    alerts.append({
                        "type": "HIGH_BANDWIDTH",
                        "detail": detail,
                        "severity": "medium",
                        "zscore": round(z, 2),
                    })

    # ── FLOW_SPIKE: static + Z-score on global bps ───────────────────────────
    active_flows = snap.get("active_flows", 0)
    if active_flows > threshold_flows:
        detail = f"Active flows: {active_flows}"
        if _check_cooldown("FLOW_SPIKE", detail):
            alerts.append({"type": "FLOW_SPIKE", "detail": detail, "severity": "high"})
    elif g_n >= BASELINE_MIN_SAMPLES and g_std > 0:
        global_bps = snap.get("total_bytes", 0) / window
        z = (global_bps - g_mean) / g_std
        if z > BASELINE_Z_THRESH:
            detail = (f"Global bandwidth spike {global_bps/1e6:.1f} MB/s "
                      f"(+{z:.1f}σ, normal {g_mean/1e6:.1f} MB/s)")
            if _check_cooldown("FLOW_SPIKE_ZSCORE", "global"):
                alerts.append({
                    "type": "FLOW_SPIKE",
                    "detail": detail,
                    "severity": "high",
                    "zscore": round(z, 2),
                })

    # ── PORT_SCAN ─────────────────────────────────────────────────────────────
    with _port_window_lock:                             # FIX: was not locked
        for f in snap.get("top_flows", []):
            src, dst_port = f.get("src_ip", ""), f.get("dst_port")
            if src and dst_port:
                if src not in _port_window:
                    # Evict oldest if we're at the host cap (LRU-lite: just drop random)
                    if len(_port_window) >= _PORT_WINDOW_MAX_HOSTS:
                        evict = next(iter(_port_window))
                        del _port_window[evict]
                    _port_window[src] = deque(maxlen=500)
                _port_window[src].append((now_ts, dst_port))

        for src, entries in list(_port_window.items()):
            recent = [(t, p) for t, p in entries if now_ts - t < 10]
            _port_window[src] = deque(recent, maxlen=500)
            unique_ports = len(set(p for _, p in recent))
            if unique_ports >= 20:
                detail = f"{src} → {unique_ports} ports/10s"
                if _check_cooldown("PORT_SCAN", src):
                    alerts.append({"type": "PORT_SCAN", "detail": detail, "severity": "high"})

    # ── SUSPICIOUS_PORT ───────────────────────────────────────────────────────
    for f in snap.get("top_flows", []):
        dp = f.get("dst_port")
        if dp in susp_ports and not is_private(f.get("dst_ip", "127.0.0.1")):
            detail = f"{f['src_ip']} → {f['dst_ip']}:{dp}"
            if _check_cooldown("SUSPICIOUS_PORT", detail):
                alerts.append({"type": "SUSPICIOUS_PORT", "detail": detail, "severity": "high"})

    # ── DNS_TUNNEL ────────────────────────────────────────────────────────────
    for f in snap.get("top_flows", []):
        if f.get("dst_port") == 53 and f.get("proto") == "UDP":
            avg_size = f.get("bytes", 0) / max(f.get("packets", 1), 1)
            if avg_size > 400:
                detail = f"{f['src_ip']} DNS avg pkt {avg_size:.0f}B"
                if _check_cooldown("DNS_TUNNEL", f["src_ip"]):
                    alerts.append({"type": "DNS_TUNNEL", "detail": detail, "severity": "medium"})

    # ── EXT_SCAN ──────────────────────────────────────────────────────────────
    ext_to_int: dict[str, set] = defaultdict(set)
    for f in snap.get("top_flows", []):
        src, dst = f.get("src_ip", ""), f.get("dst_ip", "")
        if src and dst and not is_private(src) and is_private(dst):
            ext_to_int[src].add(dst)
    for ext_ip, int_hosts in ext_to_int.items():
        if len(int_hosts) >= 5:
            detail = f"{ext_ip} → {len(int_hosts)} internal hosts"
            if _check_cooldown("EXT_SCAN", ext_ip):
                alerts.append({"type": "EXT_SCAN", "detail": detail, "severity": "high"})

    # ── BEACONING ─────────────────────────────────────────────────────────────
    alerts.extend(_check_beaconing())

    return alerts


# ─── Enrichment & ingest ──────────────────────────────────────────────────────

def enrich(snap: dict) -> dict:
    window = max(snap.get("window_sec", 1.0), 0.001)
    snap["bytes_per_sec"]   = snap.get("total_bytes",   0) / window
    snap["packets_per_sec"] = snap.get("total_packets", 0) / window
    snap["datetime"]        = datetime.now(timezone.utc).isoformat()
    bps = snap["bytes_per_sec"]
    snap["bandwidth_human"] = (
        f"{bps/1e6:.1f} MB/s" if bps >= 1e6 else
        f"{bps/1e3:.1f} KB/s" if bps >= 1e3 else
        f"{bps:.0f} B/s"
    )
    # Update adaptive baselines before detection (so this snapshot feeds next alert)
    try:
        _update_baselines(snap)
    except Exception as e:
        log.error("Baseline update failed", error=str(e))
    # Update beaconing timestamps
    try:
        _update_beacon_timestamps(snap)
    except Exception as e:
        log.error("Beacon timestamp update failed", error=str(e))
    try:
        new_alerts = detect_anomalies(snap)
        # Populate snap["beacons"] for the DNS tab (structured list, not raw alert strings)
        snap["beacons"] = [
            {
                "src":        a["detail"].split("→")[0].strip(),
                "dst":        a["detail"].split("→")[1].split(":")[0].strip() if "→" in a["detail"] else "",
                "port":       a["detail"].split(":")[1].split()[0] if ":" in a["detail"].split("→")[-1] else 0,
                "interval_s": a["detail"].split("every ")[1].split("s")[0] if "every " in a["detail"] else "?",
                "conns":      a["detail"].split("(")[1].split()[0] if "(" in a["detail"] else "?",
                "detail":     a["detail"],
            }
            for a in new_alerts if a["type"] == "BEACONING"
        ]
        # Alert deduplication: merge repeated alerts into occurrences counter
        existing = snap.get("alerts", [])
        deduped: list[dict] = list(existing)
        for alert in new_alerts:
            key = (alert["type"], alert.get("detail", "")[:60])
            match = next((a for a in deduped
                          if a["type"] == alert["type"]
                          and a.get("detail","")[:60] == alert.get("detail","")[:60]), None)
            if match:
                match["occurrences"] = match.get("occurrences", 1) + 1
            else:
                alert.setdefault("occurrences", 1)
                deduped.append(alert)
        snap["alerts"] = deduped
    except Exception as e:
        log.error("Anomaly detection failed", error=str(e))
    if geo and _config.get("geoip_enabled", True):
        try:
            geo.enrich_snapshot(snap)
        except Exception as e:
            log.warn("GeoIP enrichment failed", error=str(e))
    # Expose baseline stats for the frontend/API
    with _baseline_lock:
        snap["baseline"] = {
            "n": _welford_n(_baseline_global),
            "mean_bps": round(_welford_mean(_baseline_global), 1),
            "std_bps":  round(_welford_stddev(_baseline_global), 1),
        }
    return snap


def ingest(raw: str) -> None:
    global latest_snapshot
    if not raw or not raw.strip():
        return
    try:
        snap = json.loads(raw.strip())
    except json.JSONDecodeError as e:
        log.warn("JSON decode error", error=str(e), raw=raw[:100])
        return
    try:
        snap = enrich(snap)
    except Exception as e:
        log.error("Enrichment failed", error=str(e))
        return

    with state_lock:
        snapshot_history.append(snap)
        latest_snapshot = snap
        bandwidth_series.append({"t": snap["datetime"], "bps": snap["bytes_per_sec"], "pps": snap["packets_per_sec"]})

    if db:
        threading.Thread(target=_safe_db_save, args=(snap,), daemon=True).start()

    payload = "data: " + json.dumps(snap) + "\n\n"
    with SSE_LOCK:
        dead = []
        for q in SSE_CLIENTS:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            try: SSE_CLIENTS.remove(q)
            except ValueError: pass


def _safe_db_save(snap: dict) -> None:
    try:
        db.save_snapshot(snap)
    except Exception as e:
        log.error("DB save failed", error=str(e))


# ─── Capture with auto-recovery ───────────────────────────────────────────────

def read_from_process(interface: str) -> None:
    global _capture_proc
    restart_count = 0
    while restart_count < CAPTURE_MAX_RESTARTS:
        cmd = [CAPTURE_BINARY] + ([interface] if interface else [])
        log.info("Launching capture binary", cmd=" ".join(cmd), attempt=restart_count + 1)
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, bufsize=1)
            with _capture_lock:
                _capture_proc = proc
            for line in proc.stdout:
                if line.strip():
                    ingest(line)
            stderr_out = proc.stderr.read() if proc.stderr else ""
            ret = proc.wait()
            log.warn("Capture process exited", return_code=ret, stderr=(stderr_out[:500] if stderr_out else ""))
        except FileNotFoundError:
            log.warn("Capture binary not found — switching to DEMO mode")
            _inject_demo_data()
            return
        except Exception as e:
            log.error("Capture process error", error=str(e))
        restart_count += 1
        backoff = CAPTURE_RESTART_BACKOFF[min(restart_count - 1, len(CAPTURE_RESTART_BACKOFF) - 1)]
        log.warn(f"Restarting capture in {backoff}s", restart=restart_count)
        time.sleep(backoff)
    log.error("Max capture restarts reached — switching to DEMO mode")
    _inject_demo_data()


def read_from_stdin() -> None:
    log.info("Reading from stdin")
    for line in sys.stdin:
        if line.strip():
            ingest(line)


def _inject_demo_data() -> None:
    import random, math
    log.info("DEMO MODE active")
    hosts = ["192.168.1.1","192.168.1.10","192.168.1.20","192.168.1.50",
             "10.0.0.5","10.0.0.15","8.8.8.8","1.1.1.1","172.16.0.1","185.220.101.5"]
    ports_common = [80, 443, 53, 22, 8080, 3306, 5432, 6379, 25, 110]
    t = 0
    while True:
        t += 1
        base_bw = 400_000 + 350_000 * math.sin(t / 12) + 100_000 * math.sin(t / 3)
        top_hosts = []
        for h in hosts:
            s = int(random.gauss(base_bw / len(hosts), 60_000))
            r = int(random.gauss(base_bw / len(hosts) * 0.5, 25_000))
            top_hosts.append({"ip": h, "bytes_sent": max(0, s), "bytes_recv": max(0, r),
                               "pkts_sent": max(0, s // 1200), "pkts_recv": max(0, r // 1200)})
        top_hosts.sort(key=lambda x: x["bytes_sent"] + x["bytes_recv"], reverse=True)
        flows = []
        for _ in range(12):
            src, dst = random.choice(hosts), random.choice(hosts)
            byt = random.randint(500, 800_000)
            flows.append({"src_ip": src, "dst_ip": dst,
                          "src_port": random.randint(1024, 65535),
                          "dst_port": random.choice(ports_common),
                          "proto": random.choices(["TCP","UDP","ICMP"], weights=[70,25,5])[0],
                          "bytes": byt, "packets": max(1, byt // 1400)})
        alerts = []
        if t % 30 == 0: alerts.append({"type":"PORT_SCAN","detail":"192.168.1.50 → 24 ports/10s","severity":"high"})
        if t % 47 == 0: alerts.append({"type":"DNS_TUNNEL","detail":"10.0.0.15 DNS avg pkt 512B","severity":"medium"})
        snap = {"timestamp": int(time.time()*1000), "window_sec": 1.0,
                "total_bytes": int(base_bw + random.gauss(0, 40_000)),
                "total_packets": int(base_bw / 900),
                "active_flows": random.randint(15, 90),
                "top_hosts": top_hosts[:8], "top_flows": flows, "alerts": alerts}
        ingest(json.dumps(snap))
        time.sleep(1)


# ─── Nmap callback ────────────────────────────────────────────────────────────

def on_scan_complete(result) -> None:
    if db:
        try: db.save_scan(result)
        except Exception as e: log.error("Failed to save scan", error=str(e))
    evt = {"type": "nmap_complete", "scan_id": result.scan_id, "scan_type": result.scan_type,
           "target": result.target, "hosts": len(result.hosts), "duration": result.duration_s, "error": result.error}
    payload = "event: nmap\ndata: " + json.dumps(evt) + "\n\n"
    with SSE_LOCK:
        for q in SSE_CLIENTS:
            try: q.put_nowait(payload)
            except queue.Full: pass
    log.info("Nmap scan complete", scan_id=result.scan_id, hosts=len(result.hosts))


# ─── REST API ─────────────────────────────────────────────────────────────────

@app.get("/api/status")
def api_status():
    with state_lock: hist = len(snapshot_history)
    with _capture_lock: capture_alive = _capture_proc is not None and _capture_proc.poll() is None
    return jsonify({"ok": True, "history": hist, "db": db.stats() if db else {},
                    "capture_alive": capture_alive, "demo_mode": _config.get("demo_mode", False),
                    "auth_enabled": is_auth_enabled(), "version": "4.0"})


@app.get("/api/snapshot")
@require_auth
def api_snapshot():
    with state_lock: return jsonify(latest_snapshot or {})


@app.get("/api/history")
@require_auth
def api_history():
    limit = min(int(request.args.get("limit", 60)), HISTORY_SIZE)
    with state_lock: return jsonify(list(snapshot_history)[-limit:])


@app.get("/api/bandwidth")
@require_auth
def api_bandwidth():
    limit = int(request.args.get("limit", 60))
    with state_lock: return jsonify(list(bandwidth_series)[-limit:])


@app.get("/api/bandwidth/hourly")
@require_auth
def api_bandwidth_hourly():
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_hourly_history(hours) if db else [])


# ── Analytics ────────────────────────────────────────────────────────────────

@app.get("/api/analytics/summary")
@require_auth
def api_analytics_summary():
    if not db: return jsonify({"error": "DB not available"}), 503
    try: return jsonify(db.get_analytics_summary())
    except Exception as e: return jsonify({"error": str(e)}), 500


@app.get("/api/analytics/top-ips")
@require_auth
def api_top_ips():
    hours = int(request.args.get("hours", 24))
    limit = int(request.args.get("limit", 20))
    return jsonify(db.get_top_ips(hours=hours, limit=limit) if db else [])


@app.get("/api/analytics/top-ports")
@require_auth
def api_top_ports():
    hours = int(request.args.get("hours", 24))
    limit = int(request.args.get("limit", 20))
    return jsonify(db.get_top_ports(hours=hours, limit=limit) if db else [])


@app.get("/api/analytics/alert-timeline")
@require_auth
def api_alert_timeline():
    hours = int(request.args.get("hours", 24))
    return jsonify(db.get_alert_timeline(hours) if db else [])


@app.get("/api/analytics/baseline")
@require_auth
def api_baseline():
    """Return current adaptive baseline stats for all tracked hosts."""
    with _baseline_lock:
        hosts = {
            ip: {
                "n":       _welford_n(state),
                "mean_bps": round(_welford_mean(state), 1),
                "std_bps":  round(_welford_stddev(state), 1),
            }
            for ip, state in _baseline_host.items()
        }
        g = _baseline_global
        return jsonify({
            "global": {
                "n":       _welford_n(g),
                "mean_bps": round(_welford_mean(g), 1),
                "std_bps":  round(_welford_stddev(g), 1),
                "min_samples": BASELINE_MIN_SAMPLES,
                "z_thresh":    BASELINE_Z_THRESH,
            },
            "hosts": hosts,
        })


# ── Config ───────────────────────────────────────────────────────────────────

@app.get("/api/config")
@require_auth
def api_get_config():
    with _config_lock: return jsonify(dict(_config))


@app.patch("/api/config")
@require_auth
def api_update_config():
    data = request.json or {}
    allowed = {"alert_threshold_bps","alert_threshold_flows","alert_cooldown_sec",
               "geoip_enabled","suspicious_ports","prune_keep_days","rate_limit_max",
               "dark_mode","language",
               "beacon_max_variance","beacon_min_conns","baseline_z_thresh","baseline_min_samples"}
    with _config_lock:
        for k, v in data.items():
            if k in allowed:
                _config[k] = v
                log.info("Config updated", key=k, value=v, user=getattr(g, "user", "?"))
    with _config_lock: return jsonify(dict(_config))


# ── Alerts ───────────────────────────────────────────────────────────────────

@app.get("/api/alerts")
@require_auth
def api_alerts():
    limit   = int(request.args.get("limit", 100))
    unacked = request.args.get("unacked", "false").lower() == "true"
    if db: return jsonify(db.get_alerts(limit, unacked))
    with state_lock:
        alerts = [a for s in list(snapshot_history)[-100:] for a in s.get("alerts", [])]
    return jsonify(alerts[-limit:])


@app.post("/api/alerts/<int:alert_id>/ack")
@require_auth
def api_ack_alert(alert_id: int):
    if db: db.ack_alert(alert_id)
    return jsonify({"ok": True})


@app.post("/api/alerts/ack_all")
@require_auth
def api_ack_all():
    if db: db.ack_all_alerts()
    return jsonify({"ok": True})


# ── Hosts ────────────────────────────────────────────────────────────────────

@app.get("/api/hosts")
@require_auth
def api_hosts():
    if not db: return jsonify([])
    hosts = db.get_known_hosts()
    with state_lock: snap = latest_snapshot
    traffic_map = {h["ip"]: h for h in snap.get("top_hosts", [])}
    for h in hosts: h["live"] = traffic_map.get(h["ip"])
    return jsonify(hosts)


@app.get("/api/hosts/<ip>")
@require_auth
def api_host(ip: str):
    return jsonify(db.get_host(ip) or {} if db else {})


@app.patch("/api/hosts/<ip>")
@require_auth
def api_update_host(ip: str):
    data    = request.json or {}
    allowed = {"hostname", "tags", "notes"}
    kwargs  = {k: v for k, v in data.items() if k in allowed}
    if db and kwargs:
        if "tags" in kwargs and isinstance(kwargs["tags"], list):
            kwargs["tags"] = json.dumps(kwargs["tags"])
        db.update_host(ip, **kwargs)
    return jsonify({"ok": True})


# ── Scans ────────────────────────────────────────────────────────────────────

@app.get("/api/scans")
@require_auth
def api_scans():
    return jsonify(db.get_scans(int(request.args.get("limit", 50))) if db else [])


@app.post("/api/scans")
@require_auth
def api_scan_start():
    if not scanner: return jsonify({"error": "Scanner not initialized"}), 503
    data = request.json or {}
    try: stype = ScanType(data.get("scan_type", "tcp_connect").lower())
    except ValueError: return jsonify({"error": f"Unknown scan_type"}), 400
    target = data.get("target", "")
    if not target: return jsonify({"error": "target required"}), 400
    job_id = scanner.submit(stype, target, ports=data.get("ports", "1-1024"), extra_args=data.get("extra", ""))
    log.info("Scan started", scan_id=job_id, type=stype.value, target=target)
    return jsonify({"scan_id": job_id, "status": "running"}), 202


@app.get("/api/scans/<scan_id>")
@require_auth
def api_scan_status(scan_id: str):
    if scanner and scanner.is_running(scan_id): return jsonify({"scan_id": scan_id, "status": "running"})
    if scanner:
        result = scanner.get_result(scan_id)
        if result:
            from dataclasses import asdict
            return jsonify(asdict(result))
    if db:
        scans = db.get_scans(limit=1000)
        match = next((s for s in scans if s["id"] == scan_id), None)
        if match:
            match["ports"] = db.get_scan_ports(scan_id)
            return jsonify(match)
    return jsonify({"error": "Not found"}), 404


@app.get("/api/scans/<scan_id>/ports")
@require_auth
def api_scan_ports(scan_id: str):
    return jsonify(db.get_scan_ports(scan_id) if db else [])


@app.get("/api/vulnerabilities")
@require_auth
def api_vulns():
    return jsonify(db.get_vulnerabilities(int(request.args.get("limit", 200))) if db else [])


@app.get("/api/scan_types")
@require_auth
def api_scan_types():
    from nmap_scanner import SCAN_ARGS, NEEDS_ROOT
    return jsonify([{"id": st.value, "name": st.name, "args": SCAN_ARGS[st], "needs_root": st in NEEDS_ROOT} for st in ScanType])


@app.get("/api/geoip/<ip>")
@require_auth
def api_geoip(ip: str):
    if geo: return jsonify(geo.lookup(ip))
    return jsonify({"error": "GeoIP unavailable"}), 503


# ── Export ───────────────────────────────────────────────────────────────────

@app.get("/api/export/alerts.csv")
@require_auth
def export_alerts_csv():
    if not db: return jsonify({"error": "DB not available"}), 503
    import csv, io
    alerts = db.get_alerts(limit=10000)
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["id","ts","type","detail","severity","source","acked"])
    writer.writeheader()
    for a in alerts: writer.writerow({k: a.get(k,"") for k in ["id","ts","type","detail","severity","source","acked"]})
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=netwatch_alerts.csv"})


@app.get("/api/export/hosts.csv")
@require_auth
def export_hosts_csv():
    if not db: return jsonify({"error": "DB not available"}), 503
    import csv, io
    hosts = db.get_known_hosts()
    fields = ["ip","hostname","mac","vendor","os_guess","first_seen","last_seen","tags","notes"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=fields)
    writer.writeheader()
    for h in hosts: writer.writerow({k: h.get(k,"") for k in fields})
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=netwatch_hosts.csv"})


@app.get("/api/export/snapshots.json")
@require_auth
def export_snapshots_json():
    with state_lock: data = list(snapshot_history)
    return Response(json.dumps(data, indent=2), mimetype="application/json",
                    headers={"Content-Disposition": "attachment; filename=netwatch_snapshots.json"})


# ── SSE ──────────────────────────────────────────────────────────────────────

@app.get("/api/stream")
@require_auth
def api_stream():
    q: queue.Queue = queue.Queue(maxsize=30)
    with SSE_LOCK: SSE_CLIENTS.append(q)

    def generate():
        with state_lock:
            if latest_snapshot:
                yield "data: " + json.dumps(latest_snapshot) + "\n\n"
        try:
            while True:
                try: yield q.get(timeout=25)
                except queue.Empty: yield ": keepalive\n\n"
        except GeneratorExit: pass
        finally:
            with SSE_LOCK:
                try: SSE_CLIENTS.remove(q)
                except ValueError: pass

    return Response(generate(), mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"})


# ─── Background tasks ─────────────────────────────────────────────────────────

def _prune_loop():
    while True:
        time.sleep(PRUNE_INTERVAL)
        if db:
            try:
                db.prune(keep_days=_config.get("prune_keep_days", 7))
                log.info("DB pruned")
            except Exception as e: log.error("Prune error", error=str(e))


def _rate_cleanup_loop():
    while True:
        time.sleep(300)
        now = time.time()
        with _rate_lock:
            stale = [ip for ip, times in _rate_buckets.items()
                     if not any(now - t < RATE_LIMIT_WINDOW for t in times)]
            for ip in stale: del _rate_buckets[ip]


# ─── Entry point ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NetWatch v4")
    parser.add_argument("--interface",  "-i", default=os.getenv("NETWATCH_INTERFACE", ""))
    parser.add_argument("--stdin",      action="store_true")
    parser.add_argument("--demo",       action="store_true",
                        default=os.getenv("NETWATCH_DEMO", "false").lower() == "true")
    parser.add_argument("--port",       "-p", type=int, default=int(os.getenv("NETWATCH_PORT", "5000")))
    parser.add_argument("--no-db",      action="store_true")
    parser.add_argument("--no-geo",     action="store_true")
    parser.add_argument("--no-nmap",    action="store_true")
    parser.add_argument("--no-auth",    action="store_true")
    parser.add_argument("--maxmind-db", default="")
    parser.add_argument("--auto-scan",  action="store_true")
    args = parser.parse_args()

    log.info("NetWatch v4 starting", port=args.port, demo=args.demo)

    if not args.no_db:
        try:
            db = Database(path=Path(DB_PATH))
            log.info("SQLite ready", path=DB_PATH)
        except Exception as e:
            log.error("DB init failed", error=str(e))
            sys.exit(1)

    if not args.no_geo:
        geo = GeoIPResolver(maxmind_db=args.maxmind_db)
    else:
        _config["geoip_enabled"] = False

    if not args.no_nmap:
        try:
            scanner   = NmapScanner(on_complete=on_scan_complete)
            scheduler = ScanScheduler(scanner)
            if args.auto_scan:
                subnet = local_subnet(args.interface)
                scheduler.add(ScanType.PING,    subnet, interval_s=120)
                scheduler.add(ScanType.SYN,     subnet, ports="21-25,53,80,110,143,443,3306,5432,8080", interval_s=300)
                scheduler.add(ScanType.VERSION, subnet, ports="22,80,443,8080", interval_s=600)
                scheduler.start()
        except Exception as e:
            log.warn("Nmap init failed", error=str(e))

    if args.no_auth:
        os.environ["NETWATCH_AUTH_ENABLED"] = "false"
        log.warn("Authentication DISABLED")
    else:
        register_auth_routes(app)
        log.info("Authentication enabled")

    _config["demo_mode"] = args.demo
    _config["interface"] = args.interface

    if args.demo:
        t = threading.Thread(target=_inject_demo_data, daemon=True)
    elif args.stdin:
        t = threading.Thread(target=read_from_stdin, daemon=True)
    else:
        t = threading.Thread(target=read_from_process, args=(args.interface,), daemon=True)
    t.start()

    threading.Thread(target=_prune_loop, daemon=True).start()
    threading.Thread(target=_rate_cleanup_loop, daemon=True).start()

    log.info("Server ready", url=f"http://0.0.0.0:{args.port}")
    app.run(host="0.0.0.0", port=args.port, threaded=True)
