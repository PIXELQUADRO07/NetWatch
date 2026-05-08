"""
db.py – NetWatch persistence layer (SQLite)
Stores traffic snapshots, nmap scan results, alerts, hosts, and flows.

Schema is created automatically on first run.
"""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

DB_PATH = Path(__file__).parent / "netwatch.db"


# ─── Schema ──────────────────────────────────────────────────────────────────

SCHEMA = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- ── Traffic snapshots (1/sec aggregated windows) ──────────────────────────
CREATE TABLE IF NOT EXISTS snapshots (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    ts              TEXT    NOT NULL,          -- ISO-8601 UTC
    window_sec      REAL    NOT NULL DEFAULT 1.0,
    total_bytes     INTEGER NOT NULL DEFAULT 0,
    total_packets   INTEGER NOT NULL DEFAULT 0,
    active_flows    INTEGER NOT NULL DEFAULT 0,
    bytes_per_sec   REAL    NOT NULL DEFAULT 0,
    packets_per_sec REAL    NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);

-- ── Per-host traffic (from snapshots) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS host_traffic (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    ip          TEXT    NOT NULL,
    bytes_sent  INTEGER NOT NULL DEFAULT 0,
    bytes_recv  INTEGER NOT NULL DEFAULT 0,
    pkts_sent   INTEGER NOT NULL DEFAULT 0,
    pkts_recv   INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_ht_ip ON host_traffic(ip);
CREATE INDEX IF NOT EXISTS idx_ht_snap ON host_traffic(snapshot_id);

-- ── Per-flow traffic ──────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS flows (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    snapshot_id INTEGER NOT NULL REFERENCES snapshots(id) ON DELETE CASCADE,
    src_ip      TEXT NOT NULL,
    dst_ip      TEXT NOT NULL,
    src_port    INTEGER,
    dst_port    INTEGER,
    proto       TEXT,
    bytes       INTEGER NOT NULL DEFAULT 0,
    packets     INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_flows_snap ON flows(snapshot_id);

-- ── Alerts ────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT    NOT NULL,
    type        TEXT    NOT NULL,
    detail      TEXT    NOT NULL DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT 'low',   -- low/medium/high
    source      TEXT    NOT NULL DEFAULT 'traffic', -- traffic / nmap
    acked       INTEGER NOT NULL DEFAULT 0,        -- 0=new, 1=acked
    extra_json  TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts  ON alerts(ts);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acked);

-- ── Known hosts (enriched, updated on each scan) ──────────────────────────
CREATE TABLE IF NOT EXISTS known_hosts (
    ip          TEXT    PRIMARY KEY,
    hostname    TEXT    NOT NULL DEFAULT '',
    mac         TEXT    NOT NULL DEFAULT '',
    vendor      TEXT    NOT NULL DEFAULT '',
    os_guess    TEXT    NOT NULL DEFAULT '',
    os_accuracy INTEGER NOT NULL DEFAULT 0,
    first_seen  TEXT    NOT NULL,
    last_seen   TEXT    NOT NULL,
    tags        TEXT    NOT NULL DEFAULT '[]',   -- JSON list
    notes       TEXT    NOT NULL DEFAULT '',
    geoip_json  TEXT    NOT NULL DEFAULT '{}'   -- country/city/asn from GeoIP
);

-- ── Nmap scan jobs ────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS nmap_scans (
    id          TEXT    PRIMARY KEY,    -- job_id from NmapScanner
    scan_type   TEXT    NOT NULL,
    target      TEXT    NOT NULL,
    ports_arg   TEXT    NOT NULL DEFAULT '',
    started_at  TEXT    NOT NULL,
    ended_at    TEXT    NOT NULL DEFAULT '',
    duration_s  REAL    NOT NULL DEFAULT 0,
    host_count  INTEGER NOT NULL DEFAULT 0,
    error       TEXT    NOT NULL DEFAULT '',
    raw_command TEXT    NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_scans_ts ON nmap_scans(started_at);

-- ── Nmap discovered ports (per scan) ─────────────────────────────────────
CREATE TABLE IF NOT EXISTS nmap_ports (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL REFERENCES nmap_scans(id) ON DELETE CASCADE,
    ip          TEXT    NOT NULL,
    port        INTEGER NOT NULL,
    proto       TEXT    NOT NULL,
    state       TEXT    NOT NULL,
    service     TEXT    NOT NULL DEFAULT '',
    version     TEXT    NOT NULL DEFAULT '',
    product     TEXT    NOT NULL DEFAULT '',
    cpe         TEXT    NOT NULL DEFAULT '',
    script_json TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_np_scan ON nmap_ports(scan_id);
CREATE INDEX IF NOT EXISTS idx_np_ip   ON nmap_ports(ip);

-- ── Nmap vuln findings (extracted from script output) ────────────────────
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     TEXT    NOT NULL REFERENCES nmap_scans(id) ON DELETE CASCADE,
    ip          TEXT    NOT NULL,
    port        INTEGER,
    proto       TEXT    NOT NULL DEFAULT 'tcp',
    script_id   TEXT    NOT NULL,
    output      TEXT    NOT NULL DEFAULT '',
    severity    TEXT    NOT NULL DEFAULT 'unknown',
    cve         TEXT    NOT NULL DEFAULT '',    -- extracted CVE ids (comma-sep)
    discovered  TEXT    NOT NULL               -- ISO-8601
);
CREATE INDEX IF NOT EXISTS idx_vuln_ip   ON vulnerabilities(ip);
CREATE INDEX IF NOT EXISTS idx_vuln_scan ON vulnerabilities(scan_id);

-- ── Bandwidth aggregates (hourly, for long-term charts) ──────────────────
CREATE TABLE IF NOT EXISTS bw_hourly (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    hour        TEXT    UNIQUE NOT NULL,   -- "2025-01-15T14" (UTC)
    total_bytes INTEGER NOT NULL DEFAULT 0,
    total_pkts  INTEGER NOT NULL DEFAULT 0,
    peak_bps    REAL    NOT NULL DEFAULT 0,
    sample_cnt  INTEGER NOT NULL DEFAULT 0
);
"""


# ─── Database class ──────────────────────────────────────────────────────────

class Database:
    def __init__(self, path: Path = DB_PATH):
        self._path = path
        self._local = threading.local()
        self._init_schema()

    # ── Connection management ─────────────────────────────────────────────

    def _conn(self) -> sqlite3.Connection:
        """Per-thread SQLite connection (thread-safe)."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(str(self._path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def tx(self):
        conn = self._conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def _init_schema(self):
        with self.tx() as conn:
            conn.executescript(SCHEMA)

    # ── Snapshots ─────────────────────────────────────────────────────────

    def save_snapshot(self, snap: dict) -> int:
        with self.tx() as conn:
            cur = conn.execute(
                """INSERT INTO snapshots
                   (ts, window_sec, total_bytes, total_packets, active_flows,
                    bytes_per_sec, packets_per_sec)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    snap.get("datetime", datetime.now(timezone.utc).isoformat()),
                    snap.get("window_sec",      1.0),
                    snap.get("total_bytes",       0),
                    snap.get("total_packets",     0),
                    snap.get("active_flows",      0),
                    snap.get("bytes_per_sec",   0.0),
                    snap.get("packets_per_sec", 0.0),
                ),
            )
            snap_id = cur.lastrowid

            # Host traffic
            for h in snap.get("top_hosts", []):
                conn.execute(
                    """INSERT INTO host_traffic
                       (snapshot_id, ip, bytes_sent, bytes_recv, pkts_sent, pkts_recv)
                       VALUES (?,?,?,?,?,?)""",
                    (snap_id, h["ip"], h.get("bytes_sent", 0),
                     h.get("bytes_recv", 0), h.get("pkts_sent", 0), h.get("pkts_recv", 0)),
                )
                # Upsert known_hosts
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """INSERT INTO known_hosts (ip, first_seen, last_seen)
                       VALUES (?, ?, ?)
                       ON CONFLICT(ip) DO UPDATE SET last_seen=excluded.last_seen""",
                    (h["ip"], now, now),
                )

            # Flows
            for f in snap.get("top_flows", []):
                conn.execute(
                    """INSERT INTO flows
                       (snapshot_id, src_ip, dst_ip, src_port, dst_port, proto, bytes, packets)
                       VALUES (?,?,?,?,?,?,?,?)""",
                    (snap_id, f["src_ip"], f["dst_ip"], f.get("src_port"),
                     f.get("dst_port"), f.get("proto"), f.get("bytes", 0), f.get("packets", 0)),
                )

            # Alerts
            ts = snap.get("datetime", datetime.now(timezone.utc).isoformat())
            for a in snap.get("alerts", []):
                conn.execute(
                    """INSERT INTO alerts (ts, type, detail, severity, source)
                       VALUES (?,?,?,?,?)""",
                    (ts, a["type"], a.get("detail", ""), a.get("severity", "low"), "traffic"),
                )

            # Hourly aggregate
            hour = snap.get("datetime", "")[:13]  # "2025-01-15T14"
            bps  = snap.get("bytes_per_sec", 0)
            conn.execute(
                """INSERT INTO bw_hourly (hour, total_bytes, total_pkts, peak_bps, sample_cnt)
                   VALUES (?, ?, ?, ?, 1)
                   ON CONFLICT(hour) DO UPDATE SET
                       total_bytes = total_bytes + excluded.total_bytes,
                       total_pkts  = total_pkts  + excluded.total_pkts,
                       peak_bps    = MAX(peak_bps, excluded.peak_bps),
                       sample_cnt  = sample_cnt  + 1""",
                (hour, snap.get("total_bytes", 0), snap.get("total_packets", 0), bps),
            )

            return snap_id

    def get_bandwidth_history(self, limit: int = 60) -> list[dict]:
        cur = self._conn().execute(
            """SELECT ts, bytes_per_sec as bps, packets_per_sec as pps
               FROM snapshots ORDER BY id DESC LIMIT ?""", (limit,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        rows.reverse()
        return rows

    def get_hourly_history(self, hours: int = 24) -> list[dict]:
        cur = self._conn().execute(
            """SELECT hour, total_bytes, total_pkts, peak_bps, sample_cnt
               FROM bw_hourly ORDER BY hour DESC LIMIT ?""", (hours,)
        )
        rows = [dict(r) for r in cur.fetchall()]
        rows.reverse()
        return rows

    # ── Alerts ────────────────────────────────────────────────────────────

    def get_alerts(self, limit: int = 100, unacked_only: bool = False) -> list[dict]:
        q = "SELECT * FROM alerts"
        if unacked_only:
            q += " WHERE acked=0"
        q += " ORDER BY id DESC LIMIT ?"
        cur = self._conn().execute(q, (limit,))
        return [dict(r) for r in cur.fetchall()]

    def ack_alert(self, alert_id: int) -> None:
        with self.tx() as conn:
            conn.execute("UPDATE alerts SET acked=1 WHERE id=?", (alert_id,))

    def ack_all_alerts(self) -> None:
        with self.tx() as conn:
            conn.execute("UPDATE alerts SET acked=1")

    # ── Known hosts ───────────────────────────────────────────────────────

    def get_known_hosts(self) -> list[dict]:
        cur = self._conn().execute("SELECT * FROM known_hosts ORDER BY last_seen DESC")
        return [dict(r) for r in cur.fetchall()]

    def update_host(self, ip: str, **kwargs) -> None:
        if not kwargs:
            return
        cols  = ", ".join(f"{k}=?" for k in kwargs)
        vals  = list(kwargs.values()) + [ip]
        with self.tx() as conn:
            conn.execute(f"UPDATE known_hosts SET {cols} WHERE ip=?", vals)

    def get_host(self, ip: str) -> Optional[dict]:
        cur = self._conn().execute("SELECT * FROM known_hosts WHERE ip=?", (ip,))
        row = cur.fetchone()
        return dict(row) if row else None

    # ── Nmap ──────────────────────────────────────────────────────────────

    def save_scan(self, result) -> None:
        """Persist a ScanResult (from nmap_scanner.py) to the database."""
        with self.tx() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO nmap_scans
                   (id, scan_type, target, ports_arg, started_at, ended_at,
                    duration_s, host_count, error, raw_command)
                   VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (
                    result.scan_id, result.scan_type, result.target, result.ports_arg,
                    result.started_at, result.ended_at, result.duration_s,
                    len(result.hosts), result.error, result.raw_nmap,
                ),
            )

            for host in result.hosts:
                # Update known_hosts
                now = datetime.now(timezone.utc).isoformat()
                conn.execute(
                    """INSERT INTO known_hosts
                       (ip, hostname, mac, vendor, os_guess, os_accuracy, first_seen, last_seen)
                       VALUES (?,?,?,?,?,?,?,?)
                       ON CONFLICT(ip) DO UPDATE SET
                           hostname    = COALESCE(NULLIF(excluded.hostname,''),    hostname),
                           mac         = COALESCE(NULLIF(excluded.mac,''),         mac),
                           vendor      = COALESCE(NULLIF(excluded.vendor,''),      vendor),
                           os_guess    = COALESCE(NULLIF(excluded.os_guess,''),    os_guess),
                           os_accuracy = MAX(os_accuracy, excluded.os_accuracy),
                           last_seen   = excluded.last_seen""",
                    (host.ip, host.hostname, host.mac, host.vendor,
                     host.os_guess, host.os_accuracy, now, now),
                )

                for p in host.ports:
                    conn.execute(
                        """INSERT INTO nmap_ports
                           (scan_id, ip, port, proto, state, service, version,
                            product, cpe, script_json)
                           VALUES (?,?,?,?,?,?,?,?,?,?)""",
                        (result.scan_id, host.ip, p.port, p.proto, p.state,
                         p.service, p.version, p.product, p.cpe,
                         json.dumps(p.script)),
                    )

                    # Extract vulnerabilities
                    for script_id, output in p.script.items():
                        if "VULNERABLE" in output.upper() or "CVE" in output.upper():
                            import re
                            cves = ",".join(re.findall(r"CVE-\d{4}-\d+", output))
                            severity = "high" if "VULNERABLE" in output.upper() else "medium"
                            conn.execute(
                                """INSERT INTO vulnerabilities
                                   (scan_id, ip, port, proto, script_id, output,
                                    severity, cve, discovered)
                                   VALUES (?,?,?,?,?,?,?,?,?)""",
                                (result.scan_id, host.ip, p.port, p.proto,
                                 script_id, output[:4000], severity, cves, now),
                            )
                            # Also create an alert
                            conn.execute(
                                """INSERT INTO alerts (ts, type, detail, severity, source, extra_json)
                                   VALUES (?,?,?,?,?,?)""",
                                (now, "VULNERABILITY",
                                 f"{host.ip}:{p.port} — {script_id}",
                                 severity, "nmap",
                                 json.dumps({"cve": cves, "scan_id": result.scan_id})),
                            )

    def get_scans(self, limit: int = 50) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM nmap_scans ORDER BY started_at DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_scan_ports(self, scan_id: str) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM nmap_ports WHERE scan_id=? ORDER BY ip, port", (scan_id,)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_vulnerabilities(self, limit: int = 200) -> list[dict]:
        cur = self._conn().execute(
            "SELECT * FROM vulnerabilities ORDER BY discovered DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    # ── Stats ─────────────────────────────────────────────────────────────

    def stats(self) -> dict:
        conn = self._conn()
        def scalar(q, *a):
            return conn.execute(q, a).fetchone()[0] or 0

        return {
            "snapshots":    scalar("SELECT COUNT(*) FROM snapshots"),
            "alerts_total": scalar("SELECT COUNT(*) FROM alerts"),
            "alerts_new":   scalar("SELECT COUNT(*) FROM alerts WHERE acked=0"),
            "known_hosts":  scalar("SELECT COUNT(*) FROM known_hosts"),
            "nmap_scans":   scalar("SELECT COUNT(*) FROM nmap_scans"),
            "vulns":        scalar("SELECT COUNT(*) FROM vulnerabilities"),
            "flows_stored": scalar("SELECT COUNT(*) FROM flows"),
            "db_size_mb":   round(Path(self._path).stat().st_size / 1e6, 2)
                            if Path(self._path).exists() else 0,
        }

    # ── Cleanup ───────────────────────────────────────────────────────────

    def prune(self, keep_days: int = 7) -> None:
        """Delete snapshots older than keep_days (cascades to host_traffic/flows)."""
        cutoff = datetime.now(timezone.utc).isoformat()[:10]  # rough date cutoff
        # Actually compute properly:
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(days=keep_days)).isoformat()
        with self.tx() as conn:
            conn.execute("DELETE FROM snapshots WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM alerts WHERE ts < ? AND acked=1", (cutoff,))
            conn.execute("VACUUM")

    # ── Analytics ─────────────────────────────────────────────────────────

    def get_top_ips(self, hours: int = 24, limit: int = 20) -> list[dict]:
        """Top IPs by total traffic in the last N hours."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        cur = self._conn().execute(
            """SELECT ht.ip,
                      SUM(ht.bytes_sent)  AS total_sent,
                      SUM(ht.bytes_recv)  AS total_recv,
                      SUM(ht.bytes_sent + ht.bytes_recv) AS total_bytes,
                      COUNT(*)            AS samples
               FROM host_traffic ht
               JOIN snapshots s ON s.id = ht.snapshot_id
               WHERE s.ts >= ?
               GROUP BY ht.ip
               ORDER BY total_bytes DESC
               LIMIT ?""", (cutoff, limit)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_top_ports(self, hours: int = 24, limit: int = 20) -> list[dict]:
        """Top destination ports by traffic volume."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        cur = self._conn().execute(
            """SELECT f.dst_port,
                      f.proto,
                      SUM(f.bytes)    AS total_bytes,
                      SUM(f.packets)  AS total_packets,
                      COUNT(*)        AS flow_count
               FROM flows f
               JOIN snapshots s ON s.id = f.snapshot_id
               WHERE s.ts >= ? AND f.dst_port IS NOT NULL
               GROUP BY f.dst_port, f.proto
               ORDER BY total_bytes DESC
               LIMIT ?""", (cutoff, limit)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_alert_timeline(self, hours: int = 24) -> list[dict]:
        """Alerts per hour for the last N hours."""
        from datetime import timedelta
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        cur = self._conn().execute(
            """SELECT substr(ts, 1, 13) AS hour,
                      type,
                      severity,
                      COUNT(*) AS count
               FROM alerts
               WHERE ts >= ?
               GROUP BY hour, type, severity
               ORDER BY hour ASC""", (cutoff,)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_analytics_summary(self) -> dict:
        """Full 24h summary for the analytics dashboard."""
        conn = self._conn()
        from datetime import timedelta
        cutoff_24h = (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()
        cutoff_1h  = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()

        def scalar(q, *a):
            row = conn.execute(q, a).fetchone()
            return (row[0] or 0) if row else 0

        total_bytes_24h  = scalar("SELECT SUM(total_bytes)   FROM snapshots WHERE ts >= ?", cutoff_24h)
        total_pkts_24h   = scalar("SELECT SUM(total_packets) FROM snapshots WHERE ts >= ?", cutoff_24h)
        peak_bps_24h     = scalar("SELECT MAX(bytes_per_sec) FROM snapshots WHERE ts >= ?", cutoff_24h)
        alerts_24h       = scalar("SELECT COUNT(*) FROM alerts WHERE ts >= ?",              cutoff_24h)
        alerts_high_24h  = scalar("SELECT COUNT(*) FROM alerts WHERE ts >= ? AND severity='high'", cutoff_24h)
        unique_hosts_24h = scalar(
            "SELECT COUNT(DISTINCT ip) FROM host_traffic ht JOIN snapshots s ON s.id=ht.snapshot_id WHERE s.ts >= ?",
            cutoff_24h
        )

        return {
            "period_hours":      24,
            "total_bytes":       total_bytes_24h,
            "total_packets":     total_pkts_24h,
            "peak_bps":          peak_bps_24h,
            "alerts_total":      alerts_24h,
            "alerts_high":       alerts_high_24h,
            "unique_hosts":      unique_hosts_24h,
            "top_ips":           self.get_top_ips(hours=24, limit=10),
            "top_ports":         self.get_top_ports(hours=24, limit=10),
            "alert_timeline":    self.get_alert_timeline(hours=24),
            "hourly_bandwidth":  self.get_hourly_history(hours=24),
        }
