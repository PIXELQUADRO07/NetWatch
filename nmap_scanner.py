"""
nmap_scanner.py – NetWatch Nmap integration
Wraps python-nmap to expose all major scan types with async execution,
result normalization, and SQLite persistence integration.

Requirements:
    pip install python-nmap
    sudo apt install nmap   (or brew install nmap)

Most scan types require root/sudo.
"""

from __future__ import annotations

import ipaddress
import json
import subprocess
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Callable, Optional
import nmap


# ─── Scan type catalogue ─────────────────────────────────────────────────────

class ScanType(str, Enum):
    # ── Discovery ──────────────────────────────────────────────────────────
    PING          = "ping"           # -sn  — host discovery only, no port scan
    ARP           = "arp"            # -PR  — ARP ping (LAN only, very fast)
    # ── Port scans ─────────────────────────────────────────────────────────
    SYN           = "syn"            # -sS  — stealth SYN scan (root)
    TCP_CONNECT   = "tcp_connect"    # -sT  — full TCP connect (no root)
    UDP           = "udp"            # -sU  — UDP scan (slow, root)
    ACK           = "ack"            # -sA  — ACK scan (firewall mapping, root)
    WINDOW        = "window"         # -sW  — Window scan (root)
    MAIMON        = "maimon"         # -sM  — Maimon scan (FIN/ACK, root)
    NULL          = "null"           # -sN  — NULL scan (root)
    FIN           = "fin"            # -sF  — FIN scan (root)
    XMAS          = "xmas"           # -sX  — Xmas scan (root)
    SCTP_INIT     = "sctp_init"      # -sY  — SCTP INIT scan (root)
    SCTP_COOKIE   = "sctp_cookie"    # -sZ  — SCTP COOKIE-ECHO scan (root)
    IP_PROTO      = "ip_proto"       # -sO  — IP protocol scan
    # ── Version & OS ───────────────────────────────────────────────────────
    VERSION       = "version"        # -sV  — service version detection
    OS_DETECT     = "os_detect"      # -O   — OS fingerprinting (root)
    AGGRESSIVE    = "aggressive"     # -A   — OS + version + scripts + traceroute
    # ── Script scans ───────────────────────────────────────────────────────
    VULN          = "vuln"           # --script vuln
    AUTH          = "auth"           # --script auth
    DISCOVERY_SCR = "discovery_scr"  # --script discovery
    SAFE          = "safe"           # --script safe
    DEFAULT_SCR   = "default_scr"    # --script default  (-sC)
    BROADCAST     = "broadcast"      # --script broadcast (find hosts/services on LAN)
    # ── Timing / evasion ───────────────────────────────────────────────────
    SLOW_COMP     = "slow_comp"      # -T0 -sS — paranoid/slow, IDS evasion
    FAST          = "fast"           # -T4 -F  — fast top-100 ports


# Map each ScanType → nmap CLI arguments
SCAN_ARGS: dict[ScanType, str] = {
    ScanType.PING:          "-sn",
    ScanType.ARP:           "-sn -PR",
    ScanType.SYN:           "-sS",
    ScanType.TCP_CONNECT:   "-sT",
    ScanType.UDP:           "-sU --top-ports 100",
    ScanType.ACK:           "-sA",
    ScanType.WINDOW:        "-sW",
    ScanType.MAIMON:        "-sM",
    ScanType.NULL:          "-sN",
    ScanType.FIN:           "-sF",
    ScanType.XMAS:          "-sX",
    ScanType.SCTP_INIT:     "-sY",
    ScanType.SCTP_COOKIE:   "-sZ",
    ScanType.IP_PROTO:      "-sO",
    ScanType.VERSION:       "-sV --version-intensity 5",
    ScanType.OS_DETECT:     "-O --osscan-guess",
    ScanType.AGGRESSIVE:    "-A",
    ScanType.VULN:          "-sV --script vuln",
    ScanType.AUTH:          "--script auth",
    ScanType.DISCOVERY_SCR: "--script discovery",
    ScanType.SAFE:          "--script safe",
    ScanType.DEFAULT_SCR:   "-sC",
    ScanType.BROADCAST:     "--script broadcast -e eth0",  # override -e as needed
    ScanType.SLOW_COMP:     "-T0 -sS",
    ScanType.FAST:          "-T4 -F",
}

NEEDS_ROOT = {
    ScanType.ARP, ScanType.SYN, ScanType.UDP, ScanType.ACK, ScanType.WINDOW,
    ScanType.MAIMON, ScanType.NULL, ScanType.FIN, ScanType.XMAS,
    ScanType.SCTP_INIT, ScanType.SCTP_COOKIE, ScanType.OS_DETECT,
    ScanType.AGGRESSIVE, ScanType.VULN, ScanType.SLOW_COMP,
}


# ─── Result data classes ─────────────────────────────────────────────────────

@dataclass
class PortResult:
    port:     int
    proto:    str          # tcp / udp / sctp
    state:    str          # open / closed / filtered / open|filtered
    service:  str = ""
    version:  str = ""
    product:  str = ""
    cpe:      str = ""
    script:   dict = field(default_factory=dict)  # script id → output


@dataclass
class HostResult:
    ip:          str
    hostname:    str = ""
    state:       str = "up"   # up / down
    os_guess:    str = ""
    os_accuracy: int = 0
    mac:         str = ""
    vendor:      str = ""
    ports:       list[PortResult] = field(default_factory=list)
    scripts:     dict = field(default_factory=dict)  # host-level scripts


@dataclass
class ScanResult:
    scan_id:    str
    scan_type:  str
    target:     str
    ports_arg:  str
    started_at: str
    ended_at:   str = ""
    duration_s: float = 0.0
    hosts:      list[HostResult] = field(default_factory=list)
    error:      str = ""
    raw_nmap:   str = ""        # full nmap command-line summary


# ─── Scanner ─────────────────────────────────────────────────────────────────

class NmapScanner:
    """
    High-level async Nmap wrapper.

    Usage:
        scanner = NmapScanner(on_complete=my_callback)
        job_id = scanner.submit(ScanType.SYN, "192.168.1.0/24")
        # … callback fires when done
        result = scanner.get_result(job_id)
    """

    def __init__(self, on_complete: Optional[Callable[[ScanResult], None]] = None):
        self._nm        = nmap.PortScanner()
        self._lock      = threading.Lock()
        self._results:  dict[str, ScanResult] = {}
        self._running:  set[str] = set()
        self._on_complete = on_complete
        self._counter   = 0

    # ── Public API ────────────────────────────────────────────────────────

    def submit(
        self,
        scan_type:  ScanType,
        target:     str,
        ports:      str = "1-1024",
        extra_args: str = "",
    ) -> str:
        """Queue a scan and return its job_id (runs in a background thread)."""
        with self._lock:
            self._counter += 1
            job_id = f"scan_{self._counter:04d}"

        t = threading.Thread(
            target=self._run,
            args=(job_id, scan_type, target, ports, extra_args),
            daemon=True,
        )
        with self._lock:
            self._running.add(job_id)
        t.start()
        return job_id

    def get_result(self, job_id: str) -> Optional[ScanResult]:
        with self._lock:
            return self._results.get(job_id)

    def is_running(self, job_id: str) -> bool:
        with self._lock:
            return job_id in self._running

    def list_results(self) -> list[ScanResult]:
        with self._lock:
            return list(self._results.values())

    # ── Internal ──────────────────────────────────────────────────────────

    def _run(self, job_id: str, scan_type: ScanType, target: str, ports: str, extra_args: str):
        started = datetime.now(timezone.utc)
        args    = SCAN_ARGS.get(scan_type, "-sT")
        if extra_args:
            args += " " + extra_args

        result = ScanResult(
            scan_id    = job_id,
            scan_type  = scan_type.value,
            target     = target,
            ports_arg  = ports,
            started_at = started.isoformat(),
        )

        try:
            nm = nmap.PortScanner()

            # ping/arp/broadcast don't use port argument
            no_port_types = {
                ScanType.PING, ScanType.ARP, ScanType.BROADCAST,
                ScanType.DISCOVERY_SCR, ScanType.SAFE,
            }
            if scan_type in no_port_types:
                nm.scan(hosts=target, arguments=args)
            else:
                nm.scan(hosts=target, ports=ports, arguments=args)

            result.raw_nmap = nm.command_line()
            result.hosts    = self._parse_hosts(nm)

        except nmap.PortScannerError as e:
            result.error = str(e)
        except Exception as e:
            result.error = f"Unexpected error: {e}"

        ended          = datetime.now(timezone.utc)
        result.ended_at   = ended.isoformat()
        result.duration_s = (ended - started).total_seconds()

        with self._lock:
            self._results[job_id] = result
            self._running.discard(job_id)

        if self._on_complete:
            try:
                self._on_complete(result)
            except Exception:
                pass

    @staticmethod
    def _parse_hosts(nm: nmap.PortScanner) -> list[HostResult]:
        hosts = []
        for ip in nm.all_hosts():
            h    = nm[ip]
            host = HostResult(
                ip       = ip,
                hostname = h.hostname() or "",
                state    = h.state(),
            )

            # MAC / vendor
            if "addresses" in h:
                host.mac    = h["addresses"].get("mac", "")
            if "vendor" in h and host.mac:
                host.vendor = h["vendor"].get(host.mac, "")

            # OS detection
            if "osmatch" in h and h["osmatch"]:
                best        = h["osmatch"][0]
                host.os_guess    = best.get("name", "")
                host.os_accuracy = int(best.get("accuracy", 0))

            # Host-level scripts
            if "hostscript" in h:
                for s in h["hostscript"]:
                    host.scripts[s["id"]] = s["output"]

            # Ports
            for proto in h.all_protocols():
                for port_num in sorted(h[proto].keys()):
                    pd = h[proto][port_num]
                    pr = PortResult(
                        port    = port_num,
                        proto   = proto,
                        state   = pd.get("state",   ""),
                        service = pd.get("name",    ""),
                        version = pd.get("version", ""),
                        product = pd.get("product", ""),
                        cpe     = pd.get("cpe",     ""),
                    )
                    # Port scripts (vuln, auth, etc.)
                    if "script" in pd:
                        pr.script = dict(pd["script"])
                    host.ports.append(pr)

            hosts.append(host)
        return hosts


# ─── Scheduler for periodic scans ────────────────────────────────────────────

class ScanScheduler:
    """Run recurring scans on a fixed interval."""

    def __init__(self, scanner: NmapScanner):
        self._scanner  = scanner
        self._jobs:    list[dict] = []
        self._thread:  Optional[threading.Thread] = None
        self._running  = False

    def add(self, scan_type: ScanType, target: str, ports: str = "1-1024",
            interval_s: int = 300) -> None:
        self._jobs.append({
            "scan_type":  scan_type,
            "target":     target,
            "ports":      ports,
            "interval_s": interval_s,
            "next_run":   time.time(),
        })

    def start(self) -> None:
        self._running = True
        self._thread  = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._running = False

    def _loop(self) -> None:
        while self._running:
            now = time.time()
            for job in self._jobs:
                if now >= job["next_run"]:
                    self._scanner.submit(job["scan_type"], job["target"], job["ports"])
                    job["next_run"] = now + job["interval_s"]
            time.sleep(5)


# ─── Convenience: detect local subnet ────────────────────────────────────────

def local_subnet(interface: str = "") -> str:
    """Return the local subnet in CIDR notation, e.g. '192.168.1.0/24'."""
    try:
        import socket, struct, fcntl
        SIOCGIFADDR    = 0x8915
        SIOCGIFNETMASK = 0x891b
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        iface = interface.encode() or b"eth0"

        ip_bytes   = fcntl.ioctl(s, SIOCGIFADDR,    b'\x00' * 32)
        mask_bytes = fcntl.ioctl(s, SIOCGIFNETMASK, b'\x00' * 32)

        ip   = socket.inet_ntoa(ip_bytes[20:24])
        mask = socket.inet_ntoa(mask_bytes[20:24])

        network = ipaddress.IPv4Network(f"{ip}/{mask}", strict=False)
        return str(network)
    except Exception:
        return "192.168.1.0/24"  # safe fallback
