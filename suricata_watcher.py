"""
backend/services/suricata_watcher.py

Tails the Suricata EVE JSON log file in real-time (inotify-style via polling).
In DEMO_MODE it generates realistic synthetic Suricata events so you can run
the dashboard without a live Suricata install.
"""

import json
import os
import time
import random
import threading
from datetime import datetime, timezone
from typing import Optional

from backend.services.threat_engine import ThreatEngine
from backend.utils.geoip import resolve_country
from backend.utils.parsers import parse_eve_event


# ── Synthetic event templates (mirrors real Suricata EVE schema) ──────────────

_ATTACK_IPS = [
    ("185.220.101.47", "CN"), ("91.108.4.29", "RU"), ("177.66.10.184", "BR"),
    ("45.142.212.100", "IR"), ("203.0.113.55", "KP"), ("194.165.16.11", "UA"),
    ("196.251.81.200", "NG"), ("80.82.77.139", "NL"), ("89.248.167.131", "DE"),
    ("104.244.73.13", "US"), ("112.85.42.100", "CN"), ("5.188.86.22", "RU"),
]

_ALERT_TEMPLATES = [
    {"signature": "ET SCAN Nmap Scripting Engine User-Agent", "category": "Web Application Attack",     "severity": 2, "proto": "TCP",  "dest_port": 80},
    {"signature": "ET EXPLOIT Apache Log4Shell CVE-2021-44228",   "category": "Attempted Administrator Privilege Gain", "severity": 1, "proto": "TCP",  "dest_port": 443},
    {"signature": "ET SCAN SSH BruteForce Login",                  "category": "Attempted Information Leak",            "severity": 2, "proto": "TCP",  "dest_port": 22},
    {"signature": "ET SQL MySQL SELECT Statement in URI",          "category": "Web Application Attack",                "severity": 2, "proto": "TCP",  "dest_port": 3306},
    {"signature": "ET DOS Potential DDoS TCP Flood",               "category": "Denial of Service Attack",             "severity": 1, "proto": "TCP",  "dest_port": 443},
    {"signature": "ET MALWARE Metasploit Meterpreter Reverse Shell","category": "A Network Trojan was Detected",        "severity": 1, "proto": "TCP",  "dest_port": 4444},
    {"signature": "ET POLICY Cleartext Password over HTTP",        "category": "Policy Violation",                     "severity": 3, "proto": "TCP",  "dest_port": 80},
    {"signature": "ET SCAN Nessus Vulnerability Scanner",          "category": "Network Scan",                         "severity": 3, "proto": "TCP",  "dest_port": 0},
    {"signature": "ET TROJAN Known Malicious Bot C2 Communication","category": "Trojan Activity",                      "severity": 1, "proto": "TCP",  "dest_port": 8080},
    {"signature": "ET DNS Suspicious DNS Query for TOR Hidden Service","category": "Potentially Bad Traffic",          "severity": 3, "proto": "UDP",  "dest_port": 53},
    {"signature": "ET FTP Bruteforce Login Attempt",               "category": "Attempted Information Leak",           "severity": 2, "proto": "TCP",  "dest_port": 21},
    {"signature": "ET INFO RDP Connection Attempt",                "category": "Potentially Bad Traffic",              "severity": 3, "proto": "TCP",  "dest_port": 3389},
]

_FLOW_PROTOS = ["TCP", "UDP", "ICMP", "HTTP", "DNS", "TLS", "SMB"]
_INTERNAL_HOSTS = [f"10.0.{s}.{h}" for s in range(0, 5) for h in range(1, 20)]


def _make_demo_alert() -> dict:
    tpl = random.choice(_ALERT_TEMPLATES)
    src_ip, country = random.choice(_ATTACK_IPS)
    dest_ip = random.choice(_INTERNAL_HOSTS)
    dest_port = tpl["dest_port"] if tpl["dest_port"] else random.choice([80, 443, 22, 3306, 21])
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    sid = random.randint(2000000, 2099999)
    return {
        "timestamp": now,
        "event_type": "alert",
        "src_ip": src_ip,
        "src_port": random.randint(1024, 65535),
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "proto": tpl["proto"],
        "_country": country,
        "alert": {
            "action": "blocked",
            "gid": 1,
            "signature_id": sid,
            "rev": 1,
            "signature": tpl["signature"],
            "category": tpl["category"],
            "severity": tpl["severity"],
        },
        "flow_id": random.randint(10**15, 10**16),
        "in_iface": "eth0",
        "app_proto": tpl["proto"].lower(),
        "payload_printable": "",
        "http": {},
        "dns": {},
    }


def _make_demo_stats() -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    return {
        "timestamp": now,
        "event_type": "stats",
        "stats": {
            "decoder": {
                "pkts": random.randint(130000, 160000),
                "bytes": random.randint(150_000_000, 200_000_000),
            },
            "detect": {
                "alert": random.randint(10, 60),
            },
            "flow": {
                "tcp": random.randint(2000, 5000),
                "udp": random.randint(500, 2000),
                "icmp": random.randint(10, 100),
            },
        },
    }


def _make_demo_flow() -> dict:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
    src_ip = f"{random.randint(1,254)}.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(1,254)}"
    dest_ip = random.choice(_INTERNAL_HOSTS)
    return {
        "timestamp": now,
        "event_type": "flow",
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": random.randint(1024, 65535),
        "dest_port": random.choice([80, 443, 22, 53, 3306, 8080]),
        "proto": random.choice(_FLOW_PROTOS),
        "flow": {
            "pkts_toserver": random.randint(1, 500),
            "pkts_toclient": random.randint(1, 500),
            "bytes_toserver": random.randint(100, 500000),
            "bytes_toclient": random.randint(100, 500000),
            "start": now,
            "end": now,
            "state": "closed",
            "reason": "timeout",
        },
    }


# ── Watcher ───────────────────────────────────────────────────────────────────

class SuricataWatcher:
    """
    Watches the Suricata EVE JSON log for new events and pushes them to the
    ThreatEngine + broadcasts via SocketIO.

    Real mode  : tails /var/log/suricata/eve.json line-by-line
    Demo mode  : generates synthetic events at DEMO_EVENT_INTERVAL seconds
    """

    def __init__(self, eve_log_path: str, threat_engine: ThreatEngine, socketio):
        self.eve_log_path = eve_log_path
        self.threat_engine = threat_engine
        self.socketio = socketio
        self._stop = threading.Event()

    def stop(self):
        self._stop.set()

    def watch(self):
        demo = not os.path.exists(self.eve_log_path)
        if demo:
            print(f"[Watcher] EVE log not found at {self.eve_log_path} — running in DEMO mode")
            self._demo_loop()
        else:
            print(f"[Watcher] Tailing {self.eve_log_path}")
            self._tail_loop()

    # ── Real log tailing ──────────────────────────────────────────────────────

    def _tail_loop(self):
        with open(self.eve_log_path, "r") as f:
            f.seek(0, 2)  # seek to end
            while not self._stop.is_set():
                line = f.readline()
                if line:
                    self._process_line(line.strip())
                else:
                    time.sleep(0.05)

    def _process_line(self, line: str):
        if not line:
            return
        try:
            raw = json.loads(line)
        except json.JSONDecodeError:
            return
        # Enrich with GeoIP
        src_ip = raw.get("src_ip", "")
        raw["_country"] = resolve_country(src_ip)
        event = parse_eve_event(raw)
        if event:
            self._dispatch(event, raw)

    # ── Demo synthetic loop ───────────────────────────────────────────────────

    def _demo_loop(self):
        tick = 0
        while not self._stop.is_set():
            tick += 1
            # Alerts most frequent
            if random.random() < 0.55:
                raw = _make_demo_alert()
                event = parse_eve_event(raw)
                if event:
                    self._dispatch(event, raw)

            # Stats every ~10 ticks
            if tick % 10 == 0:
                raw = _make_demo_stats()
                event = parse_eve_event(raw)
                if event:
                    self._dispatch(event, raw)

            # Flows occasionally
            if random.random() < 0.3:
                raw = _make_demo_flow()
                event = parse_eve_event(raw)
                if event:
                    self._dispatch(event, raw)

            time.sleep(1.5)

    # ── Dispatch ──────────────────────────────────────────────────────────────

    def _dispatch(self, event: dict, raw: dict):
        """Push to ThreatEngine and broadcast via WebSocket."""
        self.threat_engine.ingest(event)
        # Emit specific event type to front-end
        self.socketio.emit(event["event_type"], event)
        # Always emit updated summary
        self.socketio.emit("summary", self.threat_engine.get_summary())
