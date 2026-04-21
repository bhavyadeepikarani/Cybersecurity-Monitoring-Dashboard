"""
backend/services/threat_engine.py

In-memory threat correlation engine.
Tracks alerts, flows, stats, anomalies, top attackers, port hit-counts,
protocol distribution, and rolling traffic timeseries.
"""

import threading
from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Any


SEVERITY_MAP = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
SEVERITY_COLOR = {"CRITICAL": "#ff4444", "HIGH": "#ffaa00", "MEDIUM": "#4499ff", "LOW": "#00ff88"}


class ThreatEngine:
    """Thread-safe in-memory state store for all security events."""

    def __init__(self, max_alerts: int = 500, traffic_buckets: int = 60):
        self._lock = threading.Lock()

        # Alert store (ring buffer)
        self._alerts: deque = deque(maxlen=max_alerts)

        # Counters
        self._total_blocked = 0
        self._packets_per_sec = 0
        self._bytes_per_sec = 0
        self._active_sessions = 0

        # Top attackers: src_ip → hit count
        self._attacker_counts: dict = defaultdict(int)

        # Country → hit count
        self._country_counts: dict = defaultdict(int)

        # Port → hit count
        self._port_counts: dict = defaultdict(int)

        # Protocol distribution
        self._proto_counts: dict = defaultdict(int)

        # Signature → hit count (top rules)
        self._sig_counts: dict = defaultdict(int)

        # Traffic timeseries: each bucket = {in, out, blocked}
        self._traffic_series: deque = deque(
            [{"in": 0, "out": 0, "blocked": 0} for _ in range(traffic_buckets)],
            maxlen=traffic_buckets,
        )
        self._current_bucket: dict = {"in": 0, "out": 0, "blocked": 0}

        # Anomaly score (0-100)
        self._anomaly_score = 0
        self._anomaly_notes: list = []

    # ── Ingestion ─────────────────────────────────────────────────────────────

    def ingest(self, event: dict):
        etype = event.get("event_type")
        with self._lock:
            if etype == "alert":
                self._handle_alert(event)
            elif etype == "stats":
                self._handle_stats(event)
            elif etype == "flow":
                self._handle_flow(event)
            self._recalculate_anomaly_score()

    def _handle_alert(self, ev: dict):
        self._alerts.appendleft(ev)
        self._total_blocked += 1

        src = ev.get("src_ip", "")
        country = ev.get("country", "Unknown")
        dest_port = ev.get("dest_port", 0)
        proto = ev.get("proto", "TCP")
        sig = ev.get("signature", "")

        self._attacker_counts[src] += 1
        self._country_counts[country] += 1
        self._port_counts[str(dest_port)] += 1
        self._proto_counts[proto] += 1
        self._sig_counts[sig] += 1

        # Traffic bucket
        self._current_bucket["blocked"] += 1
        self._traffic_series[-1]["blocked"] = self._current_bucket["blocked"]

    def _handle_stats(self, ev: dict):
        stats = ev.get("stats", {})
        decoder = stats.get("decoder", {})
        flow = stats.get("flow", {})

        self._packets_per_sec = decoder.get("pkts", self._packets_per_sec)
        self._bytes_per_sec = decoder.get("bytes", self._bytes_per_sec)
        self._active_sessions = (
            flow.get("tcp", 0) + flow.get("udp", 0) + flow.get("icmp", 0)
        )
        in_val = decoder.get("pkts", 0)
        out_val = int(in_val * 0.7)
        self._traffic_series.append({"in": in_val, "out": out_val, "blocked": 0})
        self._current_bucket = {"in": in_val, "out": out_val, "blocked": 0}

    def _handle_flow(self, ev: dict):
        proto = ev.get("proto", "TCP")
        self._proto_counts[proto] += 1

    # ── Anomaly scoring ───────────────────────────────────────────────────────

    def _recalculate_anomaly_score(self):
        score = 0
        notes = []

        # Recent alert rate (last 5 buckets)
        recent_blocked = sum(b["blocked"] for b in list(self._traffic_series)[-5:])
        if recent_blocked > 50:
            score += 40
            notes.append(f"High block rate: {recent_blocked} in last 5 sec")
        elif recent_blocked > 20:
            score += 20

        # Critical alerts
        critical_count = sum(
            1 for a in list(self._alerts)[:20] if a.get("severity_label") == "CRITICAL"
        )
        score += min(critical_count * 8, 40)
        if critical_count:
            notes.append(f"{critical_count} CRITICAL alerts in last 20 events")

        # Top attacker repeat hits
        if self._attacker_counts:
            top_hits = max(self._attacker_counts.values())
            if top_hits > 100:
                score += 20
                notes.append(f"Single IP with {top_hits}+ hits detected")

        self._anomaly_score = min(score, 100)
        self._anomaly_notes = notes[:3]

    # ── Public API ────────────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        with self._lock:
            top_attackers = sorted(
                self._attacker_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]
            top_ports = sorted(
                self._port_counts.items(), key=lambda x: x[1], reverse=True
            )[:8]
            top_countries = sorted(
                self._country_counts.items(), key=lambda x: x[1], reverse=True
            )[:8]
            top_protos = dict(
                sorted(self._proto_counts.items(), key=lambda x: x[1], reverse=True)[:6]
            )
            top_sigs = sorted(
                self._sig_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            bandwidth_gbps = round(self._bytes_per_sec / 1e9, 2)

            return {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "metrics": {
                    "packets_per_sec": self._packets_per_sec,
                    "threats_blocked": self._total_blocked,
                    "active_sessions": self._active_sessions,
                    "bandwidth_gbps": bandwidth_gbps,
                    "anomaly_score": self._anomaly_score,
                    "anomaly_notes": self._anomaly_notes,
                },
                "top_attackers": [
                    {"ip": ip, "hits": hits} for ip, hits in top_attackers
                ],
                "top_ports": [
                    {"port": port, "hits": hits} for port, hits in top_ports
                ],
                "top_countries": [
                    {"country": cc, "hits": hits} for cc, hits in top_countries
                ],
                "proto_distribution": top_protos,
                "top_signatures": [
                    {"signature": sig, "hits": hits} for sig, hits in top_sigs
                ],
                "traffic_series": list(self._traffic_series),
            }

    def get_snapshot(self) -> dict:
        """Full snapshot including recent alert list."""
        summary = self.get_summary()
        with self._lock:
            summary["recent_alerts"] = list(self._alerts)[:50]
        return summary

    def get_alert(self, alert_id: str) -> dict | None:
        with self._lock:
            for alert in self._alerts:
                if str(alert.get("id")) == alert_id:
                    return alert
        return None

    def get_alerts(self, page: int = 1, per_page: int = 25,
                   severity: str = None, src_ip: str = None) -> dict:
        with self._lock:
            alerts = list(self._alerts)

        if severity:
            alerts = [a for a in alerts if a.get("severity_label", "").upper() == severity.upper()]
        if src_ip:
            alerts = [a for a in alerts if a.get("src_ip") == src_ip]

        total = len(alerts)
        start = (page - 1) * per_page
        end = start + per_page

        return {
            "total": total,
            "page": page,
            "per_page": per_page,
            "alerts": alerts[start:end],
        }
