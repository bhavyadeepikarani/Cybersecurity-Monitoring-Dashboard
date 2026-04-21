"""
backend/routes/api.py

REST API endpoints for the CyberShield dashboard.

Base path: /api/v1
"""

from flask import Blueprint, current_app, jsonify, request

api_bp = Blueprint("api", __name__)


# ── Health ─────────────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "service": "CyberShield API v1"})


# ── Summary ───────────────────────────────────────────────────────────────────

@api_bp.route("/summary", methods=["GET"])
def summary():
    """
    Returns the current live summary: metrics, top attackers,
    top ports, proto distribution, traffic timeseries.
    """
    data = current_app.threat_engine.get_summary()
    return jsonify(data)


# ── Snapshot ──────────────────────────────────────────────────────────────────

@api_bp.route("/snapshot", methods=["GET"])
def snapshot():
    """Full snapshot including last 50 alerts."""
    data = current_app.threat_engine.get_snapshot()
    return jsonify(data)


# ── Alerts ────────────────────────────────────────────────────────────────────

@api_bp.route("/alerts", methods=["GET"])
def list_alerts():
    """
    Paginated alert list.

    Query params:
      page       (int, default 1)
      per_page   (int, default 25, max 100)
      severity   (CRITICAL|HIGH|MEDIUM|LOW)
      src_ip     (filter by source IP)
    """
    page = int(request.args.get("page", 1))
    per_page = min(int(request.args.get("per_page", 25)), 100)
    severity = request.args.get("severity")
    src_ip = request.args.get("src_ip")

    result = current_app.threat_engine.get_alerts(
        page=page, per_page=per_page, severity=severity, src_ip=src_ip
    )
    return jsonify(result)


@api_bp.route("/alerts/<alert_id>", methods=["GET"])
def get_alert(alert_id: str):
    """
    Drill-down: full detail for a single alert by its UUID.
    """
    alert = current_app.threat_engine.get_alert(alert_id)
    if not alert:
        return jsonify({"error": "Alert not found"}), 404
    return jsonify(alert)


# ── Top attackers ─────────────────────────────────────────────────────────────

@api_bp.route("/attackers", methods=["GET"])
def top_attackers():
    data = current_app.threat_engine.get_summary()
    return jsonify(data["top_attackers"])


# ── Traffic series ────────────────────────────────────────────────────────────

@api_bp.route("/traffic", methods=["GET"])
def traffic_series():
    data = current_app.threat_engine.get_summary()
    return jsonify(data["traffic_series"])


# ── Ports ─────────────────────────────────────────────────────────────────────

@api_bp.route("/ports", methods=["GET"])
def top_ports():
    data = current_app.threat_engine.get_summary()
    return jsonify(data["top_ports"])


# ── Countries ─────────────────────────────────────────────────────────────────

@api_bp.route("/countries", methods=["GET"])
def top_countries():
    data = current_app.threat_engine.get_summary()
    return jsonify(data["top_countries"])


# ── Signatures ────────────────────────────────────────────────────────────────

@api_bp.route("/signatures", methods=["GET"])
def top_signatures():
    data = current_app.threat_engine.get_summary()
    return jsonify(data["top_signatures"])
