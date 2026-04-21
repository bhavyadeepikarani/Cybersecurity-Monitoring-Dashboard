"""
CyberShield — Production Cybersecurity Monitoring Dashboard
Backend: Python 3.11+ / Flask / Flask-SocketIO
Data Source: Suricata IDS EVE JSON log
"""

import os
import threading
from flask import Flask
from flask_socketio import SocketIO
from flask_cors import CORS

from backend.routes.api import api_bp
from backend.routes.dashboard import dashboard_bp
from backend.services.suricata_watcher import SuricataWatcher
from backend.services.threat_engine import ThreatEngine
from config.settings import Config

# ── App factory ───────────────────────────────────────────────────────────────

def create_app(config_class=Config):
    app = Flask(
        __name__,
        template_folder="frontend/templates",
        static_folder="frontend/static",
    )
    app.config.from_object(config_class)

    CORS(app, resources={r"/api/*": {"origins": "*"}})
    socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

    # Register blueprints
    app.register_blueprint(api_bp, url_prefix="/api/v1")
    app.register_blueprint(dashboard_bp)

    # Attach shared services to app context
    app.threat_engine = ThreatEngine()
    app.socketio = socketio

    # Start Suricata log watcher in a background thread
    watcher = SuricataWatcher(
        eve_log_path=app.config["SURICATA_EVE_LOG"],
        threat_engine=app.threat_engine,
        socketio=socketio,
    )
    watcher_thread = threading.Thread(target=watcher.watch, daemon=True)
    watcher_thread.start()

    return app, socketio


app, socketio = create_app()


# ── WebSocket events ───────────────────────────────────────────────────────────

@socketio.on("connect")
def handle_connect():
    print("[WS] Client connected")
    # Push initial state snapshot on connect
    socketio.emit("snapshot", app.threat_engine.get_snapshot())


@socketio.on("disconnect")
def handle_disconnect():
    print("[WS] Client disconnected")


@socketio.on("request_snapshot")
def handle_snapshot_request():
    socketio.emit("snapshot", app.threat_engine.get_snapshot())


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    print(f"[CyberShield] Starting on http://0.0.0.0:{port}")
    socketio.run(app, host="0.0.0.0", port=port, debug=debug)
