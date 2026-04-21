# CyberShield — Real-Time Cybersecurity Monitoring Dashboard

A production-ready SOC (Security Operations Center) dashboard powered by
**Python Flask + Flask-SocketIO**, connected live to **Suricata IDS** via
EVE JSON log tailing. Includes full REST API, WebSocket push, drill-down
threat panels, and a built-in DEMO mode that generates realistic synthetic
events so you can run the dashboard without a Suricata install.

---

## Features

| Feature | Details |
|---|---|
| **Live metrics** | Packets/sec, threats blocked, active sessions, bandwidth, anomaly score |
| **Traffic chart** | Rolling 60-second inbound/outbound/blocked timeseries |
| **Alert feed** | Real-time table of Suricata alerts with severity badges |
| **Drill-down panel** | Click any alert → full detail: IPs, ports, payload, HTTP/DNS/TLS context, actions |
| **Geographic map** | Attack origin countries with animated connection lines |
| **Port & protocol charts** | Top attacked ports + protocol distribution donut |
| **Top signatures** | Most-triggered Suricata rule signatures with bar charts |
| **Anomaly engine** | In-memory correlation scoring (0–100) with notes |
| **Live log stream** | Auto-scrolling event log with CRIT/WARN/INFO levels |
| **WebSocket push** | Sub-second event delivery via Flask-SocketIO |
| **REST API** | Full `/api/v1/` endpoints for external integrations |
| **Demo mode** | Synthetic Suricata events — no IDS required to run |

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/yourorg/cybershield.git
cd cybershield
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Configure

```bash
cp .env.example .env
# Edit .env as needed — DEMO_MODE=true works out of the box
```

### 3. Run

```bash
python app.py
# Open http://localhost:5000
```

---

## Connecting to Real Suricata IDS

1. Install Suricata (see `suricata/INTEGRATION.md`)
2. Ensure EVE JSON output is enabled in `/etc/suricata/suricata.yaml`
3. Update your `.env`:
   ```
   DEMO_MODE=false
   SURICATA_EVE_LOG=/var/log/suricata/eve.json
   ```
4. Restart the dashboard

---

## REST API Reference

| Method | Endpoint | Description |
|---|---|---|
| GET | `/api/v1/health` | Service health check |
| GET | `/api/v1/summary` | Current metrics + timeseries + top lists |
| GET | `/api/v1/snapshot` | Full snapshot including last 50 alerts |
| GET | `/api/v1/alerts` | Paginated alerts (`?page=1&per_page=25&severity=CRITICAL&src_ip=x.x.x.x`) |
| GET | `/api/v1/alerts/<id>` | Single alert detail by UUID |
| GET | `/api/v1/attackers` | Top attacker IPs |
| GET | `/api/v1/traffic` | Traffic timeseries (60 buckets) |
| GET | `/api/v1/ports` | Top attacked ports |
| GET | `/api/v1/countries` | Top attack-origin countries |
| GET | `/api/v1/signatures` | Top triggered Suricata signatures |

---

## WebSocket Events

| Event | Direction | Payload |
|---|---|---|
| `connect` | Client → Server | — |
| `snapshot` | Server → Client | Full state snapshot |
| `summary` | Server → Client | Metrics + timeseries (every ~1.5s) |
| `alert` | Server → Client | Single parsed Suricata alert |
| `stats` | Server → Client | Suricata stats update |
| `flow` | Server → Client | Flow event |
| `request_snapshot` | Client → Server | Triggers fresh snapshot emit |

---

## Project Structure

```
cybershield/
├── app.py                          # Flask app factory + SocketIO events
├── requirements.txt
├── .env.example
├── config/
│   └── settings.py                 # All configuration (env-driven)
├── backend/
│   ├── routes/
│   │   ├── api.py                  # REST API blueprints
│   │   └── dashboard.py            # HTML page route
│   ├── services/
│   │   ├── suricata_watcher.py     # EVE JSON log tailer + demo generator
│   │   └── threat_engine.py        # In-memory analytics + anomaly scoring
│   └── utils/
│       ├── parsers.py              # EVE JSON → internal schema
│       └── geoip.py                # IP → country resolution
├── frontend/
│   └── templates/
│       └── dashboard.html          # Full production dashboard (HTML/JS/CSS)
└── suricata/
    └── INTEGRATION.md              # Suricata install + config guide
```

---

## Production Deployment

```bash
# Install gunicorn + eventlet for async WebSocket support
pip install gunicorn eventlet

# Run with gunicorn
gunicorn --worker-class eventlet -w 1 --bind 0.0.0.0:5000 app:app
```

For Nginx reverse proxy, add to your server block:
```nginx
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header Host $host;
}
```

---

## Optional: MaxMind GeoIP

For accurate country resolution:
1. Register at https://dev.maxmind.com (free)
2. Download `GeoLite2-City.mmdb`
3. `pip install geoip2`
4. Set `GEOIP_DB_PATH=/path/to/GeoLite2-City.mmdb` in `.env`
