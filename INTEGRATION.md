# Suricata IDS Integration Guide

## What is the EVE JSON log?

Suricata writes all events (alerts, flows, DNS, HTTP, TLS, stats) to a
single structured JSON log called **eve.json**. CyberShield tails this file
in real-time and ingests each line as it appears.

Default path: `/var/log/suricata/eve.json`

---

## Installing Suricata

### Ubuntu / Debian
```bash
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update && sudo apt install suricata -y
sudo systemctl enable --now suricata
```

### RHEL / CentOS
```bash
sudo dnf install epel-release -y
sudo dnf install suricata -y
sudo systemctl enable --now suricata
```

### Verify EVE log is active
```bash
tail -f /var/log/suricata/eve.json | python3 -m json.tool
```

---

## Configure EVE JSON output

Edit `/etc/suricata/suricata.yaml`:

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: /var/log/suricata/eve.json
      types:
        - alert:
            payload: yes
            payload-printable: yes
            metadata: yes
        - flow
        - stats:
            totals: yes
            threads: no
        - http
        - dns
        - tls
```

Restart Suricata:
```bash
sudo systemctl restart suricata
```

---

## Updating Suricata Rules

```bash
# Install suricata-update
pip install suricata-update

# Download Emerging Threats Open ruleset (free)
sudo suricata-update

# Update and reload rules without restart
sudo kill -USR2 $(cat /var/run/suricata.pid)
```

---

## Giving the dashboard read access to eve.json

```bash
# Add your app user to the suricata group
sudo usermod -aG suricata $USER

# Or set file permissions directly
sudo chmod 644 /var/log/suricata/eve.json
sudo chmod 755 /var/log/suricata/
```

---

## Running CyberShield in production mode

1. Set `DEMO_MODE=false` in your `.env`
2. Set `SURICATA_EVE_LOG=/var/log/suricata/eve.json`
3. Start the dashboard — it will tail the live log automatically

```bash
DEMO_MODE=false python app.py
```

---

## Example EVE Alert event
```json
{
  "timestamp": "2024-01-15T14:32:01.123456+0000",
  "flow_id": 1234567890123456,
  "in_iface": "eth0",
  "event_type": "alert",
  "src_ip": "185.220.101.47",
  "src_port": 54321,
  "dest_ip": "10.0.1.15",
  "dest_port": 22,
  "proto": "TCP",
  "app_proto": "ssh",
  "alert": {
    "action": "blocked",
    "gid": 1,
    "signature_id": 2001219,
    "rev": 20,
    "signature": "ET SCAN SSH BruteForce Login",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "payload_printable": "SSH-2.0-libssh_0.9.6\r\n"
}
```
