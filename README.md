# GRUMP — Game Routing Unified Mapping Proxy

**GRUMP** is a dynamic TCP/UDP port forwarder designed for game server networks. It is designed to allow safe exposure of private game servers to the public internet by relaying traffic to available internal hosts based on port activity. 

---

## Features

- Dynamic routing of incoming TCP/UDP traffic to multiple hosts within a subnet
- Redis-based port scan caching and client rate limiting
- CIDR-based IP filtering and disallowed host control
- JSON-based logging for easy log ingestion and threat detection
- CrowdSec integration: log parsing configs and an optional built-in stream bouncer
- Systemd-compatible for clean daemon operation

---

## Installation

1. **Build the binary:**

   ```bash
   go build -o grump ./src
   sudo mv grump /opt/grump/grump
   ```

2. **Create system user:**

   ```bash
   sudo useradd -r -s /usr/sbin/nologin grump
   sudo mkdir -p /opt/grump
   sudo chown -R grump:grump /opt/grump
   ```

3. **Add configuration:**
   Create `/opt/grump/config.json` with contents like:

   ```json
   {
     "target_cidr": "10.0.200.0/24",
     "redis_host": "localhost",
     "redis_port": 6379,
     "redis_ttl": 60,
     "redis_prefix": "grump",
     "listen_address": "10.0.100.10",
     "max_scans_per_ip": 10,
     "max_scans_per_ip_timeout": 60,
     "disallowed_hosts": ["10.0.200.1"],
     "port_ranges": [{ "start": 25565, "end": 25570 }],
     "timeouts": {
       "25565": 1500
     },
     "crowdsec_enabled": false,
     "crowdsec_api_url": "http://localhost:8080/",
     "crowdsec_api_key": "<bouncer api key>",
     "crowdsec_ticker_interval": "10s"
   }
   ```
---

## Systemd Integration

1. **Create service file** at `/etc/systemd/system/grump.service`:

2. **Enable & start:**
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable grump
   sudo systemctl start grump
   ```

---

## Logging & Monitoring

GRUMP logs all activity as structured JSON to stdout (journal):

```bash
journalctl -u grump -f
```

Example log entries (CrowdSec-compatible):

```json
{"event_type":"connection","proto":"UDP","result":"RELAY","src_ip":"1.2.3.4","src_port":34567,"dst_ip":"10.0.55.2","dst_port":25565,"timestamp":"2025-04-23T17:52:31Z"}
{"event_type":"connection","proto":"TCP","result":"RATE_LIMIT","src_ip":"8.8.8.8","src_port":0,"dst_ip":"-","dst_port":25565,"timestamp":"2025-04-23T17:52:10Z"}
```

---

## CrowdSec Integration

### Log ingestion

Ready-made CrowdSec configs live in [`crowdsec/`](crowdsec/):

- `acquis.yaml` — acquisition config for journald or Docker log sources
- `parsers/s01-parse/grump-logs.yaml` — parses GRUMP's JSON logs into CrowdSec events
- `scenarios/grump-portscan.yaml` — bans IPs that trip GRUMP's rate limiter or repeatedly probe ports

Copy them into the matching directories under `/etc/crowdsec/` and reload CrowdSec.

### Built-in bouncer

GRUMP can also act as its own CrowdSec bouncer. When enabled, it streams ban
decisions from the Local API and drops TCP connections / UDP packets from
banned IPs before any forwarding occurs (logged with `"result":"BANNED"`).

1. Register a bouncer API key:

   ```bash
   sudo cscli bouncers add grump
   ```

2. Set the `crowdsec_*` keys in `config.json`:

   ```json
   "crowdsec_enabled": true,
   "crowdsec_api_url": "http://localhost:8080/",
   "crowdsec_api_key": "<key from cscli>",
   "crowdsec_ticker_interval": "10s"
   ```
