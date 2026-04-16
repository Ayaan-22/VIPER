# 🛡 VIPER — Python Network Intrusion Detection System

A production-ready, modular Network Intrusion Detection System built in Python.  
Detects port scans, volumetric floods, brute-force attacks, and statistical traffic anomalies in real time using sliding-window algorithms and structured alerting.

---

## Table of Contents

1. [Features](#features)
2. [Architecture Overview](#architecture-overview)
3. [Directory Structure](#directory-structure)
4. [Requirements](#requirements)
5. [Installation](#installation)
6. [Configuration](#configuration)
7. [Usage](#usage)
8. [Detection Capabilities](#detection-capabilities)
9. [Alerting Channels](#alerting-channels)
10. [Web Dashboard](#web-dashboard)
11. [Reporting & Visualisation](#reporting--visualisation)
12. [PCAP Export](#pcap-export)
13. [Running Tests](#running-tests)
14. [Docker Deployment](#docker-deployment)
15. [Architecture Decisions](#architecture-decisions)
16. [Future Improvements](#future-improvements)

---

## Features

| Category | Capability |
|---|---|
| **Detection** | Port scan, SYN flood, UDP flood, ICMP flood, brute-force, anomaly |
| **Windowing** | Thread-safe sliding-window counters — no stale state |
| **Severity** | Dynamic severity escalation (LOW → CRITICAL) based on rate |
| **Alerting** | Console (coloured), rotating JSON log, email, webhook |
| **Capture** | Rotating PCAP export for offline forensics |
| **Config** | Single YAML file — no code changes needed to tune thresholds |
| **Dashboard** | Flask web UI with live alert feed and severity charts |
| **Reporting** | Text + JSON reports, Matplotlib bar/pie charts |
| **Testing** | Full pytest suite; no live interface needed |
| **Docker** | Single-command deployment with docker-compose |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        main.py (CLI)                        │
└──────────────────────────┬──────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │  NIDSEngine  │  (src/core/engine.py)
                    └──────┬──────┘
          ┌────────────────┼────────────────┐
          │                │                │
   ┌──────▼──────┐  ┌──────▼──────┐  ┌─────▼──────┐
   │   Scapy     │  │  Rotating   │  │  Reporter  │
   │   sniff()   │  │  PcapWriter │  │ Visualizer │
   └──────┬──────┘  └─────────────┘  └────────────┘
          │ enqueue()
   ┌──────▼────────────────────────────────────────┐
   │          PacketProcessor (queue + N workers)   │
   └──────┬────────────────────────────────────────┘
          │ process(packet)
   ┌──────▼────────────────────────────────────────────────────┐
   │  Detectors                                                │
   │  PortScanDetector  SynFloodDetector  UdpFloodDetector     │
   │  IcmpFloodDetector  BruteForceDetector  AnomalyDetector   │
   └──────┬────────────────────────────────────────────────────┘
          │ emit(Alert)
   ┌──────▼──────────────────────────────────────────────────┐
   │  AlertHandler  →  Console / File / Email / Webhook      │
   └─────────────────────────────────────────────────────────┘
```

**Key design principles:**

- **Separation of concerns** — each module has a single responsibility.
- **Dependency injection** — detectors receive `AlertHandler` via constructor; no globals.
- **Non-blocking capture** — Scapy's callback only enqueues packets; all processing is in worker threads.
- **Configurable everything** — all thresholds, windows, and channels live in `config/config.yaml`.

---

## Directory Structure

```
viper/
├── main.py                      # CLI entry point
├── requirements.txt
├── pytest.ini
├── Dockerfile
├── docker-compose.yml
├── config/
│   └── config.yaml              # ← edit this to tune the system
├── dashboard/
│   └── app.py                   # Flask live dashboard
├── src/
│   ├── core/
│   │   ├── engine.py            # Top-level orchestrator
│   │   ├── packet_processor.py  # Queue + worker thread pool
│   │   └── sliding_window.py    # Thread-safe time-windowed counters
│   ├── detectors/
│   │   ├── base.py              # Abstract BaseDetector
│   │   ├── port_scan.py
│   │   ├── flood_detectors.py   # SYN / UDP / ICMP
│   │   ├── brute_force.py
│   │   └── anomaly.py           # Statistical (Welford's algorithm)
│   ├── alerting/
│   │   ├── alert.py             # Alert dataclass + Severity enum
│   │   └── handler.py           # Fan-out dispatcher
│   ├── logger/
│   │   └── logger.py            # Structured JSON + coloured console
│   ├── reporting/
│   │   └── reporter.py          # Text/JSON reports + Matplotlib charts
│   ├── capture/
│   │   └── pcap_writer.py       # Rotating PCAP export
│   └── utils/
│       └── config_loader.py     # YAML loader with deep-merge defaults
└── tests/
    └── test_detectors.py        # Full pytest suite
```

---

## Requirements

- Python 3.9+
- Linux / macOS (Scapy requires raw-socket access)
- Root / `CAP_NET_RAW` privilege for live capture

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/yourname/viper.git
cd viper

# 2. Create a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

---

## Configuration

All settings live in **`config/config.yaml`**.  
Edit the file — no code changes required.

```yaml
detection:
  port_scan:
    enabled: true
    unique_ports_threshold: 15   # ports within window before alerting
    window_seconds: 10

  syn_flood:
    packets_per_second: 100      # rate threshold

  brute_force:
    target_ports: [22, 3389]     # which services to watch
    attempts_threshold: 10
    window_seconds: 30

alerting:
  email:
    enabled: true
    smtp_host: smtp.gmail.com
    username: you@gmail.com
    password: "app-password"
    to_addrs: [soc@company.com]
    min_severity: HIGH

  webhook:
    enabled: true
    url: https://hooks.slack.com/services/...
```

---

## Usage

```bash
# Basic — monitor eth0
sudo python main.py -i eth0

# Custom config file
sudo python main.py -i eth0 --config /etc/nids/production.yaml

# Increase log verbosity
sudo python main.py -i eth0 --log-level DEBUG

# Validate config and list active detectors, then exit
sudo python main.py -i eth0 --dry-run

# Post-incident: regenerate report from an existing log
python main.py --report-only --log logs/nids.log
```

### Help

```
sudo python main.py --help
```

---

## Detection Capabilities

### Port Scan
Watches for a single source IP probing many distinct destination ports within a sliding window using SYN-only packets.  Whitelisted IPs and non-SYN traffic are ignored to reduce false positives.

### SYN / UDP / ICMP Flood
Measures per-source packet rate over a 1-second sliding window.  Severity escalates to CRITICAL when the rate exceeds twice the configured threshold.

### Brute Force
Counts connection attempts to configurable service ports (SSH, RDP, FTP, Telnet, SMTP, POP3, IMAP) per source over a 30-second window.  Fires a HIGH alert when the attempt count exceeds the threshold.

### Statistical Anomaly
Uses **Welford's online algorithm** to maintain a per-source running mean and standard deviation of packet sizes and inter-arrival times — with no ML library required.  Alerts when a new observation deviates by more than `deviation_factor` (default: 3.0) standard deviations from the learnt baseline.

---

## Alerting Channels

| Channel | Config key | Notes |
|---|---|---|
| Coloured console | `alerting.console` | Colour-coded by severity |
| Rotating JSON log | `logging.file` | Structured, queryable with `jq` |
| Email (SMTP) | `alerting.email` | TLS, per-severity filter |
| HTTP Webhook | `alerting.webhook` | Slack / Teams / PagerDuty compatible |

**Query the log with `jq`:**
```bash
# All CRITICAL alerts
jq 'select(.severity=="CRITICAL")' logs/nids.log

# Top offending IPs
jq -r '.src_ip' logs/nids.log | sort | uniq -c | sort -rn | head
```

---

## Web Dashboard

```bash
# Start the dashboard (separate terminal)
python dashboard/app.py --log logs/nids.log --port 5000

# Open in browser
open http://localhost:5000
```

The dashboard auto-refreshes every 5 seconds and shows:
- Alert counters by severity
- Live scrolling alert table
- Detector breakdowns

---

## Reporting & Visualisation

Reports are generated automatically every `reporting.auto_report_interval` seconds and on shutdown.

```
reports/
├── report_20250101_120000.txt   # Human-readable summary
├── report_20250101_120000.json  # Machine-readable (for SIEM ingestion)
├── viz_20250101_120000.png      # Bar chart: alerts by detector
└── severity_20250101_120000.png # Pie chart: alerts by severity
```

---

## PCAP Export

Packets are written to rotating PCAP files in `captures/`:

```bash
# Analyse with Wireshark
wireshark captures/capture_20250101_120000.pcap

# Or with tshark
tshark -r captures/capture_20250101_120000.pcap -Y "tcp.flags.syn==1"
```

---

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=src --cov-report=term-missing

# A specific test class
pytest tests/test_detectors.py::TestPortScanDetector -v
```

Tests cover: `SlidingWindow`, `SlidingWindowDict`, `Alert`/`Severity`, `AlertHandler`, all detectors, and `ConfigLoader`.  No live network interface is required.

---

## Docker Deployment

```bash
# Build and start everything (NIDS sensor + dashboard)
docker-compose up -d

# View live logs
docker-compose logs -f nids

# Capture on a different interface
docker-compose run nids --interface ens3

# Stop
docker-compose down
```

The container requires `--cap-add NET_ADMIN --cap-add NET_RAW` (handled automatically by `docker-compose.yml`).

---

## Architecture Decisions

| Decision | Rationale |
|---|---|
| **Sliding windows over fixed counters** | Counters reset at arbitrary boundaries causing bursts to split across windows; sliding windows give a continuous view |
| **Thread-pool + queue** | Decouples capture (must be fast) from detection (may be slow); bounded queue prevents OOM under extreme load |
| **Welford's algorithm** | Single-pass, O(1) per sample, numerically stable — no need for NumPy or keeping a full history buffer |
| **Dependency injection** | Detectors are completely testable without Scapy or a network interface |
| **YAML config + deep-merge** | Users can supply a partial config; missing keys always fall back to safe defaults |
| **JSON structured logs** | Machine-parseable; trivially ingested by ELK, Splunk, Grafana Loki, or `jq` |

---

## Future Improvements

- **ML anomaly model** — replace Welford's with an `sklearn` IsolationForest or autoencoder trained on baseline traffic captures.
- **GeoIP enrichment** — annotate alerts with country/ASN using `maxminddb`.
- **eBPF integration** — use `bcc` or `pyshark` for kernel-space filtering to reduce Python-side overhead by 10×.
- **Prometheus metrics** — expose packet rates and alert counts as a `/metrics` endpoint for Grafana dashboards.
- **Alert deduplication** — group repeated alerts from the same source into a single aggregated event.
- **Active response** — optionally call `iptables` / `nftables` to block confirmed attack sources.
- **IPv6 support** — extend all detectors to handle IPv6 headers.
- **Cluster mode** — distribute capture across multiple sensors and aggregate alerts centrally.
