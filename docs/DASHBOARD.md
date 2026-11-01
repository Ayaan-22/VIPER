# VIPER Vision Dashboard

VIPER Vision upgrades the original Flask dashboard into a multi-page defensive network intrusion visualizer.

## Run Modes

```bash
python dashboard/app.py --log logs/nids.log --port 5000
python dashboard/app.py --demo
python main.py --dashboard --log logs/nids.log
python main.py --dashboard-demo
```

Historical/live log mode reads VIPER JSON logs. If the NIDS engine is running and writing `logs/nids.log`, the dashboard refreshes from that active file. Demo mode uses deterministic simulated data and is labeled as simulated in the UI.

## Pages

- Dashboard Overview
- Live Alerts
- Packet Summary
- Top Talkers
- Protocol Breakdown
- Port Scan Visualizer
- Suspicious Connections
- Attack Timeline
- Reports
- PCAP Captures
- Settings
- About VIPER

## Streaming

The dashboard exposes Server-Sent Events at:

- `GET /api/stream/alerts`
- `GET /api/stream/metrics`

With a compatible server and WebSockets explicitly enabled, optional routes are available (disabled by the default Waitress entry points):

- `/ws/alerts`
- `/ws/metrics`

## Vision 2

The main browser uses `/api/snapshot`, with persistent preferences, server-side filtering/pagination, an alert evidence drawer, measured traffic/health charts, safe report/capture downloads and responsive dark/light layouts. The dashboard incrementally indexes active and rotated logs in SQLite instead of reparsing each file per request. See [Operations](OPERATIONS.md) and [API](API.md) for compatibility changes and limits.

The readable typography update uses a 15px system-font base, 14px table text,
larger labels, increased line spacing and stronger secondary-text contrast.
Controls have a minimum height of 40px. Dark and light themes include distinct
button foreground colors. Tables scroll within their panels on narrow screens.
