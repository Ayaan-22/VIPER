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

If `flask-sock` is installed, WebSocket routes are also available:

- `/ws/alerts`
- `/ws/metrics`
