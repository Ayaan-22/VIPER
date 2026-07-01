# Troubleshooting

## Dashboard Starts but Shows No Alerts

- Confirm the log path: `python dashboard/app.py --log logs/nids.log`
- Check that log lines are JSON and contain `alert_id`
- Use demo mode to verify the UI: `python dashboard/app.py --demo`

## Packet Capture Permission Errors

- Windows: install Npcap with WinPcap API-compatible mode and run the terminal as Administrator.
- Linux/macOS: run with root privileges or grant `CAP_NET_RAW` where appropriate.
- Docker: keep `NET_ADMIN`, `NET_RAW`, and host networking for the sensor service when real packet visibility is required.

## WebSockets Unavailable

Install dashboard dependencies from `requirements.txt`. Without `flask-sock`, SSE endpoints still work:

- `/api/stream/alerts`
- `/api/stream/metrics`

## Docker Capture Limitations

Docker Desktop on Windows/macOS does not expose host interfaces the same way as Linux host networking. Use native execution for the most reliable local packet capture on those platforms.
