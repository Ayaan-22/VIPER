# VIPER Vision API

Base URL: `http://127.0.0.1:5000`

## Status and Metrics

- `GET /api/status`
- `GET /api/metrics/summary`

## Alerts

- `GET /api/alerts`
- `GET /api/alerts/recent`
- `GET /api/alerts/severity`

Supported `/api/alerts` filters:

- `severity=HIGH,CRITICAL`
- `detector=port_scan`
- `src_ip=10.0.0.5`
- `dst_ip=10.0.0.20`
- `protocol=TCP`
- `q=search text`
- `limit=100`

## Analytics

- `GET /api/analytics/top-sources`
- `GET /api/analytics/top-destinations`
- `GET /api/analytics/top-ports`
- `GET /api/analytics/protocols`
- `GET /api/analytics/timeline`
- `GET /api/analytics/port-scans`
- `GET /api/analytics/suspicious-connections`

## Reports, Captures, Settings

- `GET /api/reports`
- `POST /api/reports/generate`
- `GET /api/captures`
- `GET /api/settings`
- `PATCH /api/settings`

`PATCH /api/settings` only accepts safe dashboard settings such as refresh interval, max displayed alerts, chart window size, theme, and log path. It does not expose offensive controls.

## Streaming

- `GET /api/stream/alerts`
- `GET /api/stream/metrics`
- `WebSocket /ws/alerts` if `flask-sock` is installed
- `WebSocket /ws/metrics` if `flask-sock` is installed
