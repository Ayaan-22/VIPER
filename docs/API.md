# VIPER Vision 2 API

All endpoints except static assets require the configured dashboard key.
Without a key, both source address and Host must be loopback. Send
X-VIPER-API-Key, a Bearer token or Basic auth (viper / key). Use TLS for shared
access. Cross-origin mutations and WebSocket upgrades are rejected.

## Monitoring

- GET /api/snapshot: consolidated status, metrics, paginated alert items and settings.
- GET /api/metrics: complete metrics object.
- GET /api/metrics/summary: sensor/session and selected alert counters.
- GET /api/status and /api/health: API/sensor/index state and freshness.
- GET /metrics: authenticated Prometheus text counters, heartbeat age and demo flag.

Snapshot response keys: status, metrics, alerts (total, offset, items), settings.
Metrics identify traffic/alert scopes. Protocol packet counts/shares are null
when measured observations are unavailable. A healthy API response is not proof
of capture visibility or complete detection.

## Alerts and analytics

- GET /api/alerts: total, offset and alerts. limit is 1–1000; offset is 0–100000.
- GET /api/alerts/recent: latest alert array; limit is 1–1000.
- GET /api/alerts/severity
- GET /api/analytics/top-sources
- GET /api/analytics/top-destinations
- GET /api/analytics/top-ports
- GET /api/analytics/protocols
- GET /api/analytics/timeline: at most 1000 recent events.
- GET /api/analytics/port-scans: at most 500 episodes, with scan_type and observed samples.
- GET /api/analytics/suspicious-connections: at most 500 groups; positive window seconds.

Alert/snapshot filters: severity (comma-separated known levels), detector,
protocol, src_ip, dst_ip, q, minutes (1–10080), since and until (finite epoch or
ISO timestamps). Historical relative ranges anchor to the latest recorded
event. Snapshot sort supports timestamp or severity; alert sort additionally
supports detector, src_ip, dst_ip and protocol, with order=asc or desc.

Brute_force remains an event identifier for compatibility; the signal means
repeated connection attempts, not proven authentication failure. Flood target
context identifies the threshold-crossing packet of a per-source aggregate.

## Reports, captures and preferences

- GET /api/reports and /api/captures: names, sizes, modified timestamps and download URLs.
- POST /api/reports/generate: creates HTML/JSON and returns status, name and URL.
- GET /reports/NAME and /captures/NAME: authorized attachment downloads.
- GET /api/settings
- PATCH /api/settings: atomic validated object; persistent in dashboard CLI deployments.

Settings: refresh_interval_seconds (1–300), max_alerts_displayed (1–1000),
default_time_range_minutes (1–10080), chart_window_size (1–3600 seconds per
alert bucket), nonempty severity_filters, theme (dark/light/system), and
log_file_path (allowed directory and log/JSON-lines extension only). A file
that does not yet exist is allowed; an existing directory is not. Source changes
use a separate index. No sensor actuation controls are exposed.

Malformed inputs return JSON 400; oversized requests return 413. Report
contention returns 409. Full streaming capacity returns 429. Missing artifact
or containment failures return 404. Authentication failures return 401.

## Cursor streaming

- GET /api/stream/alerts: individual SSE alert objects with numeric id lines.
- GET /api/stream/metrics: complete metrics snapshots as SSE.
- Optional /ws/alerts and /ws/metrics: only with a compatible server and enabled config.

Reconnect alert streams using Last-Event-ID or after. Alert events are not
limited to the latest 25. Handle named gap events for unavailable/pruned
history and keepalive comments during idle periods. Index retention means the
stream is replayable within retained history, not an indefinite event archive.
The app limits SSE to four concurrent connections. The default Waitress CLI
uses polling/SSE and disables WebSockets (426 on those routes).

See [Operations](OPERATIONS.md) for storage, deployment and acceptance details.
