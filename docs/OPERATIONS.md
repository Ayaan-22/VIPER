# VIPER Vision 2 operations and release guide

This release implements the audit remediations and a new dashboard. Offline
validation does not establish capture visibility, detection accuracy, or
capacity on a particular network. Complete the acceptance checks below for
each operational deployment.

## Install and migrate

Use Python 3.12 or 3.13. Local validation uses Python 3.12 on Windows; CI is
configured for both versions on Windows and Linux.

    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-runtime.lock
    Copy-Item config/config.example.yaml config/config.yaml
    .\.venv\Scripts\python.exe main.py --config config/config.yaml --dry-run

Do not overwrite existing private configuration. Merge new options from the
example and run dry-run. Explicitly missing config paths and unknown/invalid
values now fail. For development, additionally install requirements-dev.txt.
Refresh runtime versions deliberately using requirements.txt, then run
tools/lock_dependencies.py --hashes, pip check, dependency audit and tests.
The lock records SHA256 hashes from official PyPI. Docker enforces the lock and
pins the official Python image manifest digest. Review both on each release.

Start the authorized sensor with main.py -i INTERFACE. Windows requires Npcap
and an elevated capture process. The dashboard does not need capture privilege:

    .\.venv\Scripts\python.exe main.py --dashboard
    .\.venv\Scripts\python.exe dashboard/app.py --demo

The standalone demo needs no private configuration. Both dashboard CLIs use
Waitress by default: 16 threads and 128 connection slots. Flask development
serving is explicit (--development on dashboard/app.py or
--dashboard-development on main.py). Waitress entry points disable WebSockets;
optional WebSocket deployments require a compatible server. The main UI uses
one consolidated snapshot request per poll; specialized views add one request.
SSE has a maximum of four simultaneous streams per app.

References: [Waitress API](https://docs.pylonsproject.org/projects/waitress/en/latest/api.html),
[Flask-Sock deployment](https://flask-sock.readthedocs.io/en/latest/deployment.html).

## Access and transport

Unauthenticated access requires both a loopback source and loopback Host.
Configure a long random VIPER_DASHBOARD_API_KEY before non-loopback binds.
Use an environment/secret manager instead of command-line keys or committed
credentials. Requests support X-VIPER-API-Key, bearer authorization or Basic
authentication (username viper, password the key). Browser Basic auth works.

This is a single workspace/operator-key model. For independent operators or
tenants, enforce enterprise identity/access policy at a trusted gateway; a
shared key is not per-user authorization or an audit trail. The app rejects
cross-origin mutations/WebSocket origins and emits CSP/frame/sniffing headers.
Artifact downloads use attachments.

For shared access, terminate trusted TLS at a reverse proxy, restrict backend
access and rate-limit requests. Supply real certificates/hostname in
deploy/nginx.conf.example. The app does not trust arbitrary forwarded headers.
Never expose an unencrypted API key over the Internet.

## Persistence, budgets and evidence

- Sensor logs rotate using logging.max_bytes and backup_count.
- Dashboard CLIs persist SQLite history and preferences under reports/.index/.
  Direct create_app() embeddings use memory unless database_path is supplied.
  Close their store when the embedding shuts down.
- Ingestion follows numbered rotated segments, reads appended bytes,
  deduplicates alerts and checkpoints complete lines. Malformed records are
  skipped and counted. At most 2 MiB are ingested per sync; catch-up is visible.
- Index retention defaults to 25,000 alerts, 10,000 heartbeat records and
  128 MiB encoded payload. SQLite indexes/pages/WAL add overhead. Pruning and
  parse/read failures are visible.
- Detector defaults per tracker: 2,048 keys, 65,536 total events and 8,192
  events per key. Capacity loss can reduce completeness and is counted.
- Anomaly profiles retain at most 512 trusted samples within their time
  lookback. Expired samples are removed; scored anomalies do not train the
  baseline. Expiry can return a profile to warm-up.
- Automatic reports default to 500 owned files, 512 MiB and 30 days. PCAP
  retention uses capture.max_files/rotate_mb. Capture queue loss and write/
  close errors are distinct from processing drops.

Use SQLite-aware backup or stop the dashboard first. Copying a live database
without its WAL is not a backup. Preserve source logs/PCAPs separately for
long-term forensics. Resetting an index removes history and invalidates cursors.
Do not delete evidence during upgrades.

Rates use the full configured interval and capture timestamps. Workers partition
by source; out-of-order timestamps are rejected/counted. Native alerts include
destination/protocol context. Flood counts aggregate by source: their target
identifies the packet crossing the threshold, not every counted packet's target.

The retained brute_force configuration/event identifier now means **repeated
connection attempts**. Tracking separates source, destination and service and
deduplicates retransmitted SYNs. Authentication failure requires host logs.
Port scans distinguish multi-port probes and host sweeps. IPv4/IPv6 and
ECN-marked SYNs are supported; response/malformed attempt flags are excluded.
This heuristic set does not perform full TCP reassembly or comprehensive
signature inspection.

Packet totals describe the latest sensor session. Protocol shares compare
measured heartbeat counters over a sampled interval; absent observations stay
unknown. Host rankings count alerts. Port samples contain recorded identities
only. Historical alert ranges anchor to the latest recorded alert or sensor
heartbeat. A fresh running sensor anchors ranges to the current time, so old
alerts age out even when no new alerts arrive.

Preference changes persist to a unique temporary file, flush and atomically
replace the saved preferences before publishing new in-memory state. A write
failure returns HTTP 503 and leaves previous preferences active.

The event index checkpoints the beginning and end of its consumed log region
to detect copy-truncate rotation, including files that regrow before the next
poll. Existing indexes migrate automatically. Logs should remain append-only
between rotations; these bounded checkpoints do not detect every possible edit
in the middle of a file. Rename-based rotation is preferred.

SSE alerts are individual objects with numeric event IDs, replacing the old
latest-25 arrays. Reconnect with Last-Event-ID or after and handle gap events
for unavailable/pruned cursors. WebSocket messages also contain cursor-bearing
events and gap flags. External clients must migrate from the old stream shape.

## Health and shutdown

GET /api/health reports API/sensor/index state. HTTP 200 establishes API
availability; inspect engine_status, freshness, catch-up and evidence counters
for sensor health. GET /metrics exposes authenticated Prometheus text counters
and heartbeat age (-1 means unknown; viper_simulated_data=1 means demo).
Counter categories can overlap, and session counters reset on sensor restart.

tools/healthcheck.py exits nonzero for absent/stale/stopped sensor heartbeats.
Allowed age is at least three heartbeat intervals. Heartbeats remain persisted
when diagnostic logging is above INFO.

Shutdown stops capture, drains/joins packet and PCAP workers, finishes in-flight
notification I/O, records cancelled queued notifications as loss and generates
the final report last. Timeout is an error, not successful shutdown. Compose
allows 90 seconds stop grace. SMTP verifies certificates/hostnames and has
explicit socket timeouts. SMTP/webhooks have independent bounded pools.

## Docker deployment

Set VIPER_DASHBOARD_API_KEY before Compose parses configuration, including
before build. Prepare private config/config.yaml and host logs/captures folders.

    docker compose build
    docker compose up -d
    docker compose logs -f nids dashboard

The sensor uses host networking with NET_ADMIN/NET_RAW and DAC_OVERRIDE for
writes to mounted evidence directories with different host ownership. Its
root filesystem and private configuration mount remain read-only. Dashboard services run
as UID/GID 10001, with no added capabilities and a read-only root filesystem.
Logs/captures mount read-only into the dashboard. Both services share the named
reports-data volume for reports, index and preferences. New volumes inherit
the image report directory's ownership; existing volumes may need migration.
Use downloads or docker compose cp for host exports. Do not use down -v unless
intentionally destroying named evidence volumes.

The demo profile uses its own persistent report volume. Capture visibility on
Docker Desktop differs from native Linux and requires separate acceptance.
The image COPY allow-list and .dockerignore exclude private configuration,
secrets, VCS, virtualenvs and runtime evidence.

## Operational release acceptance

The remediation report records local checks. A committed CI workflow does not
establish that its remote runs have passed. Before operational promotion:

1. Build the pinned image, inspect excluded secret canaries and scan the
   container/base OS for vulnerabilities.
2. Verify sensor-created captures/reports appear in Compose's dashboard,
   index/preferences survive recreation and UID 10001 permissions work.
3. Capture authorized IPv4/IPv6 fixtures on the intended interface/Npcap/libpcap
   stack; establish expected visibility and detection false-positive/negative
   rates. Encrypted authentication outcomes need host evidence.
4. Load-test expected packet rates, source cardinality, alert rates, disk I/O
   and concurrent operators. Set budgets from observed capacity and verify
   overflow/error telemetry and recovery.
5. Exercise capture failure, full disk, delivery failures, rotation/restart,
   graceful/forced stop and stream reconnection.
6. Validate the actual TLS/identity gateway, key rotation, monitoring alarms,
   backup/restore, retention and response ownership.

The offline benchmark does not certify live capture or multi-client capacity.
