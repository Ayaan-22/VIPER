"""VIPER Vision: authenticated monitoring API, indexed history and dashboard."""
from __future__ import annotations

import argparse
import base64
import binascii
import copy
import hashlib
import hmac
import json
import os
import sys
import threading
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from flask import Flask, Response, jsonify, render_template, request, send_from_directory, abort
try:
    from flask_sock import Sock
except ImportError:
    Sock = None

from dashboard.api.models import severity_rank, parse_timestamp
from dashboard.services.demo_data import build_demo_dataset
from dashboard.services.event_store import EventStore
from dashboard.services.metrics_service import build_metrics, to_plain, alerts_over_time, protocol_breakdown, packet_rate_over_time
from dashboard.services.report_service import generate_html_report
from dashboard.services.suspicious_connection_service import group_suspicious_connections
from dashboard.services.timeline_service import build_timeline, extract_port_scans

DEFAULT_SETTINGS = {
    "refresh_interval_seconds": 5, "max_alerts_displayed": 500,
    "default_time_range_minutes": 60, "severity_filters": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "chart_window_size": 60, "log_file_path": "logs/nids.log", "theme": "dark",
}


def create_app(*, log_path="logs/nids.log", demo=False, captures_dir="captures",
               reports_dir="reports", interface="log replay", api_key=None,
               auth_username="viper", dashboard_options=None, analytics_options=None,
               database_path=None, report_retention=None, settings_path=None):
    app = Flask(__name__, template_folder="templates", static_folder="static")
    if demo and str(reports_dir) == "reports":
        reports_dir = "reports/demo"
    key = api_key or os.getenv("VIPER_DASHBOARD_API_KEY", "")
    app.config.update(VIPER_LOG_PATH=log_path, VIPER_DEMO=demo,
                      VIPER_CAPTURES_DIR=str(Path(captures_dir).resolve()),
                      VIPER_REPORTS_DIR=str(Path(reports_dir).resolve()), VIPER_INTERFACE=interface,
                      VIPER_API_KEY=key, VIPER_AUTH_USERNAME=os.getenv("VIPER_DASHBOARD_AUTH_USER", auth_username),
                      VIPER_ALLOWED_LOG_DIR=os.getenv("VIPER_DASHBOARD_LOG_DIR") or _default_allowed_log_dir(log_path),
                      MAX_CONTENT_LENGTH=65536)
    if not key:
        app.logger.warning("VIPER Vision API key is not configured; only loopback requests are allowed. Set VIPER_DASHBOARD_API_KEY before exposing the dashboard.")
    app.viper_settings = copy.deepcopy(DEFAULT_SETTINGS)
    app.viper_settings["log_file_path"] = log_path
    preferences_path = Path(settings_path) if settings_path else None
    if preferences_path and preferences_path.is_file():
        try:
            saved = json.loads(preferences_path.read_text(encoding="utf-8"))
            # Revalidate the saved file through the same PATCH route after app setup.
        except (OSError, ValueError):
            saved = None
            app.logger.warning("Saved preferences could not be loaded")
    else:
        saved = None
    options = dashboard_options or {}
    for source, target in (("refresh_interval_seconds", "refresh_interval_seconds"),
                           ("max_live_alerts", "max_alerts_displayed"),
                           ("timeline_window_minutes", "default_time_range_minutes")):
        if source in options:
            app.viper_settings[target] = options[source]
    analytics = analytics_options or {}
    settings_lock = threading.RLock()
    store_lock = threading.RLock()
    report_lock = threading.Lock()
    stream_slots = threading.BoundedSemaphore(4)
    store = None if demo else EventStore(log_path, database_path or ":memory:")
    demo_data = build_demo_dataset() if demo else None
    app.extensions["viper_store"] = store
    settings_revision = 0
    metrics_cache = {}

    @app.before_request
    def authorize():
        if request.endpoint == "static":
            return None
        if key:
            if not _request_has_valid_key(request, app.config["VIPER_AUTH_USERNAME"], key):
                return Response("Authentication required", 401, {"WWW-Authenticate": 'Basic realm="VIPER Vision"'})
        elif not _is_loopback_host(request.remote_addr or "") or not _is_loopback_host(urlsplit(request.url).hostname or ""):
            return jsonify(error="API key required for non-loopback access"), 403
        if request.method in {"PATCH", "POST", "DELETE", "PUT"} or request.path.startswith("/ws/"):
            origin = request.headers.get("Origin")
            if request.headers.get("Sec-Fetch-Site") == "cross-site" or (origin and urlsplit(origin).netloc != request.host):
                return jsonify(error="Cross-origin changes are not allowed"), 403

    @app.after_request
    def secure_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        if request.endpoint != "static":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.errorhandler(ValueError)
    def invalid_value(exc):
        return jsonify(error=str(exc)), 400

    @app.errorhandler(413)
    def oversized(exc):
        return jsonify(error="Request exceeds 64 KiB"), 413

    def load_dataset():
        with store_lock:
            return demo_data if demo else store.snapshot()

    def status_payload(alerts, stats):
        latest = stats[-1] if stats else {}
        last_seen = latest.get("timestamp", 0)
        fresh = bool(last_seen and -5 <= time.time() - last_seen <= max(30, latest.get("heartbeat_interval", 10) * 3))
        mode = "demo" if demo else ("live" if fresh and latest.get("sensor_running") is True else "historical")
        state = "simulated" if demo else ("running" if mode == "live" else ("stopped" if latest.get("sensor_running") is False else "stale" if stats else "waiting"))
        return {"name": "VIPER Vision", "version": "2.0", "mode": mode, "demo": demo,
                "engine_status": state, "interface": latest.get("interface") or interface,
                "log_path": app.config["VIPER_LOG_PATH"], "alerts_loaded": len(alerts),
                "packet_stat_records": len(stats), "last_seen": last_seen, "generated_at": time.time(),
                "data_quality": {"simulated": True} if demo else store.health}

    def selected(alerts, args, stats=None):
        result = _filter_alerts(alerts, args)
        minutes = args.get("minutes")
        if minutes is not None:
            minutes = _integer(minutes, "minutes", 1, 10080)
            stats = load_dataset()[1] if stats is None else stats
            latest = stats[-1] if stats else {}
            anchor = max(max((a.timestamp for a in alerts), default=0), latest.get("timestamp", 0))
            if not anchor:
                anchor = time.time()
            if not demo and latest.get("sensor_running") is True and -5 <= time.time() - latest.get("timestamp", 0) <= max(30, latest.get("heartbeat_interval", 10) * 3):
                anchor = time.time()
            result = [a for a in result if a.timestamp >= anchor - minutes * 60]
        return result

    def metrics_payload(args=None):
        alerts, stats = load_dataset()
        args = args or {}
        chosen = selected(alerts, args, stats)
        state = status_payload(alerts, stats)
        revision = 0 if demo else store.revision
        cache_key = (revision, settings_revision, tuple(sorted(args.items())), int(time.time() // 5))
        with settings_lock:
            if cache_key not in metrics_cache:
                metrics = to_plain(build_metrics(chosen, stats, interface=state["interface"],
                                                 engine_status=state["engine_status"],
                                                 top_limit=analytics.get("top_talkers_limit", 10)))
                metrics["alerts_over_time"] = alerts_over_time(chosen, bucket_seconds=app.viper_settings["chart_window_size"])
                metrics["protocols"] = to_plain(protocol_breakdown(chosen, stats,
                    window_seconds=analytics.get("protocol_window_seconds", 60)))
                if stats:
                    session_stats = [item for item in stats if item.get("session_id") == stats[-1].get("session_id")]
                    points = packet_rate_over_time(session_stats)
                    cutoff = stats[-1]["timestamp"] - int(args.get("minutes", 60)) * 60
                    metrics["packet_rate_over_time"] = [point for point in points if point["timestamp"] >= cutoff][-360:]
                metrics["data_quality"] = state["data_quality"]
                metrics["latest_health"] = stats[-1] if stats else {}
                metrics["scope"] = {"alerts": "selected time range", "traffic": "latest sensor session",
                                    "protocol_packets": "measured counters only",
                                    "protocol_window_seconds": analytics.get("protocol_window_seconds", 60)}
                if len(metrics_cache) >= 8:
                    metrics_cache.clear()
                metrics_cache[cache_key] = metrics
            return metrics_cache[cache_key]

    routes = ["/", "/alerts", "/packets", "/talkers", "/protocols", "/port-scans",
              "/connections", "/timeline", "/reports", "/captures", "/settings", "/about"]
    for route in routes:
        app.add_url_rule(route, endpoint="index_" + route.replace("/", "_"),
                         view_func=lambda: render_template("index.html", demo=demo))

    @app.get("/api/status")
    @app.get("/api/health")
    def api_status():
        return jsonify(status_payload(*load_dataset()))

    @app.get("/api/snapshot")
    def api_snapshot():
        alerts, stats = load_dataset()
        args = request.args.to_dict()
        if "minutes" not in args:
            args["minutes"] = str(app.viper_settings["default_time_range_minutes"])
        chosen = selected(alerts, args, stats)
        limit = _integer(args.get("limit", app.viper_settings["max_alerts_displayed"]), "limit", 1, 1000)
        offset = _integer(args.get("offset", 0), "offset", 0, 100000)
        sort = args.get("sort", "timestamp")
        if sort not in {"timestamp", "severity"}:
            raise ValueError("Unsupported snapshot sort field")
        chosen = sorted(chosen, key=lambda a: (severity_rank(a.severity), a.timestamp) if sort == "severity" else (a.timestamp,), reverse=True)
        return jsonify(status=status_payload(alerts, stats), metrics=metrics_payload(args),
                       alerts={"total": len(chosen), "offset": offset,
                               "items": [a.to_dict() for a in chosen[offset:offset + limit]]},
                       settings=app.viper_settings)

    @app.get("/metrics")
    def prometheus_metrics():
        alerts, stats = load_dataset()
        summary = metrics_payload()["summary"]
        quality = status_payload(alerts, stats)["data_quality"]
        values = {
            "viper_packets_received_total": summary["total_packets"],
            "viper_packets_processed_total": summary["processed_packets"],
            "viper_packets_dropped_total": summary["dropped_packets"],
            "viper_packet_queue_depth": summary["queue_size"],
            "viper_capture_dropped_total": summary["capture_dropped"],
            "viper_capture_errors_total": summary["capture_errors"],
            "viper_detector_errors_total": summary["detector_errors"],
            "viper_notification_losses_total": summary["notification_losses"],
            "viper_index_invalid_records_total": quality.get("invalid_records", 0),
            "viper_sensor_heartbeat_age_seconds": max(0, time.time() - summary["last_seen"]) if summary["last_seen"] else -1,
            "viper_simulated_data": int(demo),
        }
        return Response("".join(f"{name} {value}\n" for name, value in values.items() if value is not None),
                        content_type="text/plain; version=0.0.4; charset=utf-8")

    @app.get("/api/metrics")
    def api_metrics():
        return jsonify(metrics_payload(request.args.to_dict()))

    @app.get("/api/metrics/summary")
    def api_summary():
        return jsonify(metrics_payload()["summary"])

    @app.get("/api/alerts")
    def api_alerts():
        chosen = selected(load_dataset()[0], request.args)
        limit = _integer(request.args.get("limit", app.viper_settings["max_alerts_displayed"]), "limit", 1, 1000)
        offset = _integer(request.args.get("offset", 0), "offset", 0, 100000)
        sort = request.args.get("sort", "timestamp")
        if sort not in {"timestamp", "severity", "detector", "src_ip", "dst_ip", "protocol"}:
            raise ValueError("Unsupported sort field")
        chosen.sort(key=lambda a: severity_rank(a.severity) if sort == "severity" else getattr(a, sort) or "",
                    reverse=request.args.get("order", "desc") == "desc")
        return jsonify(total=len(chosen), offset=offset, alerts=[a.to_dict() for a in chosen[offset:offset + limit]])

    @app.get("/api/alerts/recent")
    def api_recent():
        limit = _integer(request.args.get("limit", 25), "limit", 1, 1000)
        return jsonify([a.to_dict() for a in load_dataset()[0][-limit:]])

    for route, field in (("/api/alerts/severity", "alerts_by_severity"),
                         ("/api/analytics/top-sources", "top_sources"),
                         ("/api/analytics/top-destinations", "top_destinations"),
                         ("/api/analytics/top-ports", "top_ports"),
                         ("/api/analytics/protocols", "protocols")):
        app.add_url_rule(route, endpoint=field, view_func=lambda field=field: jsonify(metrics_payload()[field]))

    @app.get("/api/analytics/timeline")
    def api_timeline():
        return jsonify(to_plain(build_timeline(selected(load_dataset()[0], request.args)))[-1000:])

    @app.get("/api/analytics/port-scans")
    def api_scans():
        threshold = _integer(request.args.get("threshold", 15), "threshold", 1, 65535)
        return jsonify(to_plain(extract_port_scans(selected(load_dataset()[0], request.args), detection_threshold=threshold))[:500])

    @app.get("/api/analytics/suspicious-connections")
    def api_connections():
        window = _integer(request.args.get("window", analytics.get("suspicious_group_window_seconds", 120)), "window", 1, 86400)
        return jsonify(to_plain(group_suspicious_connections(selected(load_dataset()[0], request.args), window_seconds=window))[:500])

    @app.get("/api/reports")
    def api_reports():
        return jsonify(_list_files(app.config["VIPER_REPORTS_DIR"], (".txt", ".json", ".png", ".html", ".pdf"), "reports"))

    @app.post("/api/reports/generate")
    def api_generate_report():
        if not report_lock.acquire(blocking=False):
            return jsonify(error="A report is already being generated"), 409
        try:
            alerts, stats = load_dataset()
            path = generate_html_report(selected(alerts, request.args, stats), stats,
                                        output_dir=app.config["VIPER_REPORTS_DIR"],
                                        mode="demo" if demo else "historical")
            from src.reporting.retention import prune_reports
            prune_reports(app.config["VIPER_REPORTS_DIR"], **(report_retention or {}))
            return jsonify(status="generated", name=Path(path).name,
                           url="/reports/" + Path(path).name)
        finally:
            report_lock.release()

    @app.get("/api/captures")
    def api_captures():
        return jsonify([] if demo else _list_files(app.config["VIPER_CAPTURES_DIR"], (".pcap", ".pcapng", ".cap"), "captures"))

    @app.get("/api/settings")
    def api_settings():
        return jsonify(app.viper_settings)

    @app.patch("/api/settings")
    def api_patch_settings():
        nonlocal store, settings_revision
        updates = request.get_json(silent=True)
        if not isinstance(updates, dict):
            raise ValueError("Settings must be a JSON object")
        with store_lock, settings_lock:
            staged = copy.deepcopy(app.viper_settings)
            for name, value in updates.items():
                if name not in DEFAULT_SETTINGS:
                    raise ValueError("Unsupported setting: " + name)
                if name in {"refresh_interval_seconds", "max_alerts_displayed", "default_time_range_minutes", "chart_window_size"}:
                    bounds = {"refresh_interval_seconds": (1, 300), "max_alerts_displayed": (1, 1000),
                              "default_time_range_minutes": (1, 10080), "chart_window_size": (1, 3600)}
                    value = _integer(value, name, *bounds[name])
                elif name == "severity_filters":
                    if not isinstance(value, list) or not value or any(v not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"} for v in value if isinstance(v, str)) or any(not isinstance(v, str) for v in value):
                        raise ValueError("severity_filters must be a nonempty list of known severities")
                    value = list(dict.fromkeys(value))
                elif name == "theme":
                    if not isinstance(value, str) or value not in {"dark", "light", "system"}:
                        raise ValueError("theme must be dark, light or system")
                elif name == "log_file_path":
                    value = str(_resolve_allowed_path(value, app.config["VIPER_ALLOWED_LOG_DIR"]))
                staged[name] = value
            replacement = None
            temporary = None
            try:
                source_changed = Path(staged["log_file_path"]).resolve() != Path(app.viper_settings["log_file_path"]).resolve()
                if source_changed and not demo:
                    new_db = ":memory:" if not database_path else str(Path(database_path).with_name(hashlib.sha256(staged["log_file_path"].encode()).hexdigest()[:16] + ".sqlite"))
                    replacement = EventStore(staged["log_file_path"], new_db)
                if preferences_path:
                    preferences_path.parent.mkdir(parents=True, exist_ok=True)
                    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8",
                            dir=preferences_path.parent, prefix=".preferences-", suffix=".tmp", delete=False) as stream:
                        temporary = Path(stream.name)
                        json.dump(staged, stream, indent=2)
                        stream.flush()
                        os.fsync(stream.fileno())
                    temporary.replace(preferences_path)
            except OSError:
                if replacement is not None:
                    replacement.close()
                app.logger.exception("Could not persist workspace preferences")
                return jsonify(error="Could not persist preferences; previous settings are still active"), 503
            finally:
                if temporary is not None:
                    try:
                        temporary.unlink(missing_ok=True)
                    except OSError:
                        app.logger.warning("Could not remove temporary preferences file")
            if replacement is not None:
                previous, store = store, replacement
                app.extensions["viper_store"] = store
                previous.close()
            app.config["VIPER_LOG_PATH"] = staged["log_file_path"]
            app.viper_settings = staged
            settings_revision += 1
            metrics_cache.clear()
        return jsonify(staged)

    def events(cursor):
        while True:
            with store_lock:
                alerts, _ = load_dataset()
                if demo:
                    rows = [(index + 1, a.to_dict()) for index, a in enumerate(alerts) if index + 1 > cursor]
                    gap = False
                else:
                    rows, gap = store.after(cursor, limit=1000)
            if gap:
                yield f"event: gap\ndata: {json.dumps({'reason': 'requested cursor is no longer available'})}\n\n"
                if not rows:
                    cursor = 0
            if rows:
                for seq, payload in rows:
                    cursor = seq
                    yield f"id: {seq}\ndata: {json.dumps(payload)}\n\n"
            else:
                yield ": heartbeat\n\n"
            time.sleep(app.viper_settings["refresh_interval_seconds"])

    def stream_response(iterator):
        if not stream_slots.acquire(blocking=False):
            return jsonify(error="Streaming capacity reached; use the snapshot endpoint"), 429
        released = False
        release_lock = threading.Lock()
        def release():
            nonlocal released
            with release_lock:
                if not released:
                    released = True
                    stream_slots.release()
        def body():
            try:
                yield from iterator
            finally:
                release()
        response = Response(body(), mimetype="text/event-stream",
                            headers={"X-Accel-Buffering": "no"})
        response.call_on_close(release)
        return response

    @app.get("/api/stream/alerts")
    def stream_alerts():
        cursor = _integer(request.headers.get("Last-Event-ID", request.args.get("after", 0)), "cursor", 0, 2**63 - 1)
        return stream_response(events(cursor))

    @app.get("/api/stream/metrics")
    def stream_metrics():
        def stream():
            while True:
                yield f"data: {json.dumps(metrics_payload())}\n\n"
                time.sleep(app.viper_settings["refresh_interval_seconds"])
        return stream_response(stream())

    sock = Sock(app) if Sock and options.get("enable_websocket", True) else None
    if sock:
        @sock.route("/ws/alerts")
        def ws_alerts(ws):
            cursor = _integer(request.args.get("after", 0), "cursor", 0, 2**63 - 1)
            while ws.connected:
                with store_lock:
                    load_dataset()
                    rows, gap = ([(i + 1, a.to_dict()) for i, a in enumerate(demo_data[0]) if i + 1 > cursor], False) if demo else store.after(cursor)
                ws.send(json.dumps({"events": [{"cursor": seq, "alert": payload} for seq, payload in rows], "gap": gap}))
                if rows:
                    cursor = rows[-1][0]
                time.sleep(app.viper_settings["refresh_interval_seconds"])

        @sock.route("/ws/metrics")
        def ws_metrics(ws):
            while ws.connected:
                ws.send(json.dumps(metrics_payload()))
                time.sleep(app.viper_settings["refresh_interval_seconds"])
    else:
        @app.get("/ws/alerts")
        @app.get("/ws/metrics")
        def ws_unavailable():
            return jsonify(error="WebSockets disabled; use SSE or snapshot"), 426

    @app.get("/reports/<path:filename>")
    def download_report(filename):
        return _download(app.config["VIPER_REPORTS_DIR"], filename, {".txt", ".json", ".html", ".png", ".pdf"})

    @app.get("/captures/<path:filename>")
    def download_capture(filename):
        if demo:
            abort(404)
        return _download(app.config["VIPER_CAPTURES_DIR"], filename, {".pcap", ".pcapng", ".cap"})

    if saved:
        with app.test_request_context("/api/settings", method="PATCH", json=saved):
            try:
                api_patch_settings()
            except (ValueError, OSError):
                app.logger.warning("Saved preferences failed validation; using configured defaults")
    return app


def _filter_alerts(alerts, args):
    results = list(alerts)
    severity = args.get("severity")
    if severity:
        allowed = set(severity.upper().split(","))
        if not allowed <= {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("Unsupported severity")
        results = [a for a in results if a.severity in allowed]
    for field in ("detector", "protocol"):
        value = args.get(field)
        if value:
            results = [a for a in results if getattr(a, field) == (value.upper() if field == "protocol" else value)]
    for field in ("src_ip", "dst_ip"):
        value = args.get(field)
        if value:
            results = [a for a in results if value in (getattr(a, field) or "")]
    query = (args.get("q") or "").lower()[:256]
    if query:
        results = [a for a in results if query in " ".join((a.title, a.description, a.detector, a.src_ip, a.dst_ip or "", a.protocol)).lower()]
    for field, operation in (("since", lambda t, bound: t >= bound), ("until", lambda t, bound: t <= bound)):
        if args.get(field):
            boundary = parse_timestamp(args[field])
            results = [a for a in results if operation(a.timestamp, boundary)]
    return results


def _integer(value, field, low, high):
    if isinstance(value, bool) or isinstance(value, (list, dict, float)):
        raise ValueError(f"{field} must be an integer")
    try:
        result = int(value)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"{field} must be an integer")
    if not low <= result <= high:
        raise ValueError(f"{field} must be between {low} and {high}")
    return result


def _request_has_valid_key(req, username, expected_key):
    supplied = req.headers.get("X-VIPER-API-Key", "")
    auth = req.headers.get("Authorization", "")
    if auth.lower().startswith("bearer "):
        supplied = auth[7:].strip()
    elif auth.lower().startswith("basic "):
        try:
            user, supplied = base64.b64decode(auth[6:], validate=True).decode("utf-8").split(":", 1)
            if not hmac.compare_digest(user.encode(), username.encode()):
                return False
        except (ValueError, binascii.Error, UnicodeDecodeError):
            return False
    return hmac.compare_digest(supplied.encode(), expected_key.encode())


def _default_allowed_log_dir(log_path):
    parent = Path(log_path).expanduser().parent
    return "logs" if parent == Path(".") else str(parent)


def _resolve_allowed_path(path_value, allowed_dir):
    if not isinstance(path_value, str) or not path_value.strip():
        raise ValueError("log_file_path must not be empty")
    requested, allowed = Path(path_value).expanduser(), Path(allowed_dir).expanduser().resolve()
    if not requested.is_absolute():
        candidate = requested.resolve()
        requested = candidate if candidate.is_relative_to(allowed) else allowed / requested
    resolved = requested.resolve()
    if not resolved.is_relative_to(allowed):
        raise ValueError(f"log_file_path must stay under {allowed}")
    if resolved.exists() and not resolved.is_file():
        raise ValueError("log_file_path must identify a regular file")
    if resolved.suffix.lower() not in {".log", ".jsonl", ".ndjson"}:
        raise ValueError("log_file_path must be a log or JSON lines file")
    return resolved


def _is_loopback_host(host):
    return host in {"localhost", "127.0.0.1", "::1", "[::1]"}


def _list_files(directory, suffixes, kind):
    base = Path(directory)
    files = []
    if base.is_dir():
        for path in base.iterdir():
            try:
                if path.is_file() and not path.is_symlink() and path.suffix.lower() in suffixes and not path.name.startswith("."):
                    stat = path.stat()
                    files.append({"name": path.name, "size_bytes": stat.st_size, "modified": stat.st_mtime,
                                  "url": f"/{kind}/{path.name}"})
            except OSError:
                continue
    return sorted(files, key=lambda f: f["modified"], reverse=True)[:1000]


def _download(directory, filename, suffixes):
    path = Path(directory) / filename
    if Path(filename).name != filename or path.is_symlink() or path.suffix.lower() not in suffixes or not path.is_file():
        abort(404)
    return send_from_directory(directory, filename, as_attachment=True)


def build_parser():
    parser = argparse.ArgumentParser(description="VIPER Vision Dashboard")
    parser.add_argument("--log", default="logs/nids.log")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--demo", action="store_true")
    parser.add_argument("--captures", default="captures")
    parser.add_argument("--reports", default="reports")
    parser.add_argument("--interface", default="log replay")
    parser.add_argument("--api-key", default=None)
    parser.add_argument("--auth-user", default="viper")
    parser.add_argument("--development", action="store_true",
                        help="Use Flask's development server and optional WebSockets")
    return parser


def main():
    args = build_parser().parse_args()
    if args.demo and args.reports == "reports":
        args.reports = "reports/demo"
    key = args.api_key or os.getenv("VIPER_DASHBOARD_API_KEY", "")
    if not _is_loopback_host(args.host) and not key:
        raise SystemExit("Set VIPER_DASHBOARD_API_KEY before binding outside localhost")
    db = Path(args.reports) / ".index" / (hashlib.sha256(str(Path(args.log).resolve()).encode()).hexdigest()[:16] + ".sqlite")
    app = create_app(log_path=args.log, demo=args.demo, captures_dir=args.captures,
                     reports_dir=args.reports, interface=args.interface, api_key=key,
                     auth_username=args.auth_user, database_path=str(db),
                     settings_path=str(db.with_suffix(".settings.json")),
                     dashboard_options={"enable_websocket": args.development})
    from dashboard.server import serve_dashboard
    try:
        print(f"VIPER Vision listening on http://{args.host}:{args.port}", flush=True)
        serve_dashboard(app, args.host, args.port, development=args.development)
    finally:
        if app.extensions.get("viper_store"):
            app.extensions["viper_store"].close()


if __name__ == "__main__":
    main()
