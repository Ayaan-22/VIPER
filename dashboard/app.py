"""
dashboard/app.py
----------------
VIPER Vision dashboard for live log replay, historical analysis, and demo mode.

Usage:
    python dashboard/app.py --log logs/nids.log --port 5000
    python dashboard/app.py --demo
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hmac
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, Tuple

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

try:
    from flask import Flask, Response, jsonify, render_template, request, send_from_directory
except ImportError:
    print("Flask is not installed. Run: pip install flask", file=sys.stderr)
    sys.exit(1)

try:
    from flask_sock import Sock
except ImportError:  # WebSockets are optional; SSE still works without this.
    Sock = None

from dashboard.services.demo_data import build_demo_dataset
from dashboard.api.models import severity_rank
from dashboard.services.log_parser import parse_log
from dashboard.services.metrics_service import build_metrics, to_plain
from dashboard.services.report_service import generate_html_report
from dashboard.services.suspicious_connection_service import group_suspicious_connections
from dashboard.services.timeline_service import build_timeline, extract_port_scans


DEFAULT_SETTINGS = {
    "refresh_interval_seconds": 5,
    "max_alerts_displayed": 500,
    "default_time_range_minutes": 60,
    "severity_filters": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
    "chart_window_size": 60,
    "log_file_path": "logs/nids.log",
    "theme": "dark",
}


def create_app(
    *,
    log_path: str = "logs/nids.log",
    demo: bool = False,
    captures_dir: str = "captures",
    reports_dir: str = "reports",
    interface: str = "log replay",
    api_key: str | None = None,
    auth_username: str = "viper",
) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    resolved_log_path = Path(log_path).expanduser()
    allowed_log_dir = str(resolved_log_path.parent if resolved_log_path.parent != Path("") else Path("logs"))
    app.config.update(
        VIPER_LOG_PATH=log_path,
        VIPER_DEMO=demo,
        VIPER_CAPTURES_DIR=captures_dir,
        VIPER_REPORTS_DIR=reports_dir,
        VIPER_INTERFACE=interface,
        VIPER_API_KEY=api_key or os.getenv("VIPER_DASHBOARD_API_KEY", ""),
        VIPER_AUTH_USERNAME=os.getenv("VIPER_DASHBOARD_AUTH_USER", auth_username),
        VIPER_ALLOWED_LOG_DIR=os.getenv("VIPER_DASHBOARD_LOG_DIR", allowed_log_dir),
    )
    app.viper_settings = dict(DEFAULT_SETTINGS)
    app.viper_settings["log_file_path"] = log_path

    sock = Sock(app) if Sock else None

    @app.before_request
    def require_dashboard_auth():
        if request.endpoint == "static":
            return None
        api_key_value = app.config.get("VIPER_API_KEY")
        if not api_key_value or _request_has_valid_key(request, app.config["VIPER_AUTH_USERNAME"], api_key_value):
            return None
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="VIPER Vision"'},
        )

    def load_dataset() -> Tuple[list, list]:
        if app.config["VIPER_DEMO"]:
            return build_demo_dataset()
        return parse_log(app.config["VIPER_LOG_PATH"])

    def metrics_payload() -> Dict[str, Any]:
        alerts, packet_stats = load_dataset()
        mode = "demo" if app.config["VIPER_DEMO"] else "historical"
        metrics = build_metrics(
            alerts,
            packet_stats,
            interface="VIPER demo lab" if app.config["VIPER_DEMO"] else app.config["VIPER_INTERFACE"],
            engine_status=mode,
            top_limit=10,
        )
        return to_plain(metrics)

    @app.route("/")
    @app.route("/alerts")
    @app.route("/packets")
    @app.route("/talkers")
    @app.route("/protocols")
    @app.route("/port-scans")
    @app.route("/connections")
    @app.route("/timeline")
    @app.route("/reports")
    @app.route("/captures")
    @app.route("/settings")
    @app.route("/about")
    def index():
        return render_template("index.html", demo=app.config["VIPER_DEMO"])

    @app.get("/api/status")
    def api_status():
        alerts, packet_stats = load_dataset()
        mode = "demo" if app.config["VIPER_DEMO"] else "historical"
        summary = build_metrics(alerts, packet_stats, engine_status=mode).summary
        return jsonify(
            {
                "name": "VIPER Vision",
                "mode": mode,
                "demo": app.config["VIPER_DEMO"],
                "log_path": app.config["VIPER_LOG_PATH"],
                "alerts_loaded": len(alerts),
                "packet_stat_records": len(packet_stats),
                "engine_status": summary.engine_status,
                "generated_at": time.time(),
            }
        )

    @app.get("/api/metrics/summary")
    def api_summary():
        return jsonify(metrics_payload()["summary"])

    @app.get("/api/alerts")
    def api_alerts():
        alerts, _ = load_dataset()
        filtered = _filter_alerts(alerts, request.args)
        limit = int(request.args.get("limit", app.viper_settings["max_alerts_displayed"]))
        sort = request.args.get("sort", "timestamp")
        reverse = request.args.get("order", "desc") == "desc"
        if sort in {"timestamp", "severity", "detector", "src_ip", "dst_ip", "protocol"}:
            if sort == "severity":
                filtered.sort(key=lambda a: severity_rank(a.severity), reverse=reverse)
            else:
                filtered.sort(key=lambda a: getattr(a, sort) or "", reverse=reverse)
        return jsonify({"total": len(filtered), "alerts": [a.to_dict() for a in filtered[:limit]]})

    @app.get("/api/alerts/recent")
    def api_recent_alerts():
        alerts, _ = load_dataset()
        limit = int(request.args.get("limit", 25))
        return jsonify([a.to_dict() for a in alerts[-limit:]])

    @app.get("/api/alerts/severity")
    def api_alerts_severity():
        return jsonify(metrics_payload()["alerts_by_severity"])

    @app.get("/api/analytics/top-sources")
    def api_top_sources():
        return jsonify(metrics_payload()["top_sources"])

    @app.get("/api/analytics/top-destinations")
    def api_top_destinations():
        return jsonify(metrics_payload()["top_destinations"])

    @app.get("/api/analytics/top-ports")
    def api_top_ports():
        return jsonify(metrics_payload()["top_ports"])

    @app.get("/api/analytics/protocols")
    def api_protocols():
        return jsonify(metrics_payload()["protocols"])

    @app.get("/api/analytics/timeline")
    def api_timeline():
        alerts, _ = load_dataset()
        return jsonify(to_plain(build_timeline(_filter_alerts(alerts, request.args))))

    @app.get("/api/analytics/port-scans")
    def api_port_scans():
        alerts, _ = load_dataset()
        threshold = int(request.args.get("threshold", 15))
        return jsonify(to_plain(extract_port_scans(alerts, detection_threshold=threshold)))

    @app.get("/api/analytics/suspicious-connections")
    def api_suspicious_connections():
        alerts, _ = load_dataset()
        window = int(request.args.get("window", 120))
        return jsonify(to_plain(group_suspicious_connections(alerts, window_seconds=window)))

    @app.get("/api/reports")
    def api_reports():
        return jsonify(_list_files(app.config["VIPER_REPORTS_DIR"], ("*.txt", "*.json", "*.png", "*.html", "*.pdf")))

    @app.post("/api/reports/generate")
    def api_generate_report():
        alerts, packet_stats = load_dataset()
        path = generate_html_report(
            alerts,
            packet_stats,
            output_dir=app.config["VIPER_REPORTS_DIR"],
            mode="demo" if app.config["VIPER_DEMO"] else "historical",
        )
        return jsonify({"status": "generated", "path": path})

    @app.get("/api/captures")
    def api_captures():
        return jsonify(_list_files(app.config["VIPER_CAPTURES_DIR"], ("*.pcap", "*.pcapng", "*.cap")))

    @app.get("/api/settings")
    def api_get_settings():
        return jsonify(app.viper_settings)

    @app.patch("/api/settings")
    def api_patch_settings():
        updates = request.get_json(silent=True) or {}
        allowed = set(DEFAULT_SETTINGS)
        for key, value in updates.items():
            if key not in allowed:
                return jsonify({"error": f"Unsupported setting: {key}"}), 400
            if key in {"refresh_interval_seconds", "max_alerts_displayed", "default_time_range_minutes", "chart_window_size"}:
                try:
                    value = int(value)
                except (TypeError, ValueError):
                    return jsonify({"error": f"{key} must be an integer"}), 400
                if value <= 0:
                    return jsonify({"error": f"{key} must be positive"}), 400
            if key == "severity_filters":
                valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
                value = [str(item).upper() for item in value if str(item).upper() in valid]
            if key == "log_file_path":
                try:
                    value = str(_resolve_allowed_path(value, app.config["VIPER_ALLOWED_LOG_DIR"]))
                except ValueError as exc:
                    return jsonify({"error": str(exc)}), 400
            app.viper_settings[key] = value
            if key == "log_file_path":
                app.config["VIPER_LOG_PATH"] = str(value)
        return jsonify(app.viper_settings)

    @app.get("/api/stream/alerts")
    def stream_alerts():
        return Response(_sse_alert_stream(load_dataset), mimetype="text/event-stream")

    @app.get("/api/stream/metrics")
    def stream_metrics():
        return Response(_sse_metrics_stream(metrics_payload), mimetype="text/event-stream")

    if sock:
        @sock.route("/ws/alerts")
        def ws_alerts(ws):
            last_count = -1
            while True:
                alerts, _ = load_dataset()
                if len(alerts) != last_count:
                    ws.send(json.dumps([a.to_dict() for a in alerts[-25:]], default=str))
                    last_count = len(alerts)
                time.sleep(app.viper_settings["refresh_interval_seconds"])

        @sock.route("/ws/metrics")
        def ws_metrics(ws):
            while True:
                ws.send(json.dumps(metrics_payload(), default=str))
                time.sleep(app.viper_settings["refresh_interval_seconds"])
    else:
        @app.get("/ws/alerts")
        @app.get("/ws/metrics")
        def ws_unavailable():
            return jsonify({"error": "Install flask-sock to enable WebSocket routes; SSE endpoints are available."}), 426

    @app.get("/reports/<path:filename>")
    def download_report(filename: str):
        return send_from_directory(app.config["VIPER_REPORTS_DIR"], filename, as_attachment=False)

    return app


def _filter_alerts(alerts, args):
    results = list(alerts)
    severity = args.get("severity")
    detector = args.get("detector")
    src_ip = args.get("src_ip")
    dst_ip = args.get("dst_ip")
    protocol = args.get("protocol")
    query = (args.get("q") or "").lower()
    if severity:
        allowed = {item.strip().upper() for item in severity.split(",")}
        results = [a for a in results if a.severity in allowed]
    if detector:
        results = [a for a in results if a.detector == detector]
    if src_ip:
        results = [a for a in results if src_ip in a.src_ip]
    if dst_ip:
        results = [a for a in results if a.dst_ip and dst_ip in a.dst_ip]
    if protocol:
        results = [a for a in results if a.protocol == protocol.upper()]
    if query:
        results = [
            a
            for a in results
            if query in " ".join([a.title, a.description, a.detector, a.src_ip, a.dst_ip or "", a.protocol]).lower()
        ]
    return results


def _request_has_valid_key(req, username: str, expected_key: str) -> bool:
    supplied = req.headers.get("X-VIPER-API-Key", "")
    auth_header = req.headers.get("Authorization", "")
    if auth_header.lower().startswith("bearer "):
        supplied = auth_header[7:].strip()
    elif auth_header.lower().startswith("basic "):
        try:
            decoded = base64.b64decode(auth_header[6:], validate=True).decode("utf-8")
            supplied_user, supplied_password = decoded.split(":", 1)
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return False
        return (
            hmac.compare_digest(supplied_user, username)
            and hmac.compare_digest(supplied_password, expected_key)
        )
    return hmac.compare_digest(supplied, expected_key)


def _resolve_allowed_path(path_value: str, allowed_dir: str) -> Path:
    requested = Path(str(path_value)).expanduser()
    allowed = Path(allowed_dir).expanduser().resolve()
    if not requested.is_absolute():
        cwd_relative = requested.resolve()
        try:
            cwd_relative.relative_to(allowed)
            requested = cwd_relative
        except ValueError:
            requested = allowed / requested
    resolved = requested.resolve()
    try:
        resolved.relative_to(allowed)
    except ValueError as exc:
        raise ValueError(f"log_file_path must stay under {allowed}") from exc
    return resolved


def _is_loopback_host(host: str) -> bool:
    return host in {"", "localhost", "127.0.0.1", "::1"}


def _list_files(directory: str, patterns) -> list:
    base = Path(directory)
    if not base.exists():
        return []
    files = []
    for pattern in patterns:
        for path in base.glob(pattern):
            if path.is_file():
                stat = path.stat()
                files.append(
                    {
                        "name": path.name,
                        "path": str(path),
                        "size_bytes": stat.st_size,
                        "modified": stat.st_mtime,
                    }
                )
    files.sort(key=lambda item: item["modified"], reverse=True)
    return files


def _sse_alert_stream(load_dataset):
    last_ids = set()
    while True:
        alerts, _ = load_dataset()
        recent = alerts[-25:]
        new_ids = {a.alert_id for a in recent}
        if new_ids != last_ids:
            yield f"data: {json.dumps([a.to_dict() for a in recent], default=str)}\n\n"
            last_ids = new_ids
        time.sleep(2)


def _sse_metrics_stream(metrics_payload):
    while True:
        yield f"data: {json.dumps(metrics_payload(), default=str)}\n\n"
        time.sleep(5)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="VIPER Vision Dashboard")
    parser.add_argument("--log", default="logs/nids.log", help="Path to NIDS JSON log")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--demo", action="store_true", help="Run with simulated VIPER Vision demo data")
    parser.add_argument("--captures", default="captures", help="PCAP capture directory")
    parser.add_argument("--reports", default="reports", help="Report output directory")
    parser.add_argument("--interface", default="log replay", help="Interface label shown in the dashboard")
    parser.add_argument("--api-key", default=None, help="API key required for dashboard access")
    parser.add_argument("--auth-user", default="viper", help="Basic-auth username when API-key auth is enabled")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    configured_key = args.api_key or os.getenv("VIPER_DASHBOARD_API_KEY", "")
    if not _is_loopback_host(args.host) and not configured_key:
        print(
            "[ERROR] Set --api-key or VIPER_DASHBOARD_API_KEY before binding the dashboard outside localhost.",
            file=sys.stderr,
        )
        sys.exit(1)
    app = create_app(
        log_path=args.log,
        demo=args.demo,
        captures_dir=args.captures,
        reports_dir=args.reports,
        interface=args.interface,
        api_key=configured_key,
        auth_username=args.auth_user,
    )
    label = "demo mode" if args.demo else f"log: {args.log}"
    print(f"[*] VIPER Vision running at http://{args.host}:{args.port} ({label})")
    app.run(host=args.host, port=args.port, debug=False, threaded=True)


if __name__ == "__main__":
    main()
