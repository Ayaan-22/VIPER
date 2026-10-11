from __future__ import annotations

import json
import os
import tempfile
import unittest
from base64 import b64encode
from pathlib import Path
from unittest.mock import patch

from dashboard.services.log_parser import parse_log
from dashboard.services.metrics_service import build_metrics, protocol_breakdown, top_talkers
from dashboard.services.suspicious_connection_service import group_suspicious_connections
from dashboard.services.timeline_service import build_timeline, extract_port_scans


class DashboardServiceTests(unittest.TestCase):
    def _sample_log(self) -> str:
        records = [
            {"ts": "2026-01-01T00:00:00.000Z", "message": "packet_stats", "received": 100, "processed": 95, "dropped": 1, "queued": 4},
            {"ts": "2026-01-01T00:00:10.000Z", "message": "packet_stats", "received": 250, "processed": 240, "dropped": 1, "queued": 0},
            {
                "ts": 1767225620.0,
                "message": "alert",
                "alert_id": "a1",
                "detector": "port_scan",
                "severity": "HIGH",
                "src_ip": "203.0.113.10",
                "dst_ip": "10.0.0.5",
                "dst_port": 22,
                "alert_message": "Port scan detected",
                "unique_ports": 18,
                "sample_ports": [21, 22, 80],
            },
            {
                "ts": 1767225630.0,
                "message": "alert",
                "alert_id": "a2",
                "detector": "udp_flood",
                "severity": "CRITICAL",
                "src_ip": "203.0.113.10",
                "dst_ip": "10.0.0.53",
                "dst_port": 53,
                "alert_message": "UDP flood: 300 pkt/s",
                "rate_pps": 300,
            },
        ]
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
        for record in records:
            tmp.write(json.dumps(record) + "\n")
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_log_parser_reads_alerts_and_packet_stats(self):
        alerts, packet_stats = parse_log(self._sample_log())
        self.assertEqual(len(alerts), 2)
        self.assertEqual(len(packet_stats), 2)
        self.assertEqual(alerts[0].detector, "port_scan")
        self.assertEqual(alerts[1].protocol, "UDP")

    def test_metrics_aggregation(self):
        alerts, packet_stats = parse_log(self._sample_log())
        metrics = build_metrics(alerts, packet_stats)
        self.assertEqual(metrics.summary.total_packets, 250)
        self.assertEqual(metrics.alerts_by_severity["CRITICAL"], 1)
        self.assertEqual(metrics.top_sources[0].ip, "203.0.113.10")

    def test_top_talker_and_protocol_breakdown(self):
        alerts, packet_stats = parse_log(self._sample_log())
        talkers = top_talkers(alerts)
        protocols = protocol_breakdown(alerts, packet_stats)
        self.assertEqual(talkers[0].alert_count, 2)
        self.assertTrue(any(item.protocol == "UDP" and item.alert_count == 1 for item in protocols))

    def test_timeline_and_port_scan_extraction(self):
        alerts, _ = parse_log(self._sample_log())
        timeline = build_timeline(alerts)
        scans = extract_port_scans(alerts, detection_threshold=15)
        self.assertEqual(timeline[0].event_type, "Port scan started")
        self.assertEqual(scans[0].unique_ports, 18)

    def test_suspicious_connection_grouping(self):
        alerts, _ = parse_log(self._sample_log())
        groups = group_suspicious_connections(alerts, window_seconds=120)
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(group.alert_count >= 1 for group in groups))


class DashboardApiTests(unittest.TestCase):
    def _sample_log(self) -> str:
        records = [
            {
                "ts": 1767225620.0,
                "message": "alert",
                "alert_id": "a1",
                "detector": "port_scan",
                "severity": "HIGH",
                "src_ip": "203.0.113.10",
                "dst_ip": "10.0.0.5",
                "dst_port": 22,
                "alert_message": "Port scan detected",
            },
            {
                "ts": 1767225630.0,
                "message": "alert",
                "alert_id": "a2",
                "detector": "udp_flood",
                "severity": "CRITICAL",
                "src_ip": "203.0.113.10",
                "dst_ip": "10.0.0.53",
                "dst_port": 53,
                "alert_message": "UDP flood: 300 pkt/s",
            },
        ]
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False, encoding="utf-8")
        for record in records:
            tmp.write(json.dumps(record) + "\n")
        tmp.close()
        self.addCleanup(lambda: Path(tmp.name).unlink(missing_ok=True))
        return tmp.name

    def test_demo_api_status(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        app = create_app(demo=True)
        app.testing = True
        with app.test_client() as client:
            status = client.get("/api/status")
            summary = client.get("/api/metrics/summary")
        self.assertEqual(status.status_code, 200)
        self.assertTrue(status.get_json()["demo"])
        self.assertEqual(summary.status_code, 200)
        self.assertGreater(summary.get_json()["alerts_generated"], 0)

    def test_api_requires_configured_key(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        app = create_app(demo=True, api_key="secret")
        app.testing = True
        auth = b64encode(b"viper:secret").decode("ascii")
        with app.test_client() as client:
            unauthorized = client.get("/api/status")
            authorized = client.get("/api/status", headers={"Authorization": f"Basic {auth}"})
        self.assertEqual(unauthorized.status_code, 401)
        self.assertEqual(authorized.status_code, 200)

    def test_create_app_warns_when_api_key_missing_without_changing_no_key_access(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        with patch.dict(os.environ, {"VIPER_DASHBOARD_API_KEY": ""}):
            with self.assertLogs("dashboard.app", level="WARNING") as logs:
                app = create_app(demo=True)
        app.testing = True
        with app.test_client() as client:
            response = client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertIn("API key is not configured", "\n".join(logs.output))

    def test_alerts_sort_severity_by_rank(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        app = create_app(log_path=self._sample_log())
        app.testing = True
        with app.test_client() as client:
            response = client.get("/api/alerts?sort=severity&order=desc")
        self.assertEqual(response.status_code, 200)
        severities = [item["severity"] for item in response.get_json()["alerts"]]
        self.assertEqual(severities, ["CRITICAL", "HIGH"])

    def test_settings_reject_log_path_outside_allowed_dir(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        log_path = self._sample_log()
        outside = Path(log_path).resolve().parent.parent / "outside.log"
        app = create_app(log_path=log_path)
        app.testing = True
        with app.test_client() as client:
            response = client.patch("/api/settings", json={"log_file_path": str(outside)})
        self.assertEqual(response.status_code, 400)

    def test_settings_reject_empty_log_path(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        app = create_app(log_path="logs/nids.log", api_key="secret")
        app.testing = True
        with app.test_client() as client:
            response = client.patch(
                "/api/settings",
                json={"log_file_path": ""},
                headers={"X-VIPER-API-Key": "secret"},
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("must not be empty", response.get_json()["error"])

    def test_settings_accept_cwd_relative_log_path_in_allowed_dir(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        app = create_app(log_path="logs/nids.log")
        app.testing = True
        with app.test_client() as client:
            response = client.patch("/api/settings", json={"log_file_path": "logs/nids.log"})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["log_file_path"].endswith(str(Path("logs/nids.log"))))

    def test_bare_log_filename_defaults_allowed_log_dir_to_logs(self):
        try:
            from dashboard.app import create_app
        except SystemExit:
            self.skipTest("Flask is not installed")

        with patch.dict(os.environ, {"VIPER_DASHBOARD_LOG_DIR": ""}):
            app = create_app(log_path="nids.log", api_key="secret")
        self.assertEqual(app.config["VIPER_ALLOWED_LOG_DIR"], "logs")


class DashboardConfigTests(unittest.TestCase):
    def test_dashboard_defaults_exist(self):
        try:
            from src.utils.config_loader import load_config
        except ImportError:
            self.skipTest("PyYAML is not installed")
        cfg = load_config(path="/nonexistent/path.yaml")
        self.assertEqual(cfg.dashboard["port"], 5000)
        self.assertEqual(cfg.analytics["suspicious_group_window_seconds"], 120)


if __name__ == "__main__":
    unittest.main()
