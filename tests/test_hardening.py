"""Regression and integration coverage for the 2026-11-01 audit remediation."""
from __future__ import annotations

import json
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import Mock, patch

import pytest
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest
from scapy.utils import PcapReader
from dashboard.app import create_app
from dashboard.services.event_store import EventStore
from dashboard.services.log_parser import normalize_alert_record, parse_log
from dashboard.services.metrics_service import build_metrics
from dashboard.services.timeline_service import extract_port_scans
from src.alerting.alert import Alert, Severity
from src.alerting.handler import AlertHandler
from src.capture.pcap_writer import RotatingPcapWriter
from src.core.packet_processor import PacketProcessor
from src.core.sliding_window import SlidingWindow, SlidingWindowDict, AlertThrottle
from src.core.traffic import current_event
from src.detectors.anomaly import AnomalyDetector
from src.detectors.brute_force import BruteForceDetector
from src.detectors.flood_detectors import SynFloodDetector, UdpFloodDetector, IcmpFloodDetector
from src.detectors.port_scan import PortScanDetector
from src.utils.config_loader import load_config


class Recorder:
    def __init__(self):
        self.history = []
        self.lock = threading.Lock()

    def dispatch(self, alert):
        with self.lock:
            self.history.append(alert)


def packet(layer=None, ts=1000.0, src="192.0.2.1", dst="198.51.100.1", ipv6=False):
    net = IPv6(src="2001:db8::1", dst="2001:db8::2") if ipv6 else IP(src=src, dst=dst)
    result = net / (layer if layer is not None else UDP())
    result.time = ts
    return result


@pytest.mark.parametrize("cls,layer", [(SynFloodDetector, TCP(flags="S")), (UdpFloodDetector, UDP()), (IcmpFloodDetector, ICMP())])
def test_advancing_clock_first_packet_does_not_flood(cls, layer):
    handler = Recorder()
    detector = cls({}, handler)
    with patch("time.monotonic", side_effect=iter(100 + n * .00001 for n in range(100))):
        detector.process(packet(layer))
    assert handler.history == []


def test_explicit_zero_timestamp_and_full_window_rate():
    window = SlidingWindow(2)
    assert window.add(ts=0)
    assert window.rate(ts=0.00001) == .5
    assert window.count(ts=2) == 1
    assert window.count(ts=2.001) == 0


def test_late_window_events_are_rejected_and_budget_is_visible():
    windows = SlidingWindowDict(10, max_keys=2, max_events=3, max_events_per_key=2)
    for key, ts in (("a", 100), ("a", 101), ("a", 102), ("b", 102), ("c", 102)):
        windows.add(key, ts=ts)
    assert len(windows.keys()) <= 2
    assert windows.stats["events"] <= 3
    assert windows.stats["discarded_events"] >= 1
    assert windows.stats["evicted_keys"] == 1
    window = SlidingWindow(10)
    window.add(ts=2)
    assert not window.add(ts=1)
    assert window.late == 1


def test_atomic_throttle_under_synchronized_workers():
    throttle = AlertThrottle(5)
    start = threading.Barrier(16)
    def reserve(_):
        start.wait(timeout=3)
        return throttle.acquire("same", 100)
    with ThreadPoolExecutor(max_workers=16) as pool:
        assert sum(pool.map(reserve, range(16))) == 1
    assert not throttle.acquire("same", 105)
    assert throttle.acquire("same", 105.001)


def test_other_source_future_timestamp_does_not_expire_backlogged_history():
    windows = SlidingWindowDict(1, cleanup_interval=0)
    windows.add("backlogged", ts=1000)
    windows.add("newer-source", ts=1010)
    windows.add("backlogged", ts=1000.5)
    assert windows.count("backlogged", 1000.5) == 2


@pytest.mark.parametrize("ipv6", [False, True])
@pytest.mark.parametrize("flags", [0x02, 0x42, 0xC2])
def test_syn_flags_and_families_are_supported(ipv6, flags):
    handler = Recorder()
    PortScanDetector({"unique_ports_threshold": 1}, handler).process(packet(TCP(flags=flags), ipv6=ipv6))
    assert len(handler.history) == 1
    assert handler.history[0].dst_ip
    assert handler.history[0].metadata["protocol"] == "TCP"


@pytest.mark.parametrize("flags", [0, 1, 4, 0x12, 0x03, 0x22, 0x0A])
def test_response_or_malformed_syn_flags_are_not_attempts(flags):
    handler = Recorder()
    PortScanDetector({"unique_ports_threshold": 1}, handler).process(packet(TCP(flags=flags)))
    assert not handler.history


def test_ipv6_udp_icmp_and_anomaly():
    for cls, layer in ((UdpFloodDetector, UDP()), (IcmpFloodDetector, ICMPv6EchoRequest())):
        handler = Recorder()
        cls({"packets_per_second": 1}, handler).process(packet(layer, ipv6=True))
        assert len(handler.history) == 1
        assert handler.history[0].metadata["address_family"] == 6
    handler = Recorder()
    detector = AnomalyDetector({"min_samples": 2}, handler)
    for i in range(2):
        detector.process(packet(UDP(), ts=1000 + i, ipv6=True))
    detector.process(packet(UDP() / (b"x" * 400), ts=1002, ipv6=True))
    assert handler.history


def test_brute_force_deduplicates_retransmissions_and_separates_destinations():
    handler = Recorder()
    detector = BruteForceDetector({"attempts_threshold": 3}, handler)
    for i in range(10):
        detector.process(packet(TCP(flags="S", sport=10000, dport=22, seq=1), dst=f"198.51.100.{i + 1}"))
    assert handler.history == []
    original = packet(TCP(flags="S", sport=10000, dport=22, seq=1))
    for _ in range(10):
        detector.process(original)
    assert handler.history == []
    detector.process(packet(TCP(flags="S", sport=10001, dport=22, seq=2)))
    detector.process(packet(TCP(flags="S", sport=10002, dport=22, seq=3)))
    assert len(handler.history) == 1
    alert = handler.history[0]
    assert alert.dst_ip == "198.51.100.1"
    assert alert.metadata["attempts"] == 3
    assert alert.metadata["authentication_outcome"] == "unknown"


def test_host_sweep_is_distinct_from_multi_port_scan():
    handler = Recorder()
    detector = PortScanDetector({"unique_ports_threshold": 3, "unique_targets_threshold": 3}, handler)
    for i in range(3):
        detector.process(packet(TCP(flags="S", dport=443), dst=f"198.51.100.{i + 1}"))
    assert len(handler.history) == 1
    assert handler.history[0].metadata["scan_type"] == "host_sweep"
    normalized = normalize_alert_record(handler.history[0].to_log_dict())
    view = extract_port_scans([normalized])[0]
    assert view.scan_type == "host_sweep"
    assert view.unique_targets == 3
    assert len(view.sample_targets) == 3


def test_arrival_time_survives_backlog_and_source_order_is_preserved():
    observed = []
    gate, entered = threading.Event(), threading.Event()
    class Detector:
        name = "ordering"
        def process(self, pkt):
            if not observed:
                entered.set()
                assert gate.wait(3)
            observed.append(current_event.get().timestamp)
    processor = PacketProcessor([Detector()], worker_threads=4, stats_interval=60)
    processor.start()
    try:
        processor.enqueue(packet(ts=1000))
        assert entered.wait(2)
        processor.enqueue(packet(ts=1010))
        stop = threading.Thread(target=processor.stop)
        stop.start()
        assert stop.is_alive()
        gate.set()
        stop.join(3)
        assert not stop.is_alive()
        assert observed == [1000, 1010]
        assert processor.stats["processed"] == 2
        assert processor.stats["queued"] == 0
        assert not processor.enqueue(packet())
    finally:
        gate.set()
        processor.stop()


def test_backlogged_packets_ten_seconds_apart_do_not_share_flood_window():
    handler = Recorder()
    processor = PacketProcessor([UdpFloodDetector({"packets_per_second": 2}, handler)], worker_threads=2)
    processor.start()
    processor.enqueue(packet(ts=1000))
    processor.enqueue(packet(ts=1010))
    processor.stop()
    assert not handler.history
    assert processor.stats["protocol_counts"] == {"UDP": 2}


def test_processor_accounts_for_out_of_order_packet():
    processor = PacketProcessor([], worker_threads=1)
    processor.start()
    for ts in (10, 9, 11):
        processor.enqueue(packet(ts=ts))
    processor.stop()
    assert processor.stats["late_packets"] == 1
    assert processor.stats["dropped"] == 1
    assert processor.stats["processed"] == 2


def test_pcap_stop_flushes_actual_packets_and_retention(tmp_path):
    writer = RotatingPcapWriter(str(tmp_path), rotate_mb=.001, max_files=2)
    writer.start()
    for i in range(40):
        writer.write(packet(UDP() / (b"x" * 40), ts=i))
    writer.stop()
    assert writer.stats["written"] == 40
    assert writer.stats["errors"] == 0
    assert len(list(tmp_path.glob("*.pcap"))) <= 2
    count = 0
    for path in tmp_path.glob("*.pcap"):
        with PcapReader(str(path)) as reader:
            count += len(list(reader))
    assert count > 0
    writer.stop()


def test_smtp_uses_verifying_context_and_timeout():
    handler = AlertHandler({"console": {"enabled": False}})
    smtp = Mock()
    smtp.__enter__ = Mock(return_value=smtp)
    smtp.__exit__ = Mock(return_value=False)
    try:
        with patch("src.alerting.handler.smtplib.SMTP", return_value=smtp) as factory:
            handler._to_email(Alert(), {"smtp_host": "smtp.example.test", "smtp_port": 587,
                              "from_addr": "a@example.test", "to_addrs": ["b@example.test"],
                              "username": "test", "password": "dummy", "timeout_seconds": 3})
        assert factory.call_args.kwargs["timeout"] == 3
        context = smtp.starttls.call_args.kwargs["context"]
        assert context.check_hostname and context.verify_mode == ssl.CERT_REQUIRED
        assert handler.stats["notifications_sent"] == 1
    finally:
        handler.shutdown(wait=True)


def test_rolling_baseline_expires_and_does_not_train_on_anomalies():
    detector = AnomalyDetector({"min_samples": 2, "baseline_window_seconds": 10}, Recorder())
    for ts in (100, 101):
        detector.process(packet(ts=ts))
    detector.process(packet(UDP() / (b"x" * 500), ts=102))
    assert detector._profiles["192.0.2.1"].size_stats.n == 2
    detector.process(packet(ts=120))
    assert detector._profiles["192.0.2.1"].size_stats.n == 1


@pytest.mark.parametrize("section,key,value", [
    ("performance", "worker_threads", 0), ("performance", "queue_maxsize", 0),
    ("performance", "stats_interval", -1), ("performance", "worker_threads", True),
    ("capture", "max_files", 0), ("capture", "rotate_mb", float("inf")),
    ("reporting", "auto_report_interval", -1), ("reporting", "max_files", 0),
    ("dashboard", "port", 65536), ("dashboard", "enabled", "false"),
    ("dashboard", "max_live_alerts", 1000000), ("logging", "format", "csv"),
])
def test_invalid_config_is_rejected(tmp_path, section, key, value):
    import yaml
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump({section: {key: value}}), encoding="utf-8")
    with pytest.raises(ValueError):
        load_config(str(path))


def test_explicit_missing_configuration_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_config(str(tmp_path / "missing.yaml"))


def write_records(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def record(identifier="a", timestamp=1000, **fields):
    return {"ts": timestamp, "alert_id": identifier, "detector": "port_scan",
            "severity": "HIGH", "src_ip": "192.0.2.1", **fields}


def test_index_survives_rotation_restart_and_deduplicates(tmp_path):
    log, database = tmp_path / "nids.log", tmp_path / "index.sqlite"
    write_records(log, [record()])
    store = EventStore(log, str(database))
    assert len(store.snapshot()[0]) == 1
    log.rename(tmp_path / "nids.log.1")
    write_records(log, [record("b", 1001)])
    store.sync(force=True)
    assert [a.alert_id for a in store.snapshot()[0]] == ["a", "b"]
    assert len(store.after()[0]) == 2
    store.close()
    store = EventStore(log, str(database))
    try:
        assert [a.alert_id for a in store.snapshot()[0]] == ["a", "b"]
        first = store.snapshot()[0]
        assert store.snapshot()[0] is first
    finally:
        store.close()


def test_index_partial_lines_invalid_records_retention_and_stream_gap(tmp_path):
    log = tmp_path / "nids.log"
    log.write_text(json.dumps(record())[:-1], encoding="utf-8")
    store = EventStore(log, max_alerts=2)
    try:
        assert store.snapshot()[0] == []
        with log.open("a", encoding="utf-8") as out:
            out.write("}\n" + json.dumps(record("b", 1001)) + "\n")
            out.write('{"ts":"Infinity","alert_id":"bad"}\n')
            out.write(json.dumps(record("c", 1002)) + "\n" + json.dumps(record("d", 1003)) + "\n")
        store.sync(force=True)
        assert [a.alert_id for a in store.snapshot()[0]] == ["c", "d"]
        assert store.health["invalid_records"] == 1
        assert store.health["pruned_records"] == 2
        assert store.after(cursor=1)[1] is True
    finally:
        store.close()


def test_analytics_keep_unknown_evidence_unknown():
    alert = normalize_alert_record(record(rate_pps=500, unique_ports=3))
    metrics = build_metrics([alert], [{"timestamp": 1000, "received": 1000, "processed": 1000}])
    assert all(p.packet_count is None and p.percentage is None for p in metrics.protocols)
    assert metrics.top_sources[0].packet_count is None
    assert extract_port_scans([alert])[0].ports_touched == []
    measured = build_metrics([alert], [{"timestamp": 1000, "received": 1000, "processed": 1000,
                                       "protocol_counts": {"TCP": 700, "UDP": 300}}])
    assert next(p for p in measured.protocols if p.protocol == "UDP").percentage == 30


@pytest.fixture
def client(tmp_path):
    app = create_app(demo=True, api_key="test-key", reports_dir=str(tmp_path / "reports"),
                     captures_dir=str(tmp_path / "captures"), settings_path=str(tmp_path / "preferences.json"))
    app.testing = True
    with app.test_client() as client:
        client.environ_base["HTTP_X_VIPER_API_KEY"] = "test-key"
        yield client


@pytest.mark.parametrize("path", ["/api/alerts?limit=abc", "/api/alerts?limit=0", "/api/alerts?limit=-1",
                                   "/api/alerts?limit=1001", "/api/analytics/suspicious-connections?window=0",
                                   "/api/alerts?sort=notreal", "/api/alerts?since=Infinity",
                                   "/api/snapshot?minutes=-1", "/api/stream/alerts?after=-1"])
def test_bad_query_returns_controlled_400(client, path):
    assert client.get(path).status_code == 400


@pytest.mark.parametrize("payload", [[1], None, {"severity_filters": None}, {"severity_filters": [3]},
                                      {"severity_filters": ["UNSAFE"]}, {"theme": "unknown"}, {"theme": []},
                                      {"max_alerts_displayed": True}, {"log_file_path": ""}])
def test_bad_settings_are_atomic(client, payload):
    before = client.get("/api/settings").get_json()
    assert client.patch("/api/settings", json=payload).status_code == 400
    assert client.get("/api/settings").get_json() == before


def test_settings_persist_and_survive_invalid_later_field(client, tmp_path):
    assert client.patch("/api/settings", json={"refresh_interval_seconds": 10, "zzz": 1}).status_code == 400
    assert client.get("/api/settings").get_json()["refresh_interval_seconds"] == 5
    assert client.patch("/api/settings", json={"refresh_interval_seconds": 9, "theme": "light"}).status_code == 200
    app = create_app(demo=True, api_key="test-key", settings_path=str(tmp_path / "preferences.json"))
    with app.test_client() as second:
        settings = second.get("/api/settings", headers={"X-VIPER-API-Key": "test-key"}).get_json()
        assert settings["refresh_interval_seconds"] == 9
        assert settings["theme"] == "light"


def test_api_auth_origin_protection_and_download_containment(client, tmp_path):
    assert client.get("/api/status", headers={"X-VIPER-API-Key": "bad"}).status_code == 401
    assert client.post("/api/reports/generate", headers={"Origin": "https://outside.example"}).status_code == 403
    directory = tmp_path / "reports"
    directory.mkdir(exist_ok=True)
    (directory / "fixture.txt").write_text("evidence", encoding="utf-8")
    assert client.get("/reports/fixture.txt").data == b"evidence"
    assert client.get("/reports/../preferences.json").status_code == 404
    response = client.get("/api/snapshot")
    assert response.status_code == 200
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert response.get_json()["metrics"]["scope"]["protocol_packets"] == "measured counters only"


def test_report_generation_is_downloadable_and_labels_demo(client):
    response = client.post("/api/reports/generate")
    assert response.status_code == 200
    report = client.get(response.get_json()["url"])
    assert report.status_code == 200
    assert report.headers["Content-Disposition"].startswith("attachment")
    assert b"VIPER Vision" in report.data
    assert b"SIMULATED DATA" in report.data


def test_sensor_alert_to_logger_to_index_to_api(tmp_path):
    import logging
    from src.logger.logger import JsonFormatter
    path = tmp_path / "nids.log"
    handler = Recorder()
    detector = PortScanDetector({"unique_ports_threshold": 3}, handler)
    for port in (22, 80, 443):
        detector.process(packet(TCP(dport=port, flags="S"), ts=1000 + port / 1000))
    assert len(handler.history) == 1
    formatter = JsonFormatter()
    log_record = logging.makeLogRecord({"msg": "alert", **handler.history[0].to_log_dict()})
    path.write_text(formatter.format(log_record) + "\n", encoding="utf-8")
    app = create_app(log_path=str(path), api_key="test-key")
    try:
        with app.test_client() as test_client:
            response = test_client.get("/api/alerts", headers={"X-VIPER-API-Key": "test-key"})
            alert = response.get_json()["alerts"][0]
            assert alert["dst_ip"] == "198.51.100.1"
            assert alert["protocol"] == "TCP"
            assert alert["evidence"]["sample_ports"] == [22, 80, 443]
            assert test_client.get("/api/snapshot", headers={"X-VIPER-API-Key": "test-key"}).status_code == 200
    finally:
        app.extensions["viper_store"].close()


def engine_fixture(tmp_path):
    from src.core.engine import NIDSEngine
    config = load_config("config/config.example.yaml")
    for name in config.detection:
        config.set("detection", name, "enabled", value=name == "port_scan")
    config.set("detection", "port_scan", "unique_ports_threshold", value=3)
    config.set("reporting", "report_dir", value=str(tmp_path))
    config.set("reporting", "auto_report_interval", value=0)
    config.set("capture", "enabled", value=False)
    config.set("alerting", "console", "enabled", value=False)
    with patch.object(NIDSEngine, "_resolve_interface", return_value="fixture"), patch("src.core.engine.setup_logger"):
        return NIDSEngine(config)


def test_engine_capture_failure_cleans_up_and_restores_handlers(tmp_path):
    engine = engine_fixture(tmp_path)
    sniffer = Mock()
    sniffer.running = False
    sniffer.thread.is_alive.return_value = False
    sniffer.join.side_effect = PermissionError("fixture denied")
    with patch("scapy.all.AsyncSniffer", return_value=sniffer), patch.object(engine, "_final_report") as report:
        with pytest.raises(PermissionError):
            engine.start()
        assert not engine.processor._running
        assert all(not worker.is_alive() for worker in engine.processor._threads)
        report.assert_called_once()
    engine.stop()


def test_engine_final_report_is_after_last_detection_and_stop_is_idempotent(tmp_path):
    engine = engine_fixture(tmp_path)
    ready, halt = threading.Event(), threading.Event()
    failures = []
    class Sniffer:
        def __init__(self, **kwargs):
            self.callback = kwargs["prn"]
            self.running = False
        def start(self):
            self.running = True
            self.thread = threading.Thread(target=halt.wait, daemon=True)
            self.thread.start()
            for port in (22, 80, 443):
                self.callback(packet(TCP(flags="S", dport=port), ts=1000 + port / 1000))
            ready.set()
        def stop(self, join=True):
            self.running = False
            halt.set()
            self.thread.join(2)
        def join(self):
            self.thread.join(2)
    evidence = []
    def final_report():
        evidence.append((engine.processor.stats["processed"], len(engine.alert_handler.history)))
    def start():
        try:
            engine.start()
        except Exception as exc:
            failures.append(exc)
    with patch("scapy.all.AsyncSniffer", Sniffer), patch.object(engine, "_final_report", side_effect=final_report):
        thread = threading.Thread(target=start, daemon=True)
        thread.start()
        assert ready.wait(3)
        engine.stop()
        thread.join(3)
        assert not thread.is_alive()
        engine.stop()
    assert not failures
    assert evidence == [(3, 1)]


def test_processor_timeout_retry_does_not_claim_completion_early():
    entered, release = threading.Event(), threading.Event()
    class Slow:
        name = "slow"
        def process(self, pkt):
            entered.set()
            release.wait(3)
    processor = PacketProcessor([Slow()], worker_threads=1)
    processor.start()
    processor.enqueue(packet())
    assert entered.wait(2)
    try:
        with pytest.raises(TimeoutError):
            processor.stop(timeout=.01)
        with pytest.raises(TimeoutError):
            processor.stop(timeout=.01)
        assert not processor._closed
    finally:
        release.set()
        processor.stop()
    assert processor._closed


def test_record_budget_limits_encoded_payload_bytes(tmp_path):
    log = tmp_path / "nids.log"
    write_records(log, [record(str(i), 1000 + i, alert_message="x" * 400) for i in range(10)])
    store = EventStore(log, max_bytes=2000)
    try:
        store.sync(force=True)
        retained = store.db.execute("SELECT coalesce(sum(length(payload)),0) FROM events").fetchone()[0]
        assert retained <= 2000
        assert store.health["pruned_records"] > 0
    finally:
        store.close()


def test_stream_replays_more_than_25_alerts_and_reconnects_by_cursor(tmp_path):
    log = tmp_path / "nids.log"
    write_records(log, [record(str(i), 1000 + i) for i in range(40)])
    app = create_app(log_path=str(log), api_key="test-key")
    try:
        with app.test_client() as test_client:
            response = test_client.get("/api/stream/alerts", headers={"X-VIPER-API-Key": "test-key"}, buffered=False)
            iterator = iter(response.response)
            chunks = [next(iterator).decode() for _ in range(40)]
            assert all("id:" in chunk for chunk in chunks)
            cursor = chunks[-1].split("\n", 1)[0][4:]
            response.close()
            resumed = test_client.get("/api/stream/alerts", headers={"X-VIPER-API-Key": "test-key", "Last-Event-ID": cursor}, buffered=False)
            assert b"heartbeat" in next(iter(resumed.response))
            resumed.close()
    finally:
        app.extensions["viper_store"].close()


def test_production_server_uses_bounded_waitress_configuration():
    from dashboard.server import serve_dashboard
    with patch("waitress.serve") as serve:
        serve_dashboard(Mock(), "127.0.0.1", 5050)
    assert serve.call_args.kwargs["threads"] == 16
    assert serve.call_args.kwargs["connection_limit"] == 128
    assert serve.call_args.kwargs["expose_tracebacks"] is False


def test_report_retention_preserves_unowned_files(tmp_path):
    from src.reporting.retention import prune_reports
    for i in range(10):
        (tmp_path / f"report_{i}.txt").write_text("fixture", encoding="utf-8")
    (tmp_path / "operator-notes.txt").write_text("preserve", encoding="utf-8")
    prune_reports(tmp_path, max_files=4)
    assert len(list(tmp_path.glob("report_*.txt"))) == 4
    assert (tmp_path / "operator-notes.txt").read_text() == "preserve"


def test_native_sensor_health_distinguishes_stopped_and_fresh(tmp_path):
    from tools.healthcheck import sensor_health
    log = tmp_path / "nids.log"
    write_records(log, [{"message": "packet_stats", "ts": time.time(), "sensor_running": True}])
    assert sensor_health(log)
    write_records(log, [{"message": "packet_stats", "ts": time.time(), "sensor_running": False}])
    assert not sensor_health(log)


def test_report_charts_render_with_patched_image_dependencies(tmp_path, monkeypatch):
    from src.reporting.reporter import Visualizer
    from PIL import Image
    monkeypatch.setenv("MPLCONFIGDIR", str(tmp_path / "matplotlib"))
    alerts = [Alert(detector="port_scan", severity=Severity.HIGH),
              Alert(detector="udp_flood", severity=Severity.CRITICAL)]
    visualizer = Visualizer(str(tmp_path))
    for name in (visualizer.plot_traffic_distribution(alerts), visualizer.plot_severity_pie(alerts)):
        with Image.open(name) as image:
            image.verify()
        assert Path(name).stat().st_size > 1000


def test_metadata_cannot_override_canonical_security_fields():
    alert = Alert(src_ip="192.0.2.1", severity=Severity.HIGH,
                  metadata={"src_ip": "forged", "severity": "LOW", "message": "reserved", "levelname": "reserved"})
    result = alert.to_log_dict()
    assert result["src_ip"] == "192.0.2.1"
    assert result["severity"] == "HIGH"
    assert "message" not in result and "levelname" not in result


def test_native_zero_protocol_counters_are_measured_zero():
    metrics = build_metrics([], [{"timestamp": 1000, "received": 0, "processed": 0, "protocol_counts": {}}])
    assert all(item.packet_count == 0 and item.percentage == 0 for item in metrics.protocols)


def test_metrics_endpoint_is_authenticated_and_labels_demo(client):
    response = client.get("/metrics")
    assert response.status_code == 200
    assert b"viper_simulated_data 1" in response.data
    assert client.get("/metrics", headers={"X-VIPER-API-Key": "bad"}).status_code == 401


def test_stream_capacity_is_bounded_and_slots_release():
    app = create_app(demo=True, api_key="test-key")
    headers = {"X-VIPER-API-Key": "test-key"}
    responses = []
    try:
        for _ in range(4):
            responses.append(app.test_client().get("/api/stream/alerts", headers=headers, buffered=False))
        assert all(response.status_code == 200 for response in responses)
        assert app.test_client().get("/api/stream/alerts", headers=headers).status_code == 429
    finally:
        for response in responses:
            response.close()
    response = app.test_client().get("/api/stream/alerts", headers=headers, buffered=False)
    assert response.status_code == 200
    response.close()


def test_demo_does_not_expose_native_capture_artifacts(tmp_path):
    captures = tmp_path / "captures"
    captures.mkdir()
    (captures / "native.pcap").write_bytes(b"private-fixture")
    app = create_app(demo=True, captures_dir=str(captures), api_key="test-key")
    with app.test_client() as test_client:
        headers = {"X-VIPER-API-Key": "test-key"}
        assert test_client.get("/api/captures", headers=headers).get_json() == []
        assert test_client.get("/captures/native.pcap", headers=headers).status_code == 404


def test_unknown_severity_is_quarantined_not_downgraded(tmp_path):
    log = tmp_path / "nids.log"
    write_records(log, [record("bad", severity='HIGH" onmouseover="unsafe'), record("valid")])
    store = EventStore(log)
    try:
        alerts, _ = store.snapshot()
        assert [alert.alert_id for alert in alerts] == ["valid"]
        assert store.health["invalid_records"] == 1
    finally:
        store.close()


def test_absent_traffic_telemetry_is_unknown_not_zero():
    summary = build_metrics([], []).summary
    assert summary.total_packets is None
    assert summary.processed_packets is None
    assert summary.dropped_packets is None
    assert summary.packets_per_second is None


def test_live_time_range_does_not_reanchor_to_an_old_alert(tmp_path):
    log = tmp_path / "live.log"
    now = time.time()
    write_records(log, [record("yesterday", now - 86400),
                        {"message": "packet_stats", "ts": now, "sensor_running": True,
                         "session_id": "live", "received": 1, "processed": 1}])
    app = create_app(log_path=str(log), api_key="test-key")
    try:
        response = app.test_client().get("/api/snapshot?minutes=60", headers={"X-VIPER-API-Key": "test-key"})
        assert response.get_json()["status"]["mode"] == "live"
        assert response.get_json()["alerts"]["total"] == 0
    finally:
        app.extensions["viper_store"].close()


def test_settings_io_failure_does_not_publish_unpersisted_state(tmp_path):
    preferences = tmp_path / "preferences.json"
    app = create_app(demo=True, api_key="test-key", settings_path=str(preferences))
    app.testing = False
    client = app.test_client()
    headers = {"X-VIPER-API-Key": "test-key"}
    assert client.patch("/api/settings", json={"theme": "dark"}, headers=headers).status_code == 200
    persisted = preferences.read_bytes()
    before = client.get("/api/settings", headers=headers).get_json()
    with patch("pathlib.Path.replace", side_effect=OSError("fixture disk failure")):
        response = client.patch("/api/settings", json={"theme": "light"}, headers=headers)
    assert response.status_code == 503
    assert client.get("/api/settings", headers=headers).get_json() == before
    assert preferences.read_bytes() == persisted
    assert list(tmp_path.glob(".preferences-*.tmp")) == []


@pytest.mark.parametrize("same_size", [False, True])
def test_index_detects_copytruncate_even_after_file_regrows(tmp_path, same_size):
    log = tmp_path / "nids.log"
    write_records(log, [record("old", 1000, alert_message="old")])
    store = EventStore(log)
    try:
        assert len(store.snapshot()[0]) == 1
        replacement = [record("new", 1001, alert_message="new")] if same_size else [record("new-first", 1001, alert_message="x" * 500), record("new-last", 1002)]
        original_size = log.stat().st_size
        write_records(log, replacement)
        if same_size:
            assert log.stat().st_size == original_size
        store.sync(force=True)
        assert {a.alert_id for a in store.snapshot()[0]} == {"old", *(r["alert_id"] for r in replacement)}
        assert store.health["source_resets"] == 1
    finally:
        store.close()


def test_pcap_start_failure_still_closes_open_writer(tmp_path):
    writer = RotatingPcapWriter(str(tmp_path))
    fake = Mock()
    with patch("src.capture.pcap_writer.PcapWriter", return_value=fake), patch.object(writer, "_cleanup_old_files", side_effect=OSError("fixture retention failure")):
        with pytest.raises(OSError):
            writer.start()
        fake.close.assert_called_once()
        writer.stop()
    fake.close.assert_called_once()


def test_pcap_thread_start_failure_closes_writer_and_rejects_writes(tmp_path):
    writer = RotatingPcapWriter(str(tmp_path))
    fake = Mock()
    with patch("src.capture.pcap_writer.PcapWriter", return_value=fake), patch("threading.Thread.start", side_effect=RuntimeError("fixture thread failure")):
        with pytest.raises(RuntimeError):
            writer.start()
        writer.stop()
    fake.close.assert_called_once()
    assert writer.write(b"late") is False
    assert writer.stats["running"] is False


def test_existing_index_migrates_and_checkpoints_an_unchanged_file(tmp_path):
    import sqlite3
    log, database = tmp_path / "nids.log", tmp_path / "index.sqlite"
    write_records(log, [record("old", 1000)])
    stat = log.stat()
    with sqlite3.connect(database) as db:
        db.execute("CREATE TABLE files (identity TEXT PRIMARY KEY, offset INTEGER, skipping INTEGER)")
        db.execute("INSERT INTO files VALUES(?,?,0)", (f"{stat.st_dev}:{stat.st_ino}", stat.st_size))
    store = EventStore(log, database)
    try:
        store.sync(force=True)
        assert store.db.execute("SELECT checkpoint FROM files").fetchone()[0]
        write_records(log, [record("new", 1001)])
        store.sync(force=True)
        assert [a.alert_id for a in store.snapshot()[0]] == ["new"]
    finally:
        store.close()
