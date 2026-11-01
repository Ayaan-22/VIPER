"""
tests/test_detectors.py
-----------------------
Unit tests for the NIDS detection engine.

Run with:  pytest tests/ -v

The tests mock Scapy packets to avoid needing root or a live interface.
"""

from __future__ import annotations

import time
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# ---------------------------------------------------------------------------
# Minimal stubs so the tests run without scapy installed in CI
# ---------------------------------------------------------------------------
import sys
import types

# Stub scapy only if not available
try:
    import scapy  # noqa: F401
    _SCAPY_AVAILABLE = True
except ImportError:
    _SCAPY_AVAILABLE = False
    # Create minimal stubs
    scapy_stub = types.ModuleType("scapy")
    scapy_all  = types.ModuleType("scapy.all")
    scapy_pkt  = types.ModuleType("scapy.packet")
    scapy_inet = types.ModuleType("scapy.layers.inet")
    scapy_utils= types.ModuleType("scapy.utils")
    for m, name in [
        (scapy_stub, "scapy"),
        (scapy_all,  "scapy.all"),
        (scapy_pkt,  "scapy.packet"),
        (scapy_inet, "scapy.layers.inet"),
        (scapy_utils,"scapy.utils"),
    ]:
        sys.modules[name] = m

    class _FakePacket:
        pass
    scapy_pkt.Packet = _FakePacket
    scapy_inet.IP = type("IP", (), {})
    scapy_inet.TCP= type("TCP", (), {})
    scapy_inet.UDP= type("UDP", (), {})
    scapy_inet.ICMP=type("ICMP",(), {})


# Now import the project modules
from src.core.sliding_window import SlidingWindow, SlidingWindowDict
from src.alerting.alert import Alert, Severity, severity_gte
from src.alerting.handler import AlertHandler


# ---------------------------------------------------------------------------
# Helper: build a fake Scapy-like packet
# ---------------------------------------------------------------------------

def _make_packet(src_ip: str, dst_ip: str = "10.0.0.1",
                 proto: str = "TCP", flags: int = 0x02,
                 dport: int = 80, length: int = 64):
    """
    Returns a MagicMock that mimics a Scapy IP+TCP/UDP/ICMP packet.
    ``flags=0x02`` == SYN-only.
    """
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    pkt = MagicMock()
    pkt.__len__ = MagicMock(return_value=length)

    ip_layer  = MagicMock()
    ip_layer.src = src_ip
    ip_layer.dst = dst_ip

    tcp_layer = MagicMock()
    tcp_layer.flags = flags
    tcp_layer.dport = dport

    udp_layer = MagicMock()
    udp_layer.dport = dport

    icmp_layer = MagicMock()

    # haslayer() returns True for the right layers
    def _has(layer):
        if layer is IP:
            return True
        if layer is TCP:
            return proto == "TCP"
        if layer is UDP:
            return proto == "UDP"
        if layer is ICMP:
            return proto == "ICMP"
        return False

    pkt.haslayer = _has

    # __getitem__ subscript syntax: pkt[IP].src
    # MagicMock routes pkt[layer] through side_effect(layer)
    def _getitem(layer):
        if layer is IP:
            return ip_layer
        if layer is TCP:
            return tcp_layer
        if layer is UDP:
            return udp_layer
        if layer is ICMP:
            return icmp_layer
        raise KeyError(layer)

    pkt.__getitem__ = MagicMock(side_effect=_getitem)
    return pkt


# ---------------------------------------------------------------------------
# SlidingWindow tests
# ---------------------------------------------------------------------------

class TestSlidingWindow(unittest.TestCase):

    def test_count_within_window(self):
        w = SlidingWindow(window_seconds=5)
        for _ in range(10):
            w.add()
        self.assertEqual(w.count(), 10)

    def test_events_expire(self):
        w = SlidingWindow(window_seconds=0.1)
        w.add()
        w.add()
        time.sleep(0.15)
        self.assertEqual(w.count(), 0)

    def test_unique_values(self):
        w = SlidingWindow(window_seconds=5)
        for port in [80, 443, 8080, 80, 443]:
            w.add(port)
        self.assertEqual(w.unique_values(), {80, 443, 8080})

    def test_rate_is_positive(self):
        w = SlidingWindow(window_seconds=1)
        for _ in range(50):
            w.add()
        self.assertGreater(w.rate(), 0)

    def test_clear(self):
        w = SlidingWindow(window_seconds=5)
        for _ in range(5):
            w.add()
        w.clear()
        self.assertEqual(w.count(), 0)

    def test_thread_safety(self):
        w = SlidingWindow(window_seconds=5)
        errors = []

        def adder():
            try:
                for _ in range(100):
                    w.add()
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=adder) for _ in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()

        self.assertEqual(len(errors), 0)
        self.assertEqual(w.count(), 1000)


class TestSlidingWindowDict(unittest.TestCase):

    def test_per_key_isolation(self):
        d = SlidingWindowDict(window_seconds=5)
        d.add("key_a")
        d.add("key_a")
        d.add("key_b")
        self.assertEqual(d.count("key_a"), 2)
        self.assertEqual(d.count("key_b"), 1)

    def test_unique_values_per_key(self):
        d = SlidingWindowDict(window_seconds=5)
        for v in [22, 80, 443, 22]:
            d.add("attacker", v)
        self.assertEqual(d.unique_values("attacker"), {22, 80, 443})


# ---------------------------------------------------------------------------
# Alert model tests
# ---------------------------------------------------------------------------

class TestAlert(unittest.TestCase):

    def test_severity_ordering(self):
        self.assertTrue(severity_gte(Severity.CRITICAL, Severity.HIGH))
        self.assertTrue(severity_gte(Severity.HIGH, Severity.HIGH))
        self.assertFalse(severity_gte(Severity.LOW, Severity.MEDIUM))

    def test_to_dict_has_required_keys(self):
        a = Alert(
            detector="port_scan",
            severity=Severity.HIGH,
            src_ip="1.2.3.4",
            message="test",
        )
        d = a.to_dict()
        for key in ("alert_id", "timestamp", "detector", "severity", "src_ip", "message"):
            self.assertIn(key, d)
        self.assertEqual(d["severity"], "HIGH")

    def test_str_representation(self):
        a = Alert(detector="syn_flood", severity=Severity.CRITICAL,
                  src_ip="10.0.0.1", message="flood detected")
        self.assertIn("CRITICAL", str(a))
        self.assertIn("10.0.0.1", str(a))


# ---------------------------------------------------------------------------
# AlertHandler tests
# ---------------------------------------------------------------------------

class TestAlertHandler(unittest.TestCase):

    def _make_handler(self, min_sev="LOW"):
        cfg = {
            "severity_filter": min_sev,
            "console": {"enabled": False},   # suppress output during tests
            "email":   {"enabled": False},
            "webhook": {"enabled": False},
        }
        return AlertHandler(cfg)

    def test_alert_stored_in_history(self):
        h = self._make_handler()
        a = Alert(detector="test", severity=Severity.HIGH,
                  src_ip="1.1.1.1", message="hi")
        h.dispatch(a)
        self.assertIn(a, h.history)

    def test_severity_filter_low(self):
        h = self._make_handler(min_sev="HIGH")
        low_alert  = Alert(detector="x", severity=Severity.LOW,  src_ip="1.1.1.1", message="")
        high_alert = Alert(detector="x", severity=Severity.HIGH, src_ip="1.1.1.1", message="")
        h.dispatch(low_alert)
        h.dispatch(high_alert)
        self.assertNotIn(low_alert, h.history)
        self.assertIn(high_alert, h.history)

    def test_clear_history(self):
        h = self._make_handler()
        h.dispatch(Alert(detector="t", severity=Severity.LOW, src_ip="1.1.1.1", message=""))
        h.clear_history()
        self.assertEqual(len(h.history), 0)

    def test_severity_filter_accepts_lowercase(self):
        h = self._make_handler(min_sev="high")
        low_alert = Alert(detector="x", severity=Severity.LOW, src_ip="1.1.1.1", message="")
        high_alert = Alert(detector="x", severity=Severity.HIGH, src_ip="1.1.1.1", message="")
        h.dispatch(low_alert)
        h.dispatch(high_alert)
        self.assertNotIn(low_alert, h.history)
        self.assertIn(high_alert, h.history)
        h.shutdown()

    def test_async_delivery_is_bounded(self):
        h = AlertHandler({
            "severity_filter": "LOW",
            "console": {"enabled": False},
            "email": {
                "enabled": True,
                "min_severity": "LOW",
                "from_addr": "nids@example.test",
                "to_addrs": ["ops@example.test"],
                "smtp_host": "localhost",
                "smtp_port": 25,
                "username": "u",
                "password": "p",
            },
            "webhook": {"enabled": False},
            "max_delivery_workers": 1,
            "max_delivery_queue": 0,
        })
        gate = threading.Event()
        sent = []

        def slow_email(alert, cfg):
            sent.append(alert.alert_id)
            gate.wait(1)

        h._to_email = slow_email
        first = Alert(detector="x", severity=Severity.LOW, src_ip="1.1.1.1", message="")
        second = Alert(detector="x", severity=Severity.LOW, src_ip="1.1.1.2", message="")
        h.dispatch(first)
        h.dispatch(second)
        time.sleep(0.1)
        gate.set()
        h.shutdown(wait=True)
        self.assertEqual(sent, [first.alert_id])


# ---------------------------------------------------------------------------
# Detector tests (using mock packets)
# ---------------------------------------------------------------------------

def _silent_handler():
    return AlertHandler({
        "severity_filter": "LOW",
        "console": {"enabled": False},
        "email":   {"enabled": False},
        "webhook": {"enabled": False},
    })


class TestPortScanDetector(unittest.TestCase):

    def test_fires_after_threshold(self):
        from src.detectors.port_scan import PortScanDetector
        cfg = {"enabled": True, "unique_ports_threshold": 5, "window_seconds": 10, "whitelist_ips": []}
        h = _silent_handler()
        det = PortScanDetector(cfg, h)

        for port in range(1, 6):          # 5 unique ports → exactly at threshold
            pkt = _make_packet("1.2.3.4", dport=port)
            det.process(pkt)

        self.assertGreater(len(h.history), 0)
        self.assertEqual(h.history[0].detector, "port_scan")

    def test_no_fire_below_threshold(self):
        from src.detectors.port_scan import PortScanDetector
        cfg = {"enabled": True, "unique_ports_threshold": 15, "window_seconds": 10, "whitelist_ips": []}
        h = _silent_handler()
        det = PortScanDetector(cfg, h)

        for port in range(1, 5):          # only 4 unique ports
            pkt = _make_packet("1.2.3.4", dport=port)
            det.process(pkt)

        self.assertEqual(len(h.history), 0)

    def test_whitelist_skipped(self):
        from src.detectors.port_scan import PortScanDetector
        cfg = {"enabled": True, "unique_ports_threshold": 3, "window_seconds": 10,
               "whitelist_ips": ["1.2.3.4"]}
        h = _silent_handler()
        det = PortScanDetector(cfg, h)

        for port in range(1, 10):
            pkt = _make_packet("1.2.3.4", dport=port)
            det.process(pkt)

        self.assertEqual(len(h.history), 0)


class _FloodDetectorBehaviorTests:
    """Run the same observable contract against each public flood detector."""

    def setUp(self):
        # Keep real sliding windows, with deterministic time and no sleeps.
        clock_patch = patch("src.core.sliding_window.time.monotonic", return_value=100.0)
        self.clock = clock_patch.start()
        self.addCleanup(clock_patch.stop)

    def _make_detector(self, cfg=None):
        from src.detectors import flood_detectors
        handler = _silent_handler()
        self.addCleanup(handler.shutdown)
        detector = getattr(flood_detectors, self.detector_class)(
            {} if cfg is None else cfg, handler
        )
        return detector, handler

    def _packet(self, src_ip="2.2.2.2"):
        return _make_packet(src_ip, proto=self.protocol)

    def test_defaults_and_detector_identity(self):
        det, handler = self._make_detector()
        packet = self._packet()
        for _ in range(99):
            det.process(packet)
        self.assertEqual(handler.history, [])

        det.process(packet)
        self.assertEqual(len(handler.history), 1)
        alert = handler.history[0]
        self.assertEqual(det.name, self.detector_name)
        self.assertEqual(alert.detector, self.detector_name)
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.src_ip, "2.2.2.2")
        self.assertEqual(alert.dst_ip, "10.0.0.1")
        self.assertEqual(alert.dst_port, 80 if self.protocol in {"TCP", "UDP"} else None)
        self.assertEqual(alert.message, f"{self.label} flood: 100 pkt/s (threshold 100)")
        self.assertEqual(alert.metadata["rate_pps"], 100.0)
        self.assertEqual(alert.metadata["threshold_pps"], 100)
        self.assertEqual(alert.metadata["protocol"], self.protocol)
        self.assertEqual(det.alert_count, 1)

    def test_configured_threshold_and_window(self):
        cfg = {"enabled": True, "packets_per_second": 2.5,
               "window_seconds": 2, "whitelist_ips": []}
        det, handler = self._make_detector(cfg)
        packet = self._packet()
        for _ in range(4):
            det.process(packet)
        self.assertEqual(handler.history, [])
        det.process(packet)
        self.assertEqual(len(handler.history), 1)
        alert = handler.history[0]
        self.assertEqual(alert.severity, Severity.HIGH)
        self.assertEqual(alert.message, f"{self.label} flood: 2 pkt/s (threshold 2.5)")
        self.assertEqual(alert.metadata["rate_pps"], 2.5)
        self.assertEqual(alert.metadata["window_seconds"], 2)

    def test_threshold_and_severity_boundaries(self):
        for count, expected in ((7, None), (8, Severity.HIGH), (15, Severity.HIGH), (16, Severity.CRITICAL)):
            with self.subTest(count=count):
                det, handler = self._make_detector({"packets_per_second": 8})
                # Reserve the throttle during accumulation, then release via time.
                for _ in range(count - 1):
                    det._windows.add("2.2.2.2", ts=100.0)
                det.process(self._packet())
                self.assertEqual(len(handler.history), int(expected is not None))
                if expected:
                    self.assertEqual(handler.history[0].severity, expected)

    def test_message_and_metadata_rounding(self):
        det, handler = self._make_detector({"packets_per_second": 1, "window_seconds": 0.3})
        det.process(self._packet())
        self.assertEqual(len(handler.history), 1)
        alert = handler.history[0]
        self.assertEqual(alert.message, f"{self.label} flood: 3 pkt/s (threshold 1)")
        self.assertEqual(alert.metadata["rate_pps"], 3.3)
        self.assertEqual(alert.severity, Severity.CRITICAL)

    def test_disabled_packets_are_not_counted(self):
        det, handler = self._make_detector({"enabled": False, "packets_per_second": 1})
        det.process(self._packet())
        self.assertEqual(handler.history, [])
        self.assertEqual(det._windows.keys(), [])
        self.assertEqual(det._throttle.keys(), [])

    def test_whitelisted_packets_are_not_counted(self):
        det, handler = self._make_detector({"packets_per_second": 1,
                                            "whitelist_ips": ["2.2.2.2"]})
        det.process(self._packet())
        self.assertEqual(handler.history, [])
        self.assertEqual(det._windows.keys(), [])
        self.assertEqual(det._throttle.keys(), [])
        det.process(self._packet("3.3.3.3"))
        self.assertEqual([alert.src_ip for alert in handler.history], ["3.3.3.3"])

    def test_wrong_protocol_and_missing_ip_are_not_counted(self):
        from scapy.layers.inet import IP
        det, handler = self._make_detector({"packets_per_second": 1})
        for protocol in ("TCP", "UDP", "ICMP"):
            if protocol != self.protocol:
                det.process(_make_packet("2.2.2.2", proto=protocol))
        packet = self._packet()
        has_layer = packet.haslayer
        packet.haslayer = lambda layer: layer is not IP and has_layer(layer)
        det.process(packet)
        self.assertEqual(handler.history, [])
        self.assertEqual(det._windows.keys(), [])
        self.assertEqual(det._throttle.keys(), [])

    def test_source_rates_are_independent(self):
        det, handler = self._make_detector({"packets_per_second": 2})
        det.process(self._packet("2.2.2.2"))
        det.process(self._packet("3.3.3.3"))
        self.assertEqual(handler.history, [])
        det.process(self._packet("2.2.2.2"))
        self.assertEqual([alert.src_ip for alert in handler.history], ["2.2.2.2"])

    def test_five_second_throttle_is_per_source_and_not_extended(self):
        det, handler = self._make_detector({"packets_per_second": 0.1,
                                            "window_seconds": 10})
        packet = self._packet()
        det.process(packet)
        self.assertEqual(len(handler.history), 1)
        self.clock.return_value = 104.0
        det.process(packet)
        det.process(self._packet("3.3.3.3"))
        self.assertEqual([alert.src_ip for alert in handler.history],
                         ["2.2.2.2", "3.3.3.3"])
        self.clock.return_value = 105.0
        det.process(packet)  # Timestamp at exactly the cutoff still counts.
        self.assertEqual(len(handler.history), 2)
        self.clock.return_value = 105.001
        det.process(packet)
        self.assertEqual([alert.src_ip for alert in handler.history],
                         ["2.2.2.2", "3.3.3.3", "2.2.2.2"])
        # All four packets count, including the two whose alerts were suppressed.
        self.assertEqual(handler.history[-1].metadata["rate_pps"], 0.4)
        self.assertEqual(handler.history[-1].metadata["threshold_pps"], 0.1)
        self.assertEqual(det.alert_count, 3)

    def test_configured_window_expiry_includes_exact_boundary(self):
        for elapsed, expected_alerts in ((2.0, 1), (2.001, 0)):
            with self.subTest(elapsed=elapsed):
                self.clock.return_value = 100.0
                det, handler = self._make_detector({"packets_per_second": 2,
                                                    "window_seconds": 2})
                for _ in range(3):
                    det.process(self._packet())
                self.assertEqual(handler.history, [])
                self.clock.return_value += elapsed
                det.process(self._packet())
                self.assertEqual(len(handler.history), expected_alerts)

    def test_detector_instances_have_independent_state(self):
        first, first_handler = self._make_detector({"packets_per_second": 2})
        second, second_handler = self._make_detector({"packets_per_second": 2})
        packet = self._packet()
        first.process(packet)
        second.process(packet)
        self.assertEqual(first_handler.history, [])
        self.assertEqual(second_handler.history, [])
        first.process(packet)
        second.process(packet)
        self.assertEqual(len(first_handler.history), 1)
        self.assertEqual(len(second_handler.history), 1)


class TestSynFloodDetector(_FloodDetectorBehaviorTests, unittest.TestCase):
    detector_class = "SynFloodDetector"
    detector_name = "syn_flood"
    protocol = "TCP"
    label = "SYN"

    def test_syn_without_ack_rst_fin_is_counted(self):
        det, handler = self._make_detector({"packets_per_second": 1})
        for flags in (0x00, 0x01, 0x04, 0x10, 0x12, 0x03, 0x22):
            det.process(_make_packet("2.2.2.2", flags=flags))
        self.assertEqual(handler.history, [])
        self.assertEqual(det._windows.keys(), [])
        det.process(_make_packet("2.2.2.2", flags=0x02))
        self.assertEqual(len(handler.history), 1)


class TestUdpFloodDetector(_FloodDetectorBehaviorTests, unittest.TestCase):
    detector_class = "UdpFloodDetector"
    detector_name = "udp_flood"
    protocol = "UDP"
    label = "UDP"


class TestIcmpFloodDetector(_FloodDetectorBehaviorTests, unittest.TestCase):
    detector_class = "IcmpFloodDetector"
    detector_name = "icmp_flood"
    protocol = "ICMP"
    label = "ICMP"


class TestBruteForceDetector(unittest.TestCase):

    def test_fires_on_ssh_brute_force(self):
        from src.detectors.brute_force import BruteForceDetector
        cfg = {
            "enabled": True, "target_ports": [22],
            "attempts_threshold": 5, "window_seconds": 30, "whitelist_ips": []
        }
        h = _silent_handler()
        det = BruteForceDetector(cfg, h)

        for _ in range(6):
            pkt = _make_packet("3.3.3.3", dport=22, flags=0x02)
            det.process(pkt)

        self.assertGreater(len(h.history), 0)
        self.assertEqual(h.history[0].dst_port, 22)

    def test_non_target_port_ignored(self):
        from src.detectors.brute_force import BruteForceDetector
        cfg = {
            "enabled": True, "target_ports": [22],
            "attempts_threshold": 3, "window_seconds": 30, "whitelist_ips": []
        }
        h = _silent_handler()
        det = BruteForceDetector(cfg, h)

        for _ in range(10):
            pkt = _make_packet("3.3.3.3", dport=9999, flags=0x02)
            det.process(pkt)

        self.assertEqual(len(h.history), 0)


class TestDisabledDetector(unittest.TestCase):

    def test_disabled_detector_does_not_fire(self):
        from src.detectors.port_scan import PortScanDetector
        cfg = {"enabled": False, "unique_ports_threshold": 1, "window_seconds": 10, "whitelist_ips": []}
        h = _silent_handler()
        det = PortScanDetector(cfg, h)

        for port in range(1, 50):
            pkt = _make_packet("5.5.5.5", dport=port)
            det.process(pkt)

        self.assertEqual(len(h.history), 0)


# ---------------------------------------------------------------------------
# §3.1 — Severity comparison operator tests (previously untested)
# ---------------------------------------------------------------------------

class TestSeverityOperators(unittest.TestCase):

    def test_lt(self):
        self.assertTrue(Severity.LOW < Severity.MEDIUM)
        self.assertTrue(Severity.MEDIUM < Severity.HIGH)
        self.assertTrue(Severity.HIGH < Severity.CRITICAL)
        self.assertFalse(Severity.CRITICAL < Severity.LOW)

    def test_le(self):
        self.assertTrue(Severity.LOW <= Severity.LOW)
        self.assertTrue(Severity.LOW <= Severity.MEDIUM)
        self.assertFalse(Severity.HIGH <= Severity.MEDIUM)

    def test_gt(self):
        self.assertTrue(Severity.CRITICAL > Severity.HIGH)
        self.assertTrue(Severity.HIGH > Severity.MEDIUM)
        self.assertFalse(Severity.LOW > Severity.MEDIUM)

    def test_ge(self):
        self.assertTrue(Severity.CRITICAL >= Severity.CRITICAL)
        self.assertTrue(Severity.HIGH >= Severity.MEDIUM)
        self.assertFalse(Severity.LOW >= Severity.MEDIUM)

    def test_sorted(self):
        """Verify that sorted() works via natural ordering."""
        shuffled = [Severity.CRITICAL, Severity.LOW, Severity.HIGH, Severity.MEDIUM]
        result = sorted(shuffled)
        self.assertEqual(result, [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL])

    def test_enum_has_exactly_four_members(self):
        """Ensure no rogue fifth member like _ORDER exists."""
        self.assertEqual(len(list(Severity)), 4)


# ---------------------------------------------------------------------------
# §3.2 — Alert round-trip (to_log_dict → JSON → --report-only parser)
# ---------------------------------------------------------------------------

class TestAlertRoundTrip(unittest.TestCase):

    def test_message_survives_round_trip(self):
        """Ensure to_log_dict's 'alert_message' key is read back correctly."""
        import json
        original = Alert(
            detector="port_scan",
            severity=Severity.HIGH,
            src_ip="9.9.9.9",
            message="Port scan detected: 20 ports",
        )
        log_dict = original.to_log_dict()
        json_str = json.dumps(log_dict)
        obj = json.loads(json_str)

        # This is the key the --report-only parser must use
        self.assertIn("alert_message", obj)
        self.assertEqual(obj["alert_message"], "Port scan detected: 20 ports")

        # Reconstruct as the parser does (after fix)
        reconstructed = Alert(
            alert_id=obj["alert_id"],
            timestamp=obj.get("ts", 0),
            detector=obj.get("detector", "unknown"),
            severity=Severity[obj.get("severity", "LOW")],
            src_ip=obj.get("src_ip", ""),
            message=obj.get("alert_message", ""),
        )
        self.assertEqual(reconstructed.message, original.message)

    def test_message_key_is_not_alert_text(self):
        """The JSON 'message' key is the log record message, NOT the alert text."""
        original = Alert(
            detector="test",
            severity=Severity.MEDIUM,
            src_ip="1.2.3.4",
            message="Real alert description",
        )
        log_dict = original.to_log_dict()
        # 'message' should NOT be in to_log_dict output
        self.assertNotIn("message", log_dict)


# ---------------------------------------------------------------------------
# §3.6 — AnomalyDetector tests
# ---------------------------------------------------------------------------

class TestAnomalyDetector(unittest.TestCase):

    def _make_detector(self, min_samples=5, deviation_factor=3.0, whitelist=None):
        from src.detectors.anomaly import AnomalyDetector
        cfg = {
            "enabled": True,
            "min_samples": min_samples,
            "deviation_factor": deviation_factor,
            "baseline_window_seconds": 60,
            "whitelist_ips": whitelist or [],
        }
        h = _silent_handler()
        det = AnomalyDetector(cfg, h)
        return det, h

    def test_no_alert_during_baseline(self):
        det, h = self._make_detector(min_samples=20)
        for _ in range(19):
            pkt = _make_packet("7.7.7.7", length=100)
            det.process(pkt)
        self.assertEqual(len(h.history), 0)

    def test_fires_on_anomalous_size(self):
        det, h = self._make_detector(min_samples=5, deviation_factor=2.0)

        # Build baseline with consistent small packets
        for _ in range(10):
            pkt = _make_packet("8.8.8.8", length=100)
            det.process(pkt)

        # Send anomalously large packet
        pkt = _make_packet("8.8.8.8", length=10000)
        det.process(pkt)

        self.assertGreater(len(h.history), 0)
        self.assertEqual(h.history[0].detector, "anomaly")

    def test_whitelist_skipped(self):
        det, h = self._make_detector(min_samples=3, whitelist=["7.7.7.7"])
        for _ in range(20):
            pkt = _make_packet("7.7.7.7", length=100)
            det.process(pkt)
        # Even large anomalous packet from whitelisted IP
        pkt = _make_packet("7.7.7.7", length=99999)
        det.process(pkt)
        self.assertEqual(len(h.history), 0)

    def test_thread_safety_stress(self):
        """Hammer AnomalyDetector.process() from multiple threads concurrently."""
        det, h = self._make_detector(min_samples=5, deviation_factor=100.0)
        errors = []

        def worker(ip_suffix):
            try:
                for i in range(50):
                    pkt = _make_packet(f"10.0.0.{ip_suffix}", length=64 + i)
                    det.process(pkt)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Thread errors: {errors}")


# ---------------------------------------------------------------------------
# §3.3 — PacketProcessor exception isolation test
# ---------------------------------------------------------------------------

class TestPacketProcessorIsolation(unittest.TestCase):

    def test_failing_detector_does_not_block_others(self):
        """If one detector raises, subsequent detectors still see the packet."""
        from src.core.packet_processor import PacketProcessor

        call_log = []

        class GoodDetector:
            name = "good"
            enabled = True
            def process(self, pkt):
                call_log.append("good")

        class BadDetector:
            name = "bad"
            enabled = True
            def process(self, pkt):
                raise RuntimeError("intentional failure")

        class AnotherGoodDetector:
            name = "another_good"
            enabled = True
            def process(self, pkt):
                call_log.append("another_good")

        # Bad detector is sandwiched between two good ones
        detectors = [GoodDetector(), BadDetector(), AnotherGoodDetector()]
        pp = PacketProcessor(detectors, worker_threads=1, queue_maxsize=10)
        pp.start()

        pkt = _make_packet("6.6.6.6")
        pp.enqueue(pkt)

        # Wait for processing
        time.sleep(0.5)
        pp.stop()

        self.assertIn("good", call_log)
        self.assertIn("another_good", call_log)


# ---------------------------------------------------------------------------
# Config loader tests
# ---------------------------------------------------------------------------

class TestConfigLoader(unittest.TestCase):

    def test_defaults_loaded_without_file(self):
        from src.utils.config_loader import load_config
        cfg = load_config(path="/nonexistent/path.yaml", allow_defaults=True)
        self.assertEqual(cfg.detection["syn_flood"]["packets_per_second"], 100)

    def test_override_applied(self):
        import tempfile, os, yaml
        data = {"detection": {"syn_flood": {"packets_per_second": 999}}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            fname = f.name
        try:
            from src.utils.config_loader import load_config
            cfg = load_config(fname)
            self.assertEqual(cfg.detection["syn_flood"]["packets_per_second"], 999)
            # Defaults still present for unspecified keys
            self.assertEqual(cfg.detection["port_scan"]["unique_ports_threshold"], 15)
        finally:
            os.unlink(fname)

    def test_set_updates_nested_config(self):
        from src.utils.config_loader import load_config
        cfg = load_config(path="/nonexistent/path.yaml", allow_defaults=True)
        cfg.set("logging", "level", value="DEBUG")
        self.assertEqual(cfg.logging["level"], "DEBUG")

    def test_invalid_severity_config_fails_clearly(self):
        import tempfile, os, yaml
        data = {"alerting": {"severity_filter": "medim"}}
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(data, f)
            fname = f.name
        try:
            from src.utils.config_loader import load_config
            with self.assertRaisesRegex(ValueError, "alerting.severity_filter"):
                load_config(fname)
        finally:
            os.unlink(fname)


class TestReporter(unittest.TestCase):
    def test_report_filenames_do_not_collide(self):
        import tempfile
        from src.reporting.reporter import Reporter

        with tempfile.TemporaryDirectory() as tmp:
            reporter = Reporter(tmp)
            reporter.generate([], save=True)
            reporter.generate([], save=True)
            reports = list(Path(tmp).glob("report_*.txt"))
            json_reports = list(Path(tmp).glob("report_*.json"))
        self.assertEqual(len(reports), 2)
        self.assertEqual(len(json_reports), 2)


class TestPcapWriter(unittest.TestCase):
    def test_cleanup_old_files_keeps_newest_captures(self):
        import os
        import tempfile
        from src.capture.pcap_writer import RotatingPcapWriter

        with tempfile.TemporaryDirectory() as tmp:
            paths = []
            for idx in range(3):
                path = Path(tmp) / f"capture_20260101_00000{idx}.pcap"
                path.write_bytes(b"pcap")
                os.utime(path, (100 + idx, 100 + idx))
                paths.append(path)

            writer = RotatingPcapWriter(output_dir=tmp, max_files=2)
            writer._cleanup_old_files()

            self.assertFalse(paths[0].exists())
            self.assertTrue(paths[1].exists())
            self.assertTrue(paths[2].exists())


class TestEngineWiring(unittest.TestCase):
    def test_register_detectors_respects_enabled_config(self):
        import tempfile
        from src.core.engine import NIDSEngine
        from src.utils.config_loader import load_config

        cfg = load_config(path="/nonexistent/path.yaml", allow_defaults=True)
        for name in ("port_scan", "syn_flood", "udp_flood", "icmp_flood", "brute_force", "anomaly"):
            cfg.set("detection", name, "enabled", value=False)
        cfg.set("detection", "port_scan", "enabled", value=True)
        cfg.set("capture", "enabled", value=False)
        cfg.set("logging", "console", value=False)

        with tempfile.TemporaryDirectory() as tmp, patch("src.core.engine.setup_logger"), patch.object(
            NIDSEngine, "_resolve_interface", return_value="eth0"
        ):
            cfg.set("logging", "file", value=str(Path(tmp) / "nids.log"))
            cfg.set("reporting", "report_dir", value=tmp)
            engine = NIDSEngine(cfg)

        self.assertEqual([det.name for det in engine.detectors], ["port_scan"])
        self.assertIsNone(engine.pcap_writer)


if __name__ == "__main__":
    unittest.main(verbosity=2)
