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


class TestSynFloodDetector(unittest.TestCase):

    def test_fires_when_rate_exceeded(self):
        from src.detectors.flood_detectors import SynFloodDetector
        cfg = {"enabled": True, "packets_per_second": 5, "window_seconds": 1, "whitelist_ips": []}
        h = _silent_handler()
        det = SynFloodDetector(cfg, h)

        # Send 20 SYN packets quickly
        for _ in range(20):
            pkt = _make_packet("2.2.2.2", flags=0x02)
            det.process(pkt)

        self.assertGreater(len(h.history), 0)

    def test_non_syn_ignored(self):
        from src.detectors.flood_detectors import SynFloodDetector
        cfg = {"enabled": True, "packets_per_second": 5, "window_seconds": 1, "whitelist_ips": []}
        h = _silent_handler()
        det = SynFloodDetector(cfg, h)

        for _ in range(20):
            pkt = _make_packet("2.2.2.2", flags=0x10)  # ACK flag
            det.process(pkt)

        self.assertEqual(len(h.history), 0)


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
# Config loader tests
# ---------------------------------------------------------------------------

class TestConfigLoader(unittest.TestCase):

    def test_defaults_loaded_without_file(self):
        from src.utils.config_loader import load_config
        cfg = load_config(path="/nonexistent/path.yaml")
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
