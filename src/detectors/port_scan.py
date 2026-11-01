"""Detect same-target multi-port scans and many-target same-service sweeps."""
from scapy.layers.inet import TCP
from src.alerting.alert import Severity
from src.core.traffic import event_time, network_layer, syn_attempt
from src.detectors.base import BaseDetector


class PortScanDetector(BaseDetector):
    name = "port_scan"

    def __init__(self, cfg, handler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        window = cfg.get("window_seconds", 10)
        self._threshold = cfg.get("unique_ports_threshold", 15)
        self._target_threshold = cfg.get("unique_targets_threshold", 15)
        self._port_windows = self.window(window)
        self._target_windows = self.window(window)
        self._alerted_window = self.throttle(window)

    def process(self, packet):
        net = network_layer(packet)
        if not self.enabled or net is None or not syn_attempt(packet) or self.is_whitelisted(net.src):
            return
        now, port = event_time(packet), int(packet[TCP].dport)
        pending = []
        with self._state_lock:
            key = (net.src, net.dst)
            self._port_windows.add(key, port, now)
            count = self._port_windows.unique_count(key, now)
            if count >= self._threshold and self._alerted_window.acquire(("ports", key), now):
                pending.append(dict(scan_type="multi_port", unique_ports=count,
                                    sample_ports=sorted(self._port_windows.unique_values(key, now))[:100],
                                    threshold=self._threshold,
                                    message=f"Port scan detected: {count} unique ports probed on {net.dst}"))
            key = (net.src, port)
            self._target_windows.add(key, net.dst, now)
            targets = self._target_windows.unique_count(key, now)
            if targets >= self._target_threshold and self._alerted_window.acquire(("targets", key), now):
                pending.append(dict(scan_type="host_sweep", unique_targets=targets,
                                    sample_targets=sorted(self._target_windows.unique_values(key, now))[:100],
                                    threshold=self._target_threshold,
                                    message=f"Host sweep detected: {targets} targets probed on port {port}"))
        for fields in pending:
            self.emit_packet(packet, severity=Severity.HIGH,
                             window_seconds=self._port_windows.window_seconds, **fields)
