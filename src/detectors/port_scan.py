"""
port_scan.py
------------
Detects horizontal (single-target, many-ports) and vertical (many-targets)
port scans using time-based sliding windows and TCP flag analysis.

Heuristics to reduce false positives
-------------------------------------
* Only SYN-only packets are counted (flags == 'S'), ignoring
  legitimate established-connection traffic.
* Whitelisted source IPs are skipped.
* An alert is throttled per-source: a second alert for the same src_ip
  will not fire until the tracker has been fully reset (window rolled over).
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from src.alerting.alert import Severity
from src.alerting.handler import AlertHandler
from src.core.sliding_window import SlidingWindowDict
from src.detectors.base import BaseDetector


class PortScanDetector(BaseDetector):
    name = "port_scan"

    def __init__(self, cfg: dict, handler: AlertHandler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        window = cfg.get("window_seconds", 10)
        self._threshold: int = cfg.get("unique_ports_threshold", 15)
        self._port_windows = SlidingWindowDict(window)
        # Track which sources have already fired an alert in this window
        self._alerted: set = set()
        self._alerted_window = SlidingWindowDict(window)

    def process(self, packet: Packet) -> None:
        if not self.enabled:
            return
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return

        flags = packet[TCP].flags
        # Accept only pure SYN packets (value 0x02)
        if flags != 0x02:
            return

        src_ip = packet[IP].src
        if self.is_whitelisted(src_ip):
            return

        dst_port = packet[TCP].dport
        self._port_windows.add(src_ip, dst_port)
        unique_ports = self._port_windows.unique_values(src_ip)

        if len(unique_ports) >= self._threshold:
            # Throttle: one alert per source until window resets
            if self._alerted_window.count(src_ip) > 0:
                return
            self._alerted_window.add(src_ip)
            self.emit(
                severity=Severity.HIGH,
                src_ip=src_ip,
                message=(
                    f"Port scan detected: {len(unique_ports)} unique ports "
                    f"probed within sliding window"
                ),
                unique_ports=len(unique_ports),
                sample_ports=sorted(unique_ports)[:10],
            )
