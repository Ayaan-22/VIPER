"""
flood_detectors.py
------------------
Time-windowed flood detectors for SYN, UDP, and ICMP traffic.

Each detector tracks per-source packet rates using a sliding window.
Severity escalates dynamically based on how far the rate exceeds threshold:
  - 1–2× threshold  → HIGH
  - >2× threshold   → CRITICAL
"""

from __future__ import annotations

from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Packet

from src.alerting.alert import Severity
from src.alerting.handler import AlertHandler
from src.core.sliding_window import SlidingWindowDict
from src.detectors.base import BaseDetector


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _dynamic_severity(rate: float, threshold: float) -> Severity:
    if rate >= threshold * 2:
        return Severity.CRITICAL
    return Severity.HIGH


# ---------------------------------------------------------------------------
# SYN Flood
# ---------------------------------------------------------------------------

class SynFloodDetector(BaseDetector):
    name = "syn_flood"

    def __init__(self, cfg: dict, handler: AlertHandler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._threshold: float = cfg.get("packets_per_second", 100)
        window = cfg.get("window_seconds", 1)
        self._windows = SlidingWindowDict(window)
        self._throttle = SlidingWindowDict(5)   # alert at most once per 5 s per src

    def process(self, packet: Packet) -> None:
        if not self.enabled:
            return
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return
        if packet[TCP].flags != 0x02:           # SYN only
            return

        src_ip = packet[IP].src
        if self.is_whitelisted(src_ip):
            return

        self._windows.add(src_ip)
        rate = self._windows.rate(src_ip)

        if rate >= self._threshold and self._throttle.count(src_ip) == 0:
            self._throttle.add(src_ip)
            self.emit(
                severity=_dynamic_severity(rate, self._threshold),
                src_ip=src_ip,
                message=f"SYN flood: {rate:.0f} pkt/s (threshold {self._threshold})",
                rate_pps=round(rate, 1),
                threshold_pps=self._threshold,
            )


# ---------------------------------------------------------------------------
# UDP Flood
# ---------------------------------------------------------------------------

class UdpFloodDetector(BaseDetector):
    name = "udp_flood"

    def __init__(self, cfg: dict, handler: AlertHandler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._threshold: float = cfg.get("packets_per_second", 100)
        window = cfg.get("window_seconds", 1)
        self._windows = SlidingWindowDict(window)
        self._throttle = SlidingWindowDict(5)

    def process(self, packet: Packet) -> None:
        if not self.enabled:
            return
        if not (packet.haslayer(IP) and packet.haslayer(UDP)):
            return

        src_ip = packet[IP].src
        if self.is_whitelisted(src_ip):
            return

        self._windows.add(src_ip)
        rate = self._windows.rate(src_ip)

        if rate >= self._threshold and self._throttle.count(src_ip) == 0:
            self._throttle.add(src_ip)
            self.emit(
                severity=_dynamic_severity(rate, self._threshold),
                src_ip=src_ip,
                message=f"UDP flood: {rate:.0f} pkt/s (threshold {self._threshold})",
                rate_pps=round(rate, 1),
                threshold_pps=self._threshold,
            )


# ---------------------------------------------------------------------------
# ICMP Flood
# ---------------------------------------------------------------------------

class IcmpFloodDetector(BaseDetector):
    name = "icmp_flood"

    def __init__(self, cfg: dict, handler: AlertHandler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._threshold: float = cfg.get("packets_per_second", 100)
        window = cfg.get("window_seconds", 1)
        self._windows = SlidingWindowDict(window)
        self._throttle = SlidingWindowDict(5)

    def process(self, packet: Packet) -> None:
        if not self.enabled:
            return
        if not (packet.haslayer(IP) and packet.haslayer(ICMP)):
            return

        src_ip = packet[IP].src
        if self.is_whitelisted(src_ip):
            return

        self._windows.add(src_ip)
        rate = self._windows.rate(src_ip)

        if rate >= self._threshold and self._throttle.count(src_ip) == 0:
            self._throttle.add(src_ip)
            self.emit(
                severity=_dynamic_severity(rate, self._threshold),
                src_ip=src_ip,
                message=f"ICMP flood: {rate:.0f} pkt/s (threshold {self._threshold})",
                rate_pps=round(rate, 1),
                threshold_pps=self._threshold,
            )
