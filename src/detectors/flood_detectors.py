"""Event-time, IPv4/IPv6 per-source flood heuristics with atomic throttling."""
from __future__ import annotations

from scapy.layers.inet import TCP, UDP, ICMP
from scapy.layers.inet6 import IPv6, _ICMPv6
from src.alerting.alert import Severity
from src.core.traffic import event_time, network_layer, syn_attempt
from src.detectors.base import BaseDetector


def _dynamic_severity(rate, threshold):
    return Severity.CRITICAL if rate >= threshold * 2 else Severity.HIGH


class _FloodDetector(BaseDetector):
    def __init__(self, cfg, handler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._threshold = cfg.get("packets_per_second", 100)
        self._windows = self.window(cfg.get("window_seconds", 1))
        self._throttle = self.throttle(5)

    def _matches_packet(self, packet):
        return network_layer(packet) is not None and packet.haslayer(self._protocol)

    def process(self, packet):
        if not self.enabled or not self._matches_packet(packet):
            return
        src = network_layer(packet).src
        if self.is_whitelisted(src):
            return
        now = event_time(packet)
        with self._state_lock:
            if not self._windows.add(src, ts=now):
                return
            rate = self._windows.rate(src, now)
            fire = rate >= self._threshold and self._throttle.acquire(src, now)
        if fire:
            self.emit_packet(packet, severity=_dynamic_severity(rate, self._threshold),
                             message=f"{self._label} flood: {rate:.0f} pkt/s (threshold {self._threshold})",
                             rate_pps=round(rate, 1), threshold_pps=self._threshold,
                             window_seconds=self._windows.window_seconds, aggregation="source",
                             destination_context="packet crossing threshold")


class SynFloodDetector(_FloodDetector):
    name = "syn_flood"
    _protocol = TCP
    _label = "SYN"

    def _matches_packet(self, packet):
        return super()._matches_packet(packet) and syn_attempt(packet)


class UdpFloodDetector(_FloodDetector):
    name = "udp_flood"
    _protocol = UDP
    _label = "UDP"


class IcmpFloodDetector(_FloodDetector):
    name = "icmp_flood"
    _protocol = ICMP
    _label = "ICMP"

    def _matches_packet(self, packet):
        return network_layer(packet) is not None and (packet.haslayer(ICMP) or
                (packet.haslayer(IPv6) and packet.haslayer(_ICMPv6, _subclass=True)))
