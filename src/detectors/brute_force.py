"""
brute_force.py
--------------
Detects credential-brute-force attempts by monitoring the number of
SYN packets a single source sends to the same service port within a
sliding time window.

Targeted ports are configurable (default: SSH 22, Telnet 23, RDP 3389,
FTP 21, SMTP 25, POP3 110, IMAP 143).

Heuristics
----------
* Counts SYN-only packets to a watched port per source IP.
* Ignores RST/FIN floods (those trigger the flood detectors instead).
* Throttles repeated alerts per (src_ip, dst_port) pair.
"""

from __future__ import annotations

from typing import Set

from scapy.layers.inet import IP, TCP
from scapy.packet import Packet

from src.alerting.alert import Severity
from src.alerting.handler import AlertHandler
from src.core.sliding_window import SlidingWindowDict
from src.detectors.base import BaseDetector

# Common service port names for human-readable messages
_PORT_NAMES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    110: "POP3",
    143: "IMAP",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
}


class BruteForceDetector(BaseDetector):
    name = "brute_force"

    def __init__(self, cfg: dict, handler: AlertHandler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._target_ports: Set[int] = set(
            cfg.get("target_ports", [22, 23, 3389, 21, 25, 110, 143])
        )
        self._threshold: int = cfg.get("attempts_threshold", 10)
        window = cfg.get("window_seconds", 30)
        # Key: (src_ip, dst_port)
        self._attempt_windows = SlidingWindowDict(window)
        self._throttle = SlidingWindowDict(window)

    def process(self, packet: Packet) -> None:
        if not self.enabled:
            return
        if not (packet.haslayer(IP) and packet.haslayer(TCP)):
            return
        if packet[TCP].flags != 0x02:       # SYN only
            return

        dst_port = packet[TCP].dport
        if dst_port not in self._target_ports:
            return

        src_ip = packet[IP].src
        if self.is_whitelisted(src_ip):
            return

        key = f"{src_ip}:{dst_port}"
        self._attempt_windows.add(key)
        count = self._attempt_windows.count(key)

        if count >= self._threshold and self._throttle.count(key) == 0:
            self._throttle.add(key)
            service = _PORT_NAMES.get(dst_port, str(dst_port))
            self.emit(
                severity=Severity.HIGH,
                src_ip=src_ip,
                dst_port=dst_port,
                message=(
                    f"Brute-force against {service} (port {dst_port}): "
                    f"{count} attempts in window"
                ),
                service=service,
                attempts=count,
                threshold=self._threshold,
            )
