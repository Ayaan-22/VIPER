"""Connection-attempt heuristic; authentication failures require host log correlation."""
from scapy.layers.inet import TCP
from scapy.packet import Packet
from src.alerting.alert import Severity
from src.core.traffic import event_time, network_layer, syn_attempt
from src.detectors.base import BaseDetector

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
    name = "brute_force"  # retained event/config identifier for compatibility

    def __init__(self, cfg, handler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._target_ports = set(cfg.get("target_ports", [22, 23, 3389, 21, 25, 110, 143]))
        self._threshold = cfg.get("attempts_threshold", 10)
        window = cfg.get("window_seconds", 30)
        self._attempt_windows = self.window(window)
        self._throttle = self.throttle(window)
        self._connections = self.throttle(window)

    def process(self, packet):
        net = network_layer(packet)
        if not self.enabled or net is None or not syn_attempt(packet) or self.is_whitelisted(net.src):
            return
        tcp, now = packet[TCP], event_time(packet)
        port = int(tcp.dport)
        if port not in self._target_ports:
            return
        key = (net.src, net.dst, port)
        with self._state_lock:
            if isinstance(packet, Packet):
                fingerprint = (*key, int(tcp.sport), int(tcp.seq))
                if not self._connections.acquire(fingerprint, now):
                    return
            self._attempt_windows.add(key, ts=now)
            count = self._attempt_windows.count(key, now)
            fire = count >= self._threshold and self._throttle.acquire(key, now)
        if fire:
            service = _PORT_NAMES.get(port, str(port))
            self.emit_packet(packet, severity=Severity.HIGH,
                             message=f"Repeated connection attempts to {service}: {count} in window; authentication outcome unknown",
                             service=service, attempts=count, threshold=self._threshold,
                             window_seconds=self._attempt_windows.window_seconds,
                             evidence_type="connection_attempts", authentication_outcome="unknown")
