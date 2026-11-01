"""
demo_data.py
------------
Deterministic simulated events for VIPER Vision demo mode.
"""

from __future__ import annotations

import time
from typing import Any, Dict, List, Tuple

from dashboard.api.models import AlertEvent


def build_demo_dataset() -> Tuple[List[AlertEvent], List[Dict[str, Any]]]:
    now = time.time()
    alerts: List[AlertEvent] = []

    def add(offset: int, detector: str, severity: str, src: str, dst: str | None, port: int | None, description: str, **evidence: Any) -> None:
        alerts.append(
            AlertEvent(
                alert_id=f"demo-{len(alerts) + 1:03d}",
                timestamp=now + offset,
                severity=severity,
                detector=detector,
                src_ip=src,
                dst_ip=dst,
                dst_port=port,
                protocol=_protocol_for(detector, port),
                title="Repeated connection attempts" if detector == "brute_force" else detector.replace("_", " ").title(),
                description=description,
                evidence=evidence,
                recommended_action="Demo data: validate the pattern in your authorized lab before taking action.",
            )
        )

    add(-540, "port_scan", "HIGH", "203.0.113.44", "10.0.0.20", 22, "Port scan detected: 32 unique ports probed within sliding window", unique_ports=32, sample_ports=[21, 22, 23, 25, 53, 80, 110, 139, 143, 443])
    add(-420, "syn_flood", "CRITICAL", "198.51.100.23", "10.0.0.15", 443, "SYN flood: 420 pkt/s (threshold 100)", rate_pps=420, threshold_pps=100)
    add(-360, "udp_flood", "HIGH", "10.0.0.55", "10.0.0.1", 53, "UDP flood: 188 pkt/s (threshold 100)", rate_pps=188, threshold_pps=100)
    add(-300, "brute_force", "HIGH", "203.0.113.88", "10.0.0.30", 22, "Repeated connection attempts to SSH: 18 in 30 seconds; authentication outcome unknown", attempts=18, target_port=22)
    add(-240, "icmp_flood", "HIGH", "198.51.100.77", "10.0.0.10", None, "ICMP flood: 160 pkt/s (threshold 100)", rate_pps=160, threshold_pps=100)
    add(-180, "anomaly", "MEDIUM", "10.0.0.42", None, None, "Anomalous traffic pattern: pkt_size=1400B (mean=118, z=4.2)", anomalies=["pkt_size=1400B (mean=118, z=4.2)"], samples=98)
    add(-120, "syn_flood", "HIGH", "198.51.100.23", "10.0.0.15", 443, "SYN flood: 132 pkt/s (threshold 100)", rate_pps=132, threshold_pps=100)
    add(-60, "port_scan", "HIGH", "203.0.113.44", "10.0.0.25", 3389, "Port scan detected: 21 unique ports probed within sliding window", unique_ports=21, sample_ports=[22, 80, 135, 139, 445, 1433, 3306, 3389])
    add(-20, "udp_flood", "CRITICAL", "10.0.0.55", "10.0.0.1", 53, "UDP flood: 610 pkt/s (threshold 100)", rate_pps=610, threshold_pps=100)

    packet_stats = []
    processed = 1200
    for index, offset in enumerate(range(-600, 1, 60)):
        processed += 750 + index * 95
        packet_stats.append(
            {
                "timestamp": now + offset,
                "received": processed + 5,
                "processed": processed,
                "dropped": 2 if index > 6 else 0,
                "queued": max(0, 14 - index),
                "protocol_counts": {"TCP": int(processed * .6), "UDP": int(processed * .3), "ICMP": int(processed * .08), "OTHER": processed - int(processed * .6) - int(processed * .3) - int(processed * .08)},
                "session_id": "simulated-demo-session",
                "started_at": now - 600,
                "interface": "Demo lab · simulated",
                "sensor_running": True,
                "capture": {"dropped": 0, "errors": 0},
            }
        )
    return alerts, packet_stats


def _protocol_for(detector: str, port: int | None) -> str:
    if detector == "udp_flood":
        return "UDP"
    if detector == "icmp_flood":
        return "ICMP"
    return "TCP" if detector != "anomaly" else "OTHER"
