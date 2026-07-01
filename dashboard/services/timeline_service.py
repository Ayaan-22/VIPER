"""
timeline_service.py
-------------------
Build attack timeline and port-scan visualizer records from alert events.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, List, Sequence

from dashboard.api.models import AlertEvent, PortScanEvent, TimelineEvent, severity_rank
from dashboard.services.metrics_service import ports_from_alert


EVENT_LABELS = {
    "port_scan": "Port scan started",
    "syn_flood": "SYN flood spike",
    "udp_flood": "UDP flood spike",
    "icmp_flood": "ICMP flood spike",
    "brute_force": "Brute-force attempt",
    "anomaly": "Anomaly detected",
}


def build_timeline(alerts: Sequence[AlertEvent]) -> List[TimelineEvent]:
    events: List[TimelineEvent] = []
    previous_by_pair: Dict[str, str] = {}
    for alert in sorted(alerts, key=lambda item: item.timestamp):
        pair_key = f"{alert.src_ip}->{alert.dst_ip or '*'}:{alert.detector}"
        previous = previous_by_pair.get(pair_key)
        event_type = EVENT_LABELS.get(alert.detector, alert.title or "Alert observed")
        if previous and severity_rank(alert.severity) > severity_rank(previous):
            event_type = "Alert severity escalation"
        previous_by_pair[pair_key] = alert.severity
        events.append(
            TimelineEvent(
                timestamp=alert.timestamp,
                event_type=event_type,
                severity=alert.severity,
                detector=alert.detector,
                src_ip=alert.src_ip,
                dst_ip=alert.dst_ip,
                summary=alert.description or alert.title,
                evidence=alert.evidence,
            )
        )
    return events


def extract_port_scans(
    alerts: Sequence[AlertEvent],
    *,
    detection_threshold: int = 15,
) -> List[PortScanEvent]:
    grouped: Dict[str, List[AlertEvent]] = defaultdict(list)
    for alert in alerts:
        if alert.detector == "port_scan":
            key = f"{alert.src_ip}->{alert.dst_ip or 'multiple-targets'}"
            grouped[key].append(alert)

    scans: List[PortScanEvent] = []
    for related in grouped.values():
        ports = set()
        for alert in related:
            ports.update(ports_from_alert(alert))
            if "unique_ports" in alert.evidence and not ports:
                try:
                    ports.update(range(1, int(alert.evidence["unique_ports"]) + 1))
                except (TypeError, ValueError):
                    pass
        highest = max((a.severity for a in related), key=severity_rank, default="LOW")
        scans.append(
            PortScanEvent(
                source_ip=related[0].src_ip,
                target_ip=related[0].dst_ip or "multiple targets",
                unique_ports=max(len(ports), int(related[-1].evidence.get("unique_ports", len(ports)) or 0)),
                ports_touched=sorted(ports)[:200],
                first_seen=min(a.timestamp for a in related),
                last_seen=max(a.timestamp for a in related),
                severity=highest,
                detection_threshold=detection_threshold,
                timeline=[
                    TimelineEvent(
                        timestamp=a.timestamp,
                        event_type="Port scan threshold crossed",
                        severity=a.severity,
                        detector=a.detector,
                        src_ip=a.src_ip,
                        dst_ip=a.dst_ip,
                        summary=a.description,
                        evidence=a.evidence,
                    )
                    for a in related
                ],
            )
        )
    scans.sort(key=lambda item: (severity_rank(item.severity), item.unique_ports, item.last_seen), reverse=True)
    return scans

