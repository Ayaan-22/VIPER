"""
suspicious_connection_service.py
--------------------------------
Group related alerts to reduce noise in VIPER Vision.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Dict, List, Sequence, Tuple

from dashboard.api.models import AlertEvent, SuspiciousConnection, TimelineEvent, severity_rank
from dashboard.services.metrics_service import ports_from_alert


def group_suspicious_connections(
    alerts: Sequence[AlertEvent],
    *,
    window_seconds: int = 120,
) -> List[SuspiciousConnection]:
    buckets: Dict[Tuple[str, str, str, int], List[AlertEvent]] = defaultdict(list)
    for alert in alerts:
        window = int(alert.timestamp // window_seconds) if alert.timestamp else 0
        key = (alert.src_ip or "unknown", alert.dst_ip or "unknown", alert.detector, window)
        buckets[key].append(alert)

    groups: List[SuspiciousConnection] = []
    for (src_ip, dst_ip, detector, window), related in buckets.items():
        related.sort(key=lambda item: item.timestamp)
        highest = max((a.severity for a in related), key=severity_rank, default="LOW")
        protocols = sorted({a.protocol for a in related if a.protocol})
        ports = sorted({port for alert in related for port in ports_from_alert(alert)})
        groups.append(
            SuspiciousConnection(
                key=f"{src_ip}:{dst_ip}:{detector}:{window}",
                src_ip=src_ip,
                dst_ip=dst_ip,
                detector=detector,
                alert_count=len(related),
                severity=highest,
                first_seen=related[0].timestamp,
                last_seen=related[-1].timestamp,
                related_protocols=protocols,
                related_ports=ports[:100],
                evidence_summary=_summarize(related, protocols, ports),
                timeline=[
                    TimelineEvent(
                        timestamp=a.timestamp,
                        event_type=a.title,
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
    groups.sort(key=lambda item: (severity_rank(item.severity), item.alert_count, item.last_seen), reverse=True)
    return groups


def _summarize(alerts: Sequence[AlertEvent], protocols: List[str], ports: List[int]) -> str:
    protocol_text = ", ".join(protocols) if protocols else "unknown protocol"
    port_text = ", ".join(str(p) for p in ports[:8]) if ports else "no destination ports recorded"
    return (
        f"{len(alerts)} related alert(s) over {protocol_text}; "
        f"ports: {port_text}."
    )

