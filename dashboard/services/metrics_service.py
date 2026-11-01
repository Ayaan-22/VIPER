"""
metrics_service.py
------------------
Dashboard analytics over normalized VIPER alert and packet-stat events.
"""

from __future__ import annotations

import ipaddress
import math
from collections import Counter, defaultdict
from dataclasses import asdict
from typing import Any, Dict, Iterable, List, Sequence

from dashboard.api.models import (
    AlertEvent,
    DashboardMetrics,
    PacketSummary,
    ProtocolStats,
    TopTalker,
    severity_rank,
)


DEFAULT_PROTOCOLS = ("TCP", "UDP", "ICMP", "ICMPV6", "ARP", "OTHER")


def build_metrics(
    alerts: Sequence[AlertEvent],
    packet_stats: Sequence[Dict[str, Any]],
    *,
    interface: str = "log replay",
    engine_status: str = "historical",
    top_limit: int = 10,
) -> DashboardMetrics:
    summary = build_packet_summary(
        alerts,
        packet_stats,
        interface=interface,
        engine_status=engine_status,
    )
    return DashboardMetrics(
        summary=summary,
        alerts_by_severity=dict(_ordered_severity_counts(alerts)),
        alerts_by_detector=dict(Counter(a.detector for a in alerts)),
        alerts_over_time=alerts_over_time(alerts),
        packet_rate_over_time=packet_rate_over_time(packet_stats),
        top_sources=top_talkers(alerts, field="src_ip", limit=top_limit),
        top_destinations=top_talkers(alerts, field="dst_ip", limit=top_limit),
        top_ports=top_ports(alerts, limit=top_limit),
        protocols=protocol_breakdown(alerts, packet_stats),
    )


def build_packet_summary(
    alerts: Sequence[AlertEvent],
    packet_stats: Sequence[Dict[str, Any]],
    *,
    interface: str = "log replay",
    engine_status: str = "historical",
) -> PacketSummary:
    latest = packet_stats[-1] if packet_stats else {}
    total = int(latest.get("received", 0))
    processed = int(latest.get("processed", total))
    dropped = int(latest.get("dropped", 0))
    queued = int(latest.get("queued", 0))
    pps = _packet_rate(packet_stats)
    source_ips = {a.src_ip for a in alerts if a.src_ip}
    destination_ips = {a.dst_ip for a in alerts if a.dst_ip}
    protocols = {a.protocol for a in alerts if a.protocol}
    uptime = 0.0
    if packet_stats:
        uptime = max(0.0, latest["timestamp"] - (latest.get("started_at") or next((x["timestamp"] for x in packet_stats if x.get("session_id") == latest.get("session_id")), latest["timestamp"])))
    elif alerts:
        uptime = max(0.0, alerts[-1].timestamp - alerts[0].timestamp)
    return PacketSummary(
        total_packets=total if packet_stats else None,
        processed_packets=processed if packet_stats else None,
        dropped_packets=dropped if packet_stats else None,
        queue_size=queued if packet_stats else None,
        packets_per_second=round(pps, 2) if len(packet_stats) >= 2 else None,
        active_sources=len(source_ips),
        active_destinations=len(destination_ips),
        active_protocols=len(protocols),
        alerts_generated=len(alerts),
        engine_status=engine_status,
        interface=latest.get("interface") or interface,
        uptime_seconds=round(uptime, 2),
        capture_dropped=_safe_count(latest.get("capture", {}).get("dropped")),
        capture_errors=_safe_count(latest.get("capture", {}).get("errors")),
        detector_errors=_safe_count(latest.get("detector_errors")),
        notification_losses=_safe_count(latest.get("delivery", {}).get("notifications_failed")) + _safe_count(latest.get("delivery", {}).get("notifications_dropped")),
        last_seen=latest.get("timestamp", 0.0),
        session_id=latest.get("session_id", ""),
    )


def top_talkers(
    alerts: Sequence[AlertEvent],
    *,
    field: str = "src_ip",
    limit: int = 10,
) -> List[TopTalker]:
    buckets: Dict[str, List[AlertEvent]] = defaultdict(list)
    for alert in alerts:
        ip = getattr(alert, field, None)
        if ip:
            buckets[str(ip)].append(alert)

    talkers: List[TopTalker] = []
    for ip, related in buckets.items():
        protocols = Counter(a.protocol for a in related)
        highest = max((a.severity for a in related), key=severity_rank, default="LOW")
        talkers.append(
            TopTalker(
                ip=ip,
                packet_count=None,
                alert_count=len(related),
                first_seen=min(a.timestamp for a in related),
                last_seen=max(a.timestamp for a in related),
                most_common_protocol=protocols.most_common(1)[0][0] if protocols else "OTHER",
                highest_severity=highest,
                related_alerts=[a.alert_id for a in related[-5:]],
                classification=classify_ip(ip),
            )
        )
    talkers.sort(key=lambda t: (t.alert_count, severity_rank(t.highest_severity), t.packet_count or 0), reverse=True)
    return talkers[:limit]


def top_ports(alerts: Sequence[AlertEvent], *, limit: int = 10) -> List[Dict[str, Any]]:
    counts: Counter = Counter()
    severity: Dict[int, str] = {}
    for alert in alerts:
        ports = ports_from_alert(alert)
        for port in ports:
            counts[port] += 1
            current = severity.get(port, "LOW")
            severity[port] = max((current, alert.severity), key=severity_rank)
    return [
        {"port": port, "alert_count": count, "highest_severity": severity.get(port, "LOW")}
        for port, count in counts.most_common(limit)
    ]


def protocol_breakdown(
    alerts: Sequence[AlertEvent],
    packet_stats: Sequence[Dict[str, Any]] | None = None,
    *, window_seconds=None,
) -> List[ProtocolStats]:
    alert_counts = Counter((a.protocol or "OTHER").upper() for a in alerts)
    measured = packet_stats[-1].get("protocol_counts") if packet_stats else None
    if window_seconds is not None and packet_stats and measured is not None:
        latest = packet_stats[-1]
        same_session = [item for item in packet_stats
                        if item.get("session_id") == latest.get("session_id")
                        and item.get("protocol_counts") is not None]
        recent = [item for item in same_session if item["timestamp"] >= latest["timestamp"] - window_seconds]
        baseline = recent[0] if recent else latest
        if baseline["timestamp"] == latest["timestamp"]:
            measured = None
        else:
            measured = {key: max(0, _safe_count(value) - _safe_count(baseline["protocol_counts"].get(key)))
                        for key, value in measured.items()}
    protocol_packet_counts = Counter({k: _safe_count(v) for k, v in (measured or {}).items()})
    packet_total = sum(protocol_packet_counts.values())

    protocols = list(DEFAULT_PROTOCOLS)
    for protocol in alert_counts:
        if protocol not in protocols:
            protocols.append(protocol)

    stats: List[ProtocolStats] = []
    for protocol in protocols:
        count = protocol_packet_counts.get(protocol, 0) if measured is not None and protocol in DEFAULT_PROTOCOLS else None
        percentage = ((count / packet_total * 100.0) if packet_total else 0.0) if count is not None else None
        stats.append(
            ProtocolStats(
                protocol=protocol,
                packet_count=count,
                alert_count=alert_counts.get(protocol, 0),
                percentage=round(percentage, 2) if percentage is not None else None,
                trend=_protocol_trend(alerts, protocol),
            )
        )
    return [item for item in stats if item.packet_count or item.alert_count or item.protocol in DEFAULT_PROTOCOLS]


def alerts_over_time(alerts: Sequence[AlertEvent], *, bucket_seconds: int = 60) -> List[Dict[str, Any]]:
    buckets: Dict[int, Counter] = defaultdict(Counter)
    for alert in alerts:
        bucket = int(alert.timestamp // bucket_seconds) * bucket_seconds
        buckets[bucket][alert.severity] += 1
        buckets[bucket]["total"] += 1
    return [{"timestamp": ts, **dict(counts)} for ts, counts in sorted(buckets.items())]


def packet_rate_over_time(packet_stats: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    points: List[Dict[str, Any]] = []
    previous = None
    for stat in packet_stats:
        if previous and previous.get("session_id") == stat.get("session_id"):
            elapsed = stat["timestamp"] - previous["timestamp"]
            delta = max(0, int(stat.get("processed", 0)) - int(previous.get("processed", 0)))
            pps = delta / elapsed if elapsed > 0 else 0.0
        else:
            pps = 0.0
        points.append(
            {
                "timestamp": stat["timestamp"],
                "received": int(stat.get("received", 0)),
                "processed": int(stat.get("processed", 0)),
                "dropped": int(stat.get("dropped", 0)),
                "queued": int(stat.get("queued", 0)),
                "packets_per_second": round(pps, 2),
            }
        )
        previous = stat
    return points


def classify_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return "unknown"
    if parsed.is_loopback:
        return "loopback"
    if parsed.is_multicast:
        return "multicast"
    if parsed.is_private:
        return "private"
    return "public"


def ports_from_alert(alert: AlertEvent) -> List[int]:
    ports = set()
    if alert.dst_port:
        ports.add(alert.dst_port)
    for key in ("sample_ports", "ports_touched", "ports"):
        raw = alert.evidence.get(key)
        if isinstance(raw, Iterable) and not isinstance(raw, (str, bytes, dict)):
            for item in raw:
                try:
                    port = int(item)
                    if 1 <= port <= 65535:
                        ports.add(port)
                except (TypeError, ValueError, OverflowError):
                    continue
    return sorted(ports)


def to_plain(value: Any) -> Any:
    """Recursively convert dashboard dataclasses into JSON-friendly dicts."""
    if hasattr(value, "__dataclass_fields__"):
        return {key: to_plain(val) for key, val in asdict(value).items()}
    if isinstance(value, list):
        return [to_plain(item) for item in value]
    if isinstance(value, dict):
        return {key: to_plain(val) for key, val in value.items()}
    if isinstance(value, float) and (math.isnan(value) or math.isinf(value)):
        return 0.0
    return value


def _ordered_severity_counts(alerts: Sequence[AlertEvent]) -> Dict[str, int]:
    counts = Counter(a.severity for a in alerts)
    return {severity: counts.get(severity, 0) for severity in ("LOW", "MEDIUM", "HIGH", "CRITICAL")}


def _packet_rate(packet_stats: Sequence[Dict[str, Any]]) -> float:
    if len(packet_stats) < 2:
        return 0.0
    latest = packet_stats[-1]
    previous = packet_stats[-2]
    if latest.get("session_id") != previous.get("session_id"):
        return 0.0
    elapsed = latest["timestamp"] - previous["timestamp"]
    delta = max(0, int(latest.get("processed", 0)) - int(previous.get("processed", 0)))
    return delta / elapsed if elapsed > 0 else 0.0


def _safe_count(value):
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError, OverflowError):
        return 0


def _protocol_trend(alerts: Sequence[AlertEvent], protocol: str) -> List[Dict[str, Any]]:
    relevant = [a for a in alerts if (a.protocol or "OTHER").upper() == protocol]
    return alerts_over_time(relevant)

