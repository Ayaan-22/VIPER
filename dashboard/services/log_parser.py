"""
log_parser.py
-------------
Parse VIPER's existing structured JSON log into dashboard-friendly events.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from dashboard.api.models import AlertEvent, parse_timestamp


RECOMMENDED_ACTIONS = {
    "port_scan": "Validate the source host, review firewall exposure, and confirm the scanned services are expected.",
    "syn_flood": "Check service saturation, rate-limit the source if unauthorized, and review upstream filtering.",
    "udp_flood": "Inspect UDP services, confirm traffic legitimacy, and apply rate limits for abusive sources.",
    "icmp_flood": "Verify ICMP monitoring needs, rate-limit excessive echo traffic, and inspect source behavior.",
    "brute_force": "Review authentication logs, block unauthorized sources, and enforce lockout or MFA controls.",
    "anomaly": "Investigate unusual packet sizes or rates and compare against normal application behavior.",
}


def iter_json_lines(path: str | Path) -> Iterable[Dict[str, Any]]:
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                yield obj


def parse_log(path: str | Path) -> Tuple[List[AlertEvent], List[Dict[str, Any]]]:
    alerts: List[AlertEvent] = []
    packet_stats: List[Dict[str, Any]] = []
    for record in iter_json_lines(path):
        if record.get("message") == "packet_stats":
            packet_stats.append(_normalize_packet_stats(record))
        elif record.get("alert_id"):
            alerts.append(normalize_alert_record(record))
    alerts.sort(key=lambda a: a.timestamp)
    packet_stats.sort(key=lambda item: item.get("timestamp", 0.0))
    return alerts, packet_stats


def normalize_alert_record(record: Dict[str, Any]) -> AlertEvent:
    detector = str(record.get("detector") or "unknown")
    protocol = infer_protocol(record)
    evidence = {
        key: value
        for key, value in record.items()
        if key
        not in {
            "ts",
            "level",
            "logger",
            "message",
            "alert_id",
            "detector",
            "severity",
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "alert_message",
        }
    }
    description = str(record.get("alert_message") or record.get("message") or "")
    return AlertEvent(
        alert_id=str(record.get("alert_id")),
        timestamp=parse_timestamp(record.get("ts")),
        severity=str(record.get("severity") or record.get("level") or "LOW").upper(),
        detector=detector,
        src_ip=str(record.get("src_ip") or ""),
        dst_ip=record.get("dst_ip"),
        src_port=_safe_int(record.get("src_port")),
        dst_port=_safe_int(record.get("dst_port")),
        protocol=protocol,
        title=title_for_detector(detector),
        description=description,
        evidence=evidence,
        recommended_action=RECOMMENDED_ACTIONS.get(
            detector,
            "Review the related packets, confirm authorization, and preserve logs for follow-up.",
        ),
    )


def infer_protocol(record: Dict[str, Any]) -> str:
    explicit = record.get("protocol")
    if explicit:
        return str(explicit).upper()
    detector = str(record.get("detector") or "").lower()
    message = str(record.get("alert_message") or "").lower()
    port = _safe_int(record.get("dst_port"))
    if detector in {"udp_flood"} or "udp" in message:
        return "UDP"
    if detector in {"icmp_flood"} or "icmp" in message:
        return "ICMP"
    if detector in {"port_scan", "syn_flood", "brute_force"} or "syn" in message:
        if port == 53:
            return "DNS"
        if port == 80:
            return "HTTP"
        if port == 443:
            return "HTTPS"
        return "TCP"
    if port == 53:
        return "DNS"
    if port == 80:
        return "HTTP"
    if port == 443:
        return "HTTPS"
    return "OTHER"


def title_for_detector(detector: str) -> str:
    return {
        "port_scan": "Port scan detected",
        "syn_flood": "SYN flood spike",
        "udp_flood": "UDP flood spike",
        "icmp_flood": "ICMP flood spike",
        "brute_force": "Brute-force attempt",
        "anomaly": "Statistical anomaly",
    }.get(detector, detector.replace("_", " ").title() or "Alert")


def _normalize_packet_stats(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": parse_timestamp(record.get("ts")),
        "received": _safe_int(record.get("received")) or 0,
        "processed": _safe_int(record.get("processed")) or 0,
        "dropped": _safe_int(record.get("dropped")) or 0,
        "queued": _safe_int(record.get("queued")) or 0,
    }


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None

