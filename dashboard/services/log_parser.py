"""
log_parser.py
-------------
Parse VIPER's existing structured JSON log into dashboard-friendly events.
"""

from __future__ import annotations

import json
import warnings
from collections import deque
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
    if not p.is_file() or p.is_symlink():
        return
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        skipping = False
        while True:
            line = fh.readline(65537)
            if not line:
                break
            if skipping or len(line) > 65536:
                skipping = not line.endswith("\n")
                continue
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                continue
            if isinstance(obj, dict):
                yield obj


def parse_log(path: str | Path) -> Tuple[List[AlertEvent], List[Dict[str, Any]]]:
    alerts = deque()
    packet_stats = deque(maxlen=20000)
    truncated = 0
    base = Path(path)
    paths = sorted([p for p in base.parent.glob(base.name + ".*") if p.suffix[1:].isdigit()], key=lambda p: p.stat().st_mtime)
    paths.append(base)
    seen = set()
    for segment in paths:
        for record in iter_json_lines(segment):
            try:
                if record.get("message") == "packet_stats":
                    truncated += int(len(packet_stats) == packet_stats.maxlen)
                    packet_stats.append(_normalize_packet_stats(record))
                elif record.get("alert_id") and str(record["alert_id"]) not in seen:
                    alert = normalize_alert_record(record)
                    if len(alerts) >= 100000:
                        seen.discard(alerts.popleft().alert_id)
                        truncated += 1
                    alerts.append(alert)
                    seen.add(alert.alert_id)
            except (ValueError, TypeError, OverflowError, RecursionError, AttributeError):
                continue
    if truncated:
        warnings.warn(f"Log replay retained bounded recent history; {truncated} older records were omitted", stacklevel=2)
    alerts = list(alerts)
    packet_stats = list(packet_stats)
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
    description = str(record.get("alert_message") or record.get("message") or "")[:4096]
    return AlertEvent(
        alert_id=str(record.get("alert_id"))[:256],
        timestamp=parse_timestamp(record.get("ts")),
        severity=normalize_severity(record.get("severity")),
        detector=detector,
        src_ip=str(record.get("src_ip") or ""),
        dst_ip=str(record["dst_ip"])[:128] if record.get("dst_ip") else None,
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
        candidate = str(explicit).upper()
        return candidate if candidate in {"TCP", "UDP", "ICMP", "ICMPV6", "ARP", "DNS", "HTTP", "HTTPS", "OTHER"} else "OTHER"
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
        "brute_force": "Repeated connection attempts",
        "anomaly": "Statistical anomaly",
    }.get(detector, detector.replace("_", " ").title() or "Alert")


def _normalize_packet_stats(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "timestamp": parse_timestamp(record.get("ts")),
        "received": _safe_int(record.get("received")) or 0,
        "processed": _safe_int(record.get("processed")) or 0,
        "dropped": _safe_int(record.get("dropped")) or 0,
        "queued": max(0, _safe_int(record.get("queued")) or 0),
        "session_id": str(record.get("session_id") or "legacy"),
        "started_at": parse_timestamp(record.get("started_at")),
        "heartbeat_interval": max(0.1, min(300, float(record.get("heartbeat_interval", 10)))),
        "sensor_running": record.get("sensor_running"),
        "interface": str(record.get("interface") or ""),
        "protocol_counts": ({str(k): max(0, _safe_int(v) or 0) for k, v in record["protocol_counts"].items()
                             if str(k) in {"TCP", "UDP", "ICMP", "ICMPV6", "ARP", "OTHER"}}
                            if isinstance(record.get("protocol_counts"), dict) else None),
        "capture": record.get("capture") if isinstance(record.get("capture"), dict) else {},
        "delivery": record.get("delivery") if isinstance(record.get("delivery"), dict) else {},
        "detector_errors": max(0, _safe_int(record.get("detector_errors")) or 0),
        "detector_state": record.get("detector_state") if isinstance(record.get("detector_state"), dict) else {},

    }


def _safe_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return None



def normalize_severity(value):
    name = str(value or "LOW").upper()
    if name not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}:
        raise ValueError("unknown alert severity")
    return name

