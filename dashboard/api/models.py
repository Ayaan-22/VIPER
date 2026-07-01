"""
models.py
---------
Typed dashboard-facing models used by the VIPER Vision API and services.

The main NIDS alert dataclass remains in ``src.alerting.alert``. These
models are intentionally separate so the dashboard can normalize historical
log records without changing detector output or structured logging.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SEVERITY_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get((severity or "LOW").upper(), 0)


def parse_timestamp(value: Any) -> float:
    """Return epoch seconds for VIPER's numeric or ISO JSON log timestamps."""
    if value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value)
    text = str(value).strip()
    if not text:
        return 0.0
    try:
        return float(text)
    except ValueError:
        pass
    try:
        normalized = text.replace("Z", "+00:00")
        return datetime.fromisoformat(normalized).timestamp()
    except ValueError:
        return 0.0


def format_ts(epoch_seconds: float) -> str:
    if epoch_seconds <= 0:
        return ""
    return datetime.fromtimestamp(epoch_seconds, tz=timezone.utc).isoformat()


@dataclass
class PacketSummary:
    total_packets: int = 0
    processed_packets: int = 0
    dropped_packets: int = 0
    queue_size: int = 0
    packets_per_second: float = 0.0
    active_sources: int = 0
    active_destinations: int = 0
    active_protocols: int = 0
    alerts_generated: int = 0
    engine_status: str = "historical"
    interface: str = "log replay"
    uptime_seconds: float = 0.0


@dataclass
class AlertEvent:
    alert_id: str
    timestamp: float
    severity: str
    detector: str
    src_ip: str = ""
    dst_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "OTHER"
    title: str = ""
    description: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["timestamp_iso"] = format_ts(self.timestamp)
        return data


@dataclass
class TopTalker:
    ip: str
    packet_count: int = 0
    alert_count: int = 0
    first_seen: float = 0.0
    last_seen: float = 0.0
    most_common_protocol: str = "OTHER"
    highest_severity: str = "LOW"
    related_alerts: List[str] = field(default_factory=list)
    classification: str = "unknown"


@dataclass
class ProtocolStats:
    protocol: str
    packet_count: int = 0
    alert_count: int = 0
    percentage: float = 0.0
    trend: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class TimelineEvent:
    timestamp: float
    event_type: str
    severity: str
    detector: str = ""
    src_ip: str = ""
    dst_ip: Optional[str] = None
    summary: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SuspiciousConnection:
    key: str
    src_ip: str
    dst_ip: str
    detector: str
    alert_count: int
    severity: str
    first_seen: float
    last_seen: float
    related_protocols: List[str] = field(default_factory=list)
    related_ports: List[int] = field(default_factory=list)
    evidence_summary: str = ""
    timeline: List[TimelineEvent] = field(default_factory=list)


@dataclass
class PortScanEvent:
    source_ip: str
    target_ip: str
    unique_ports: int
    ports_touched: List[int]
    first_seen: float
    last_seen: float
    severity: str
    detection_threshold: int
    timeline: List[TimelineEvent] = field(default_factory=list)


@dataclass
class DashboardMetrics:
    summary: PacketSummary
    alerts_by_severity: Dict[str, int]
    alerts_by_detector: Dict[str, int]
    alerts_over_time: List[Dict[str, Any]]
    packet_rate_over_time: List[Dict[str, Any]]
    top_sources: List[TopTalker]
    top_destinations: List[TopTalker]
    top_ports: List[Dict[str, Any]]
    protocols: List[ProtocolStats]


@dataclass
class ReportSummary:
    generated_at: str
    total_alerts: int
    highest_severity: str
    top_sources: List[TopTalker]
    top_ports: List[Dict[str, Any]]
    recommendations: List[str]

