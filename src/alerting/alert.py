"""
alert.py
--------
Defines the Alert data-class and Severity enum used throughout the system.
Keeping the model in its own module avoids circular imports and makes
serialisation straightforward.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from functools import total_ordering
from typing import Any, Dict, Optional


# Canonical ordering: LOW=0, MEDIUM=1, HIGH=2, CRITICAL=3.
# Defined at module level so both the Severity operators and the
# standalone severity_gte() helper can reference it.
_SEVERITY_ORDER: Dict[str, int] = {
    "LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3,
}


class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    def __lt__(self, other: str) -> bool:
        if other not in _SEVERITY_ORDER:
            return NotImplemented
        return _SEVERITY_ORDER[self] < _SEVERITY_ORDER[other]

    def __le__(self, other: str) -> bool:
        if other not in _SEVERITY_ORDER:
            return NotImplemented
        return _SEVERITY_ORDER[self] <= _SEVERITY_ORDER[other]

    def __gt__(self, other: str) -> bool:
        if other not in _SEVERITY_ORDER:
            return NotImplemented
        return _SEVERITY_ORDER[self] > _SEVERITY_ORDER[other]

    def __ge__(self, other: str) -> bool:
        if other not in _SEVERITY_ORDER:
            return NotImplemented
        return _SEVERITY_ORDER[self] >= _SEVERITY_ORDER[other]


def severity_gte(a: Severity, b: Severity) -> bool:
    """Return True if severity *a* is greater-than-or-equal to *b*."""
    return _SEVERITY_ORDER[a.value] >= _SEVERITY_ORDER[b.value]


@dataclass
class Alert:
    """
    Immutable record of a detected security event.
    """
    alert_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    detector: str = ""
    severity: Severity = Severity.MEDIUM
    src_ip: str = ""
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # Serialisation helpers
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["severity"] = self.severity.value
        return d

    def to_log_dict(self) -> Dict[str, Any]:
        """Compact representation suitable for structured log lines.

        Note: the alert text is stored as ``alert_message`` to avoid
        shadowing the ``message`` attribute that Python's logging module
        reserves for its own use in LogRecord extra dicts.
        """
        return {
            "alert_id":      self.alert_id,
            "ts":            self.timestamp,
            "detector":      self.detector,
            "severity":      self.severity.value,
            "src_ip":        self.src_ip,
            "dst_ip":        self.dst_ip,
            "dst_port":      self.dst_port,
            "alert_message": self.message,   # renamed to avoid LogRecord collision
            **self.metadata,
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity.value}] {self.detector} | {self.src_ip} | {self.message}"
        )
