"""
base.py
-------
Abstract base class for all detectors.  Each detector receives raw Scapy
packets, maintains its own sliding-window state, and emits Alert objects
via the shared AlertHandler.
"""

from __future__ import annotations

import threading
import time
from src.core.traffic import evidence, network_layer, packet_timestamp
from src.core.sliding_window import SlidingWindowDict, AlertThrottle
from abc import ABC, abstractmethod
from typing import Optional, Set

from scapy.packet import Packet

from src.alerting.alert import Alert, Severity
from src.alerting.handler import AlertHandler
from src.logger.logger import get_logger


class BaseDetector(ABC):
    """
    Contract that every detector must fulfil:

    * ``name``  – human-readable identifier (used in alerts and logs).
    * ``process(packet)`` – called for every captured packet.
    * ``reset()`` – called periodically to flush stale state (optional).
    """

    def __init__(
        self,
        cfg: dict,
        handler: AlertHandler,
        whitelist: Optional[Set[str]] = None,
    ):
        self.cfg = cfg
        self.handler = handler
        self.whitelist: Set[str] = set(whitelist or [])
        self.enabled: bool = cfg.get("enabled", True)
        self.log = get_logger(f"detector.{self.name}")
        self._lock = threading.Lock()
        self._alert_count = 0
        self._state_lock = threading.RLock()

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Detector identifier, e.g. 'port_scan'."""

    @abstractmethod
    def process(self, packet: Packet) -> None:
        """Analyse a single packet and emit alerts if warranted."""

    # ------------------------------------------------------------------
    # Helpers available to sub-classes
    # ------------------------------------------------------------------

    def emit(
        self,
        severity: Severity,
        src_ip: str,
        message: str,
        dst_ip: Optional[str] = None,
        dst_port: Optional[int] = None,
        timestamp=None,
        **metadata,
    ) -> None:
        """Create an Alert and forward it to the handler."""
        alert = Alert(
            timestamp=time.time() if timestamp is None else timestamp,
            detector=self.name,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            message=message,
            metadata=metadata,
        )
        with self._lock:
            self._alert_count += 1
        self.handler.dispatch(alert)

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist

    @property
    def alert_count(self) -> int:
        return self._alert_count

    def reset(self) -> None:
        """Optional: subclasses may override to purge stale window data."""

    def window(self, seconds):
        return SlidingWindowDict(seconds, max_keys=self.cfg.get("max_state_keys", 2048),
                                 max_events=self.cfg.get("max_state_events", 65536),
                                 max_events_per_key=self.cfg.get("max_events_per_key", 8192))

    def throttle(self, seconds):
        return AlertThrottle(seconds, self.cfg.get("max_state_keys", 2048))

    def emit_packet(self, packet, **fields):
        context = evidence(packet)
        context.update(fields)
        self.emit(src_ip=network_layer(packet).src, timestamp=packet_timestamp(packet), **context)

    @property
    def health(self):
        windows = [value.stats for value in vars(self).values() if isinstance(value, SlidingWindowDict)]
        return {"evicted_keys": sum(w["evicted_keys"] for w in windows),
                "discarded_events": sum(w["discarded_events"] for w in windows),
                "throttle_evictions": sum(v.evictions for v in vars(self).values() if isinstance(v, AlertThrottle))}
