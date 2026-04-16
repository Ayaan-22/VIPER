"""
base.py
-------
Abstract base class for all detectors.  Each detector receives raw Scapy
packets, maintains its own sliding-window state, and emits Alert objects
via the shared AlertHandler.
"""

from __future__ import annotations

import threading
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
        **metadata,
    ) -> None:
        """Create an Alert and forward it to the handler."""
        alert = Alert(
            detector=self.name,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            message=message,
            metadata=metadata,
        )
        self._alert_count += 1
        self.handler.dispatch(alert)

    def is_whitelisted(self, ip: str) -> bool:
        return ip in self.whitelist

    @property
    def alert_count(self) -> int:
        return self._alert_count

    def reset(self) -> None:
        """Optional: subclasses may override to purge stale window data."""
