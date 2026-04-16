"""
handler.py
----------
AlertHandler is the single dispatch point for all Alerts raised by detectors.
It fans out to enabled channels (console, file-log, email, webhook) and
applies the per-channel minimum-severity filter defined in config.
"""

from __future__ import annotations

import json
import smtplib
import threading
import urllib.request
from email.mime.text import MIMEText
from typing import List, Optional

from src.alerting.alert import Alert, Severity, severity_gte
from src.logger.logger import get_logger

log = get_logger("alerting.handler")


class AlertHandler:
    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._lock = threading.Lock()
        self._history: List[Alert] = []
        self._min_severity = Severity[cfg.get("severity_filter", "LOW")]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, alert: Alert) -> None:
        """Evaluate and fan-out a single alert to all enabled channels."""
        if not severity_gte(alert.severity, self._min_severity):
            return

        with self._lock:
            self._history.append(alert)

        # Console
        if self._cfg.get("console", {}).get("enabled", True):
            self._to_console(alert)

        # File log (structured)
        self._to_log(alert)

        # Email
        email_cfg = self._cfg.get("email", {})
        if email_cfg.get("enabled") and severity_gte(
            alert.severity, Severity[email_cfg.get("min_severity", "HIGH")]
        ):
            threading.Thread(
                target=self._to_email, args=(alert, email_cfg), daemon=True
            ).start()

        # Webhook
        wh_cfg = self._cfg.get("webhook", {})
        if wh_cfg.get("enabled") and severity_gte(
            alert.severity, Severity[wh_cfg.get("min_severity", "MEDIUM")]
        ):
            threading.Thread(
                target=self._to_webhook, args=(alert, wh_cfg), daemon=True
            ).start()

    @property
    def history(self) -> List[Alert]:
        with self._lock:
            return list(self._history)

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    # ------------------------------------------------------------------
    # Output channels
    # ------------------------------------------------------------------

    _COLOUR = {
        "LOW":      "\033[36m",
        "MEDIUM":   "\033[33m",
        "HIGH":     "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET":    "\033[0m",
    }

    def _to_console(self, alert: Alert) -> None:
        colorize = self._cfg.get("console", {}).get("colorize", True)
        prefix = ""
        suffix = ""
        if colorize:
            prefix = self._COLOUR.get(alert.severity.value, "")
            suffix = self._COLOUR["RESET"]
        print(f"{prefix}{'━'*60}{suffix}")
        print(f"{prefix}⚠  ALERT  [{alert.severity.value}]  {alert.detector}{suffix}")
        print(f"   Source  : {alert.src_ip}")
        if alert.dst_ip:
            print(f"   Target  : {alert.dst_ip}:{alert.dst_port}")
        print(f"   Message : {alert.message}")
        if alert.metadata:
            print(f"   Meta    : {alert.metadata}")
        print(f"{prefix}{'━'*60}{suffix}")

    def _to_log(self, alert: Alert) -> None:
        sev = alert.severity.value
        if sev == "CRITICAL":
            log.critical("alert", extra=alert.to_log_dict())
        elif sev == "HIGH":
            log.error("alert", extra=alert.to_log_dict())
        elif sev == "MEDIUM":
            log.warning("alert", extra=alert.to_log_dict())
        else:
            log.info("alert", extra=alert.to_log_dict())

    def _to_email(self, alert: Alert, cfg: dict) -> None:
        try:
            msg = MIMEText(json.dumps(alert.to_dict(), indent=2))
            msg["Subject"] = f"[NIDS] {alert.severity.value}: {alert.detector} from {alert.src_ip}"
            msg["From"] = cfg["from_addr"]
            msg["To"] = ", ".join(cfg["to_addrs"])
            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"]) as s:
                s.starttls()
                s.login(cfg["username"], cfg["password"])
                s.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())
        except Exception as exc:
            log.error(f"Email alert failed: {exc}")

    def _to_webhook(self, alert: Alert, cfg: dict) -> None:
        try:
            body = json.dumps(alert.to_dict()).encode()
            req = urllib.request.Request(
                cfg["url"],
                data=body,
                headers=cfg.get("headers", {"Content-Type": "application/json"}),
                method="POST",
            )
            urllib.request.urlopen(req, timeout=5)
        except Exception as exc:
            log.error(f"Webhook alert failed: {exc}")
