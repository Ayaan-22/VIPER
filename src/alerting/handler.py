"""
handler.py
----------
AlertHandler is the single dispatch point for all Alerts raised by detectors.
It fans out to enabled channels (console, file-log, email, webhook) and
applies the per-channel minimum-severity filter defined in config.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
from collections import Counter
import threading
import urllib.request
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from email.mime.text import MIMEText
from typing import List, Optional

from src.alerting.alert import Alert, Severity, severity_gte
from src.logger.logger import get_logger

log = get_logger("alerting.handler")
log.setLevel(logging.INFO)  # Persist security events regardless of diagnostic verbosity.


def _parse_severity(value: object, default: Severity, field_name: str) -> Severity:
    name = str(value or default.value).upper()
    if name in Severity.__members__:
        return Severity[name]
    log.warning(f"Invalid severity {value!r} for {field_name}; using {default.value}")
    return default


class AlertHandler:
    def __init__(self, cfg: dict):
        self._cfg = cfg
        self._lock = threading.Lock()
        self._history: deque = deque(maxlen=10000)
        self.session_id = None
        self._total = 0
        self._by_severity = Counter()
        self._by_detector = Counter()
        self._delivery_dropped = self._delivery_failed = self._delivery_sent = 0
        self._min_severity = _parse_severity(cfg.get("severity_filter", "LOW"), Severity.LOW, "severity_filter")
        max_workers = max(1, int(cfg.get("max_delivery_workers", 4)))
        max_queue = max(0, int(cfg.get("max_delivery_queue", 100)))
        self._delivery_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nids-alert")
        self._delivery_slots = threading.BoundedSemaphore(max_workers + max_queue)
        self._webhook_executor = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="nids-webhook")
        self._webhook_slots = threading.BoundedSemaphore(max_workers + max_queue)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def dispatch(self, alert: Alert) -> None:
        """Evaluate and fan-out a single alert to all enabled channels."""
        if not severity_gte(alert.severity, self._min_severity):
            return

        with self._lock:
            self._history.append(alert)
            self._total += 1
            self._by_severity[alert.severity.value] += 1
            self._by_detector[alert.detector] += 1
            if self.session_id:
                alert.metadata["session_id"] = self.session_id

        # Console
        if self._cfg.get("console", {}).get("enabled", True):
            try:
                self._to_console(alert)
            except (OSError, UnicodeError):
                log.exception("Console alert output failed")

        # File log (structured)
        self._to_log(alert)

        # Email
        email_cfg = self._cfg.get("email", {})
        email_min = _parse_severity(email_cfg.get("min_severity", "HIGH"), Severity.HIGH, "email.min_severity")
        if email_cfg.get("enabled") and severity_gte(
            alert.severity, email_min
        ):
            self._submit_delivery(self._to_email, alert, email_cfg)

        # Webhook
        wh_cfg = self._cfg.get("webhook", {})
        webhook_min = _parse_severity(wh_cfg.get("min_severity", "MEDIUM"), Severity.MEDIUM, "webhook.min_severity")
        if wh_cfg.get("enabled") and severity_gte(
            alert.severity, webhook_min
        ):
            self._submit_delivery(self._to_webhook, alert, wh_cfg)

    @property
    def history(self) -> List[Alert]:
        with self._lock:
            return list(self._history)

    def clear_history(self) -> None:
        with self._lock:
            self._history.clear()

    def shutdown(self, wait: bool = False) -> None:
        # Finish in-flight bounded I/O; do not extend shutdown by draining a
        # saturated notification backlog. Cancellation is recorded as loss.
        self._delivery_executor.shutdown(wait=wait, cancel_futures=True)
        self._webhook_executor.shutdown(wait=wait, cancel_futures=True)

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

    def _submit_delivery(self, fn, alert: Alert, cfg: dict) -> None:
        webhook = cfg is self._cfg.get("webhook")
        executor = self._webhook_executor if webhook else self._delivery_executor
        slots = self._webhook_slots if webhook else self._delivery_slots
        if not slots.acquire(blocking=False):
            with self._lock:
                self._delivery_dropped += 1
            log.warning("Alert delivery queue is full; dropping async notification")
            return
        try:
            future = executor.submit(fn, alert, cfg)
        except RuntimeError:
            slots.release()
            with self._lock:
                self._delivery_dropped += 1
            log.warning("Alert delivery executor is shut down; dropping async notification")
            return
        def completed(result):
            if result.cancelled():
                with self._lock:
                    self._delivery_dropped += 1
            slots.release()
        future.add_done_callback(completed)

    def _to_email(self, alert: Alert, cfg: dict) -> None:
        try:
            msg = MIMEText(json.dumps(alert.to_dict(), indent=2))
            msg["Subject"] = f"[NIDS] {alert.severity.value}: {alert.detector} from {alert.src_ip}"
            msg["From"] = cfg["from_addr"]
            msg["To"] = ", ".join(cfg["to_addrs"])
            with smtplib.SMTP(cfg["smtp_host"], cfg["smtp_port"], timeout=cfg.get("timeout_seconds", 5)) as s:
                s.starttls(context=ssl.create_default_context())
                s.login(cfg["username"], cfg["password"])
                s.sendmail(cfg["from_addr"], cfg["to_addrs"], msg.as_string())
            with self._lock:
                self._delivery_sent += 1
        except Exception as exc:
            with self._lock:
                self._delivery_failed += 1
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
            with urllib.request.urlopen(req, timeout=cfg.get("timeout_seconds", 5)) as response:
                response.read(1024)
            with self._lock:
                self._delivery_sent += 1
        except Exception as exc:
            with self._lock:
                self._delivery_failed += 1
            log.error(f"Webhook alert failed: {exc}")

    @property
    def stats(self):
        with self._lock:
            return {"total_alerts": self._total, "retained_alerts": len(self._history),
                    "by_severity": dict(self._by_severity), "by_detector": dict(self._by_detector),
                    "notifications_sent": self._delivery_sent, "notifications_failed": self._delivery_failed,
                    "notifications_dropped": self._delivery_dropped}
