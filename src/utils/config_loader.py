"""
config_loader.py
----------------
Loads, validates, and provides typed access to the YAML configuration file.
Merges user-supplied values over hard-coded defaults so the system is
always in a consistent state even with a partial config file.
"""

from __future__ import annotations

import copy
import math
import ipaddress
from urllib.parse import urlparse
from pathlib import Path
from typing import Any, Dict, Optional

try:
    import yaml
except ImportError:
    raise ImportError("PyYAML is required: pip install pyyaml")


# ---------------------------------------------------------------------------
# Defaults  (mirrored from config.yaml for robustness)
# ---------------------------------------------------------------------------

_DEFAULTS: Dict[str, Any] = {
    "network": {
        "interface": "eth0",
        "pcap_filter": "",
        "promiscuous": True,
    },
    "detection": {
        "port_scan":  {"enabled": True, "unique_ports_threshold": 15, "window_seconds": 10, "whitelist_ips": []},
        "syn_flood":  {"enabled": True, "packets_per_second": 100,    "window_seconds": 1,  "whitelist_ips": []},
        "udp_flood":  {"enabled": True, "packets_per_second": 100,    "window_seconds": 1,  "whitelist_ips": []},
        "icmp_flood": {"enabled": True, "packets_per_second": 100,    "window_seconds": 1,  "whitelist_ips": []},
        "brute_force": {
            "enabled": True, "target_ports": [22, 23, 3389, 21, 25, 110, 143],
            "attempts_threshold": 10, "window_seconds": 30, "whitelist_ips": [],
        },
        "anomaly": {
            "enabled": True, "baseline_window_seconds": 60,
            "deviation_factor": 3.0, "min_samples": 20,
        },
    },
    "logging": {
        "level": "INFO", "format": "json", "file": "logs/nids.log",
        "max_bytes": 10_485_760, "backup_count": 5, "console": True,
    },
    "alerting": {
        "severity_filter": "LOW",
        "email":   {"enabled": False},
        "webhook": {"enabled": False},
        "console": {"enabled": True, "colorize": True},
    },
    "capture": {
        "enabled": True, "output_dir": "captures",
        "rotate_mb": 50, "max_files": 10,
    },
    "reporting": {
        "auto_report_interval": 300,
        "report_dir": "reports",
    },
    "dashboard": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 5000,
        "refresh_interval_seconds": 5,
        "max_live_alerts": 500,
        "timeline_window_minutes": 60,
        "enable_websocket": True,
        "log_file_path": "logs/nids.log",
    },
    "analytics": {
        "top_talkers_limit": 10,
        "protocol_window_seconds": 60,
        "suspicious_group_window_seconds": 120,
    },
    "performance": {
        "worker_threads": 4,
        "queue_maxsize": 10_000,
        "stats_interval": 10,
    },
}


# State budgets are deliberately finite even for direct, partial configuration.
for _section in _DEFAULTS["detection"].values():
    _section.update(max_state_keys=2048, max_state_events=65536, max_events_per_key=8192)
_DEFAULTS["detection"]["port_scan"]["unique_targets_threshold"] = 15
_DEFAULTS["detection"]["anomaly"].update(max_baseline_samples=512, whitelist_ips=[])
_DEFAULTS["alerting"].update(max_delivery_workers=4, max_delivery_queue=100)
_DEFAULTS["alerting"]["email"].update(smtp_host="", smtp_port=587, username="", password="",
                                      from_addr="", to_addrs=[], min_severity="HIGH", timeout_seconds=5)
_DEFAULTS["alerting"]["webhook"].update(url="", headers={"Content-Type": "application/json"},
                                        min_severity="MEDIUM", timeout_seconds=5)
_DEFAULTS["reporting"].update(max_files=500, max_total_mb=512, max_age_days=30)

# ---------------------------------------------------------------------------
# Deep merge utility
# ---------------------------------------------------------------------------

def _deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, val in override.items():
        if isinstance(val, dict) and isinstance(result.get(key), dict):
            result[key] = _deep_merge(result[key], val)
        else:
            result[key] = val
    return result


def _normalize_severity(value: Any, field_name: str) -> str:
    valid = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
    normalized = str(value or "").upper()
    if normalized not in valid:
        raise ValueError(f"{field_name} must be one of {', '.join(sorted(valid))}; got {value!r}")
    return normalized


def _validate_config(data: Dict[str, Any]) -> Dict[str, Any]:
    def fail(field, message):
        raise ValueError(f"{field}: {message}")

    def number(section, key, low, high, integer=False):
        value = section.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            fail(key, "must be a finite number")
        if integer and not isinstance(value, int):
            fail(key, "must be an integer")
        if not low <= value <= high:
            fail(key, f"must be between {low} and {high}")

    def shape(actual, defaults, prefix=""):
        if not isinstance(actual, dict):
            fail(prefix or "config", "must be a mapping")
        for key, value in actual.items():
            field = f"{prefix}.{key}" if prefix else key
            if key not in defaults:
                fail(field, "unknown configuration option")
            expected = defaults[key]
            if isinstance(expected, dict):
                if field == "alerting.webhook.headers":
                    if not isinstance(value, dict):
                        fail(field, "must be a mapping")
                else:
                    shape(value, expected, field)
            elif isinstance(expected, bool) and not isinstance(value, bool):
                fail(field, "must be true or false")
            elif isinstance(expected, str) and not isinstance(value, str):
                fail(field, "must be a string")
            elif isinstance(expected, list) and not isinstance(value, list):
                fail(field, "must be a list")

    shape(data, _DEFAULTS)
    alerting = data["alerting"]
    alerting["severity_filter"] = _normalize_severity(alerting["severity_filter"], "alerting.severity_filter")
    for channel, default in (("email", "HIGH"), ("webhook", "MEDIUM")):
        cfg = alerting[channel]
        cfg["min_severity"] = _normalize_severity(cfg["min_severity"], f"alerting.{channel}.min_severity")
        number(cfg, "timeout_seconds", 0.1, 30)
    for key in ("max_delivery_workers",):
        number(alerting, key, 1, 16, True)
    number(alerting, "max_delivery_queue", 0, 1000, True)
    email = alerting["email"]
    number(email, "smtp_port", 1, 65535, True)
    if not all(isinstance(addr, str) and "@" in addr for addr in email["to_addrs"]):
        fail("alerting.email.to_addrs", "must contain email addresses")
    if email["enabled"] and (not all(email[k].strip() for k in ("smtp_host", "username", "password", "from_addr")) or not email["to_addrs"]):
        fail("alerting.email", "enabled email requires SMTP credentials, sender and recipients")
    wh = alerting["webhook"]
    if not isinstance(wh["headers"], dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in wh["headers"].items()):
        fail("alerting.webhook.headers", "must map strings to strings")
    if wh["enabled"] and (urlparse(wh["url"]).scheme not in {"http", "https"} or not urlparse(wh["url"]).hostname):
        fail("alerting.webhook.url", "must be an HTTP(S) URL")
    for name, det in data["detection"].items():
        for key in ("max_state_keys", "max_state_events", "max_events_per_key"):
            number(det, key, 1, 1048576, True)
        for ip in det.get("whitelist_ips", []):
            try:
                ipaddress.ip_address(ip)
            except (ValueError, TypeError):
                fail(f"detection.{name}.whitelist_ips", "must contain IP addresses")
        for key in ("window_seconds", "baseline_window_seconds", "deviation_factor"):
            if key in det:
                number(det, key, 0.001, 86400)
        for key in ("unique_ports_threshold", "unique_targets_threshold", "attempts_threshold"):
            if key in det:
                number(det, key, 1, min(det["max_events_per_key"], 65535), True)
        if "packets_per_second" in det:
            number(det, "packets_per_second", 0.001, 1000000)
            if det["packets_per_second"] * det["window_seconds"] > det["max_events_per_key"]:
                fail(f"detection.{name}", "event budget must cover the configured rate threshold and window")
        if "target_ports" in det:
            if not det["target_ports"] or any(isinstance(v, bool) or not isinstance(v, int) or not 1 <= v <= 65535 for v in det["target_ports"]):
                fail(f"detection.{name}.target_ports", "must contain valid service ports")
        if name == "anomaly":
            number(det, "max_baseline_samples", 2, 8192, True)
            number(det, "min_samples", 2, det["max_baseline_samples"], True)
    perf = data["performance"]
    number(perf, "worker_threads", 1, 64, True)
    number(perf, "queue_maxsize", 1, 1000000, True)
    number(perf, "stats_interval", 0.1, 300)
    cap = data["capture"]
    number(cap, "rotate_mb", 0.001, 100000)
    number(cap, "max_files", 1, 10000, True)
    rep = data["reporting"]
    number(rep, "auto_report_interval", 0, 86400)
    number(rep, "max_files", 4, 100000, True)
    number(rep, "max_total_mb", 1, 100000)
    number(rep, "max_age_days", 1, 3650)
    dash = data["dashboard"]
    number(dash, "port", 1, 65535, True)
    number(dash, "refresh_interval_seconds", 1, 300, True)
    number(dash, "max_live_alerts", 1, 1000, True)
    number(dash, "timeline_window_minutes", 1, 10080, True)
    for key in ("top_talkers_limit", "protocol_window_seconds", "suspicious_group_window_seconds"):
        number(data["analytics"], key, 1, 10000, True)
    number(data["logging"], "max_bytes", 1024, 1073741824, True)
    number(data["logging"], "backup_count", 1, 100, True)
    if data["logging"]["level"].upper() not in {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}:
        fail("logging.level", "unsupported level")
    if data["logging"]["format"] not in {"json", "text"}:
        fail("logging.format", "must be json or text")
    for section, field in (("logging", "file"), ("capture", "output_dir"), ("reporting", "report_dir")):
        if not data[section][field].strip():
            fail(f"{section}.{field}", "must not be empty")
    return data


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class Config:
    """
    Thin wrapper around a merged configuration dict.
    Access sections via attribute-style: ``cfg.network``, ``cfg.detection``, etc.
    """

    def __init__(self, data: Dict[str, Any]):
        self._data = data

    def __getattr__(self, name: str) -> Any:
        try:
            return self._data[name]
        except KeyError:
            raise AttributeError(f"No config section: '{name}'")

    def get(self, *keys: str, default: Any = None) -> Any:
        """Nested key accessor: ``cfg.get('detection', 'syn_flood', 'enabled')``."""
        node = self._data
        for k in keys:
            if not isinstance(node, dict) or k not in node:
                return default
            node = node[k]
        return node

    def set(self, *keys: str, value: Any) -> None:
        """Set a nested config value, creating intermediate dictionaries."""
        if not keys:
            raise ValueError("at least one key is required")
        node = self._data
        for key in keys[:-1]:
            child = node.setdefault(key, {})
            if not isinstance(child, dict):
                raise TypeError(f"Cannot set nested key below non-dict config value: {key}")
            node = child
        node[keys[-1]] = value

    def raw(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)


def load_config(path: Optional[str] = None, *, allow_defaults: bool = False) -> Config:
    """
    Load configuration from *path* (defaults to ``config/config.yaml``
    relative to cwd), merge with built-in defaults, and return a Config.
    """
    cfg_path = Path(path or "config/config.yaml")
    user_cfg: Dict[str, Any] = {}

    if cfg_path.exists():
        with cfg_path.open("r", encoding="utf-8") as fh:
            user_cfg = yaml.safe_load(fh) or {}
    else:
        if path is not None and not allow_defaults:
            raise FileNotFoundError(f"Configuration not found: {cfg_path}. Copy config/config.example.yaml first.")
        import warnings
        warnings.warn(
            f"Config file not found at {cfg_path}; using built-in defaults.",
            stacklevel=2,
        )

    if not isinstance(user_cfg, dict):
        raise ValueError("Configuration root must be a mapping")
    merged = _validate_config(_deep_merge(_DEFAULTS, user_cfg))
    return Config(merged)
