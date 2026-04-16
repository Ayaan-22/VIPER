"""
config_loader.py
----------------
Loads, validates, and provides typed access to the YAML configuration file.
Merges user-supplied values over hard-coded defaults so the system is
always in a consistent state even with a partial config file.
"""

from __future__ import annotations

import copy
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
    "performance": {
        "worker_threads": 4,
        "queue_maxsize": 10_000,
        "stats_interval": 10,
    },
}


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

    def raw(self) -> Dict[str, Any]:
        return copy.deepcopy(self._data)


def load_config(path: Optional[str] = None) -> Config:
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
        import warnings
        warnings.warn(
            f"Config file not found at {cfg_path}; using built-in defaults.",
            stacklevel=2,
        )

    merged = _deep_merge(_DEFAULTS, user_cfg)
    return Config(merged)
