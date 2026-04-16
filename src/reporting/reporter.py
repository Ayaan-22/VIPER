"""
reporter.py
-----------
Generates human-readable and JSON security reports, and produces
traffic-distribution charts saved as PNG files.
"""

from __future__ import annotations

import json
import os
import time
from collections import Counter
from pathlib import Path
from typing import List, Optional

from src.alerting.alert import Alert, Severity
from src.logger.logger import get_logger

log = get_logger("reporting")


# ---------------------------------------------------------------------------
# Text / JSON report
# ---------------------------------------------------------------------------

class Reporter:
    def __init__(self, report_dir: str = "reports"):
        self._report_dir = Path(report_dir)
        self._report_dir.mkdir(parents=True, exist_ok=True)
        self._start_time = time.time()

    def generate(
        self,
        alerts: List[Alert],
        processor_stats: Optional[dict] = None,
        save: bool = True,
    ) -> str:
        uptime = time.time() - self._start_time
        by_severity = Counter(a.severity.value for a in alerts)
        by_detector = Counter(a.detector for a in alerts)
        top_sources  = Counter(a.src_ip for a in alerts).most_common(10)

        lines = [
            "",
            "╔══════════════════════════════════════════════════════════╗",
            "║              NIDS  SECURITY  REPORT                     ║",
            "╚══════════════════════════════════════════════════════════╝",
            f"  Generated : {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Uptime    : {uptime/3600:.1f} h  ({uptime:.0f} s)",
            "",
            "  ── Alert Summary ──────────────────────────────────────",
            f"  Total alerts : {len(alerts)}",
        ]
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            count = by_severity.get(sev, 0)
            bar = "█" * min(count, 40)
            lines.append(f"  {sev:<10} : {count:>5}  {bar}")

        lines += [
            "",
            "  ── By Detector ────────────────────────────────────────",
        ]
        for det, cnt in by_detector.most_common():
            lines.append(f"  {det:<20} : {cnt}")

        lines += [
            "",
            "  ── Top Offending Sources ──────────────────────────────",
        ]
        for ip, cnt in top_sources:
            lines.append(f"  {ip:<20} : {cnt} alerts")

        if processor_stats:
            lines += [
                "",
                "  ── Packet Processing ──────────────────────────────────",
                f"  Received   : {processor_stats.get('received', '—')}",
                f"  Processed  : {processor_stats.get('processed', '—')}",
                f"  Dropped    : {processor_stats.get('dropped', '—')}",
            ]

        lines += [
            "",
            "  ── Last 10 Alerts ─────────────────────────────────────",
        ]
        for a in alerts[-10:]:
            ts = time.strftime("%H:%M:%S", time.localtime(a.timestamp))
            lines.append(f"  [{ts}] {a.severity.value:<8} {a.detector:<18} {a.src_ip}  {a.message[:60]}")

        lines += ["", "═" * 62, ""]
        report_text = "\n".join(lines)

        if save:
            fname = self._report_dir / f"report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            fname.write_text(report_text, encoding="utf-8")

            # Also save JSON version
            json_fname = fname.with_suffix(".json")
            json_data = {
                "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "uptime_seconds": uptime,
                "summary": {
                    "total_alerts": len(alerts),
                    "by_severity":  dict(by_severity),
                    "by_detector":  dict(by_detector),
                    "top_sources":  [{"ip": ip, "count": c} for ip, c in top_sources],
                },
                "processor_stats": processor_stats or {},
                "alerts": [a.to_dict() for a in alerts[-100:]],
            }
            json_fname.write_text(json.dumps(json_data, indent=2), encoding="utf-8")
            log.info(f"Report saved: {fname}")

        return report_text


# ---------------------------------------------------------------------------
# Visualisation
# ---------------------------------------------------------------------------

class Visualizer:
    def __init__(self, report_dir: str = "reports"):
        self._report_dir = Path(report_dir)
        self._report_dir.mkdir(parents=True, exist_ok=True)

    def plot_traffic_distribution(
        self, alerts: List[Alert], filename: Optional[str] = None
    ) -> Optional[str]:
        """
        Save a bar chart of alert counts per detector to a PNG file.
        Returns the saved path, or None if matplotlib is unavailable.
        """
        try:
            import matplotlib
            matplotlib.use("Agg")  # non-interactive backend
            import matplotlib.pyplot as plt
        except ImportError:
            log.warning("matplotlib not installed; skipping visualisation")
            return None

        by_detector = Counter(a.detector for a in alerts)
        if not by_detector:
            return None

        labels = list(by_detector.keys())
        values = list(by_detector.values())
        colours = {
            "port_scan":  "#e74c3c",
            "syn_flood":  "#e67e22",
            "udp_flood":  "#f1c40f",
            "icmp_flood": "#2ecc71",
            "brute_force":"#3498db",
            "anomaly":    "#9b59b6",
        }
        bar_colours = [colours.get(l, "#95a5a6") for l in labels]

        fig, ax = plt.subplots(figsize=(10, 5))
        bars = ax.bar(labels, values, color=bar_colours, edgecolor="white", linewidth=0.8)
        ax.bar_label(bars, padding=3, fontsize=9)
        ax.set_title("NIDS – Alert Distribution by Detector", fontsize=13, fontweight="bold")
        ax.set_ylabel("Alert Count")
        ax.set_xlabel("Detector")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        plt.tight_layout()

        fname = filename or str(
            self._report_dir / f"viz_{time.strftime('%Y%m%d_%H%M%S')}.png"
        )
        plt.savefig(fname, dpi=150)
        plt.close(fig)
        log.info(f"Visualisation saved: {fname}")
        return fname

    def plot_severity_pie(
        self, alerts: List[Alert], filename: Optional[str] = None
    ) -> Optional[str]:
        """Pie chart of alert severity distribution."""
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt
        except ImportError:
            return None

        severity_colours = {
            "CRITICAL": "#c0392b",
            "HIGH":     "#e74c3c",
            "MEDIUM":   "#f39c12",
            "LOW":      "#27ae60",
        }
        counts = Counter(a.severity.value for a in alerts)
        if not counts:
            return None

        labels = list(counts.keys())
        sizes  = list(counts.values())
        cols   = [severity_colours.get(l, "#bdc3c7") for l in labels]

        fig, ax = plt.subplots(figsize=(7, 7))
        ax.pie(sizes, labels=labels, colors=cols, autopct="%1.1f%%", startangle=140)
        ax.set_title("Alert Severity Distribution", fontsize=13, fontweight="bold")
        plt.tight_layout()

        fname = filename or str(
            self._report_dir / f"severity_{time.strftime('%Y%m%d_%H%M%S')}.png"
        )
        plt.savefig(fname, dpi=150)
        plt.close(fig)
        return fname
