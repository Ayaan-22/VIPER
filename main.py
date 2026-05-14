#!/usr/bin/env python3
"""
main.py
-------
CLI entry point for VIPER – Python Network Intrusion Detection System.

Usage examples
--------------
  # Start monitoring on eth0 (uses config/config.yaml)
  sudo python main.py -i eth0

  # Override interface and increase verbosity
  sudo python main.py -i wlan0 --log-level DEBUG

  # Use a custom config file
  sudo python main.py -i eth0 --config /etc/nids/prod.yaml

  # Dry-run: validate config and list detectors, then exit
  sudo python main.py -i eth0 --dry-run

  # Generate a report from an existing log without capturing
  python main.py --report-only --log logs/nids.log
"""

from __future__ import annotations

import argparse
import sys
import textwrap

from src.core.engine import NIDSEngine
from src.utils.config_loader import load_config


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent("""\
            ╔══════════════════════════════════════════════════════════╗
            ║  VIPER – Python Network Intrusion Detection System       ║
            ║  Detects: port scans, SYN/UDP/ICMP floods,               ║
            ║           brute-force attacks, traffic anomalies         ║
            ╚══════════════════════════════════════════════════════════╝
        """),
        epilog=textwrap.dedent("""\
            Examples:
              sudo python main.py -i eth0
              sudo python main.py -i eth0 --config /etc/nids/custom.yaml
              sudo python main.py -i eth0 --log-level DEBUG
              sudo python main.py -i eth0 --dry-run
        """),
    )

    # Core options
    parser.add_argument(
        "-i", "--interface",
        metavar="IFACE",
        help="Network interface to capture from (e.g. eth0, wlan0). "
             "Overrides value in config file.",
    )
    parser.add_argument(
        "-c", "--config",
        metavar="FILE",
        default="config/config.yaml",
        help="Path to YAML configuration file (default: config/config.yaml).",
    )

    # Verbosity
    parser.add_argument(
        "--log-level",
        metavar="LEVEL",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Override logging level from config.",
    )

    # Modes
    parser.add_argument(
        "--list-interfaces",
        action="store_true",
        help="List available network interfaces and exit.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate config and print active detectors, then exit.",
    )
    parser.add_argument(
        "--report-only",
        action="store_true",
        help="Parse an existing log file and generate a report, then exit.",
    )
    parser.add_argument(
        "--log",
        metavar="FILE",
        help="Log file path (used with --report-only).",
    )

    # Output format
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI colour output.",
    )

    return parser


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except Exception:
            pass

    parser = build_parser()
    args = parser.parse_args()

    # Load config
    try:
        cfg = load_config(args.config)
    except Exception as exc:
        print(f"[ERROR] Failed to load config '{args.config}': {exc}", file=sys.stderr)
        sys.exit(1)

    # Apply CLI overrides to config dict
    if args.log_level:
        cfg._data["logging"]["level"] = args.log_level
    if args.no_color:
        cfg._data["alerting"]["console"]["colorize"] = False

    # --list-interfaces
    if args.list_interfaces:
        print("\n[+] Available network interfaces:\n")
        try:
            from scapy.all import show_interfaces
            show_interfaces()
        except ImportError:
            print("[!] Scapy is not installed or configured properly.")
        except Exception as e:
            print(f"[!] Error retrieving interfaces: {e}")
            if sys.platform == "win32":
                print("    Ensure Npcap is installed in 'WinPcap API-compatible mode'.")
        sys.exit(0)

    # --dry-run
    if args.dry_run:
        print("\n[Dry-run] Configuration validated ✓")
        print(f"  Interface  : {args.interface or cfg.network.get('interface')}")
        print(f"  Config     : {args.config}")
        print(f"  Log level  : {cfg.logging.get('level')}")
        print("\n  Enabled detectors:")
        for det in ("port_scan", "syn_flood", "udp_flood", "icmp_flood",
                    "brute_force", "anomaly"):
            status = "✓" if cfg.detection.get(det, {}).get("enabled") else "✗"
            print(f"    {status}  {det}")
        print()
        sys.exit(0)

    # --report-only
    if args.report_only:
        _report_from_log(args.log or cfg.logging.get("file", "logs/nids.log"), cfg)
        sys.exit(0)

    # Normal capture mode
    if not args.interface and not cfg.network.get("interface"):
        parser.error("Specify a network interface with -i / --interface")

    engine = NIDSEngine(cfg, interface=args.interface)
    engine.start()   # blocks until Ctrl-C


def _report_from_log(log_path: str, cfg) -> None:
    """Parse JSON alert lines from an existing log and print a report."""
    import json
    from pathlib import Path
    from src.alerting.alert import Alert, Severity
    from src.reporting.reporter import Reporter, Visualizer

    p = Path(log_path)
    if not p.exists():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    alerts = []
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            try:
                obj = json.loads(line.strip())
                if "alert_id" not in obj:
                    continue
                a = Alert(
                    alert_id=obj["alert_id"],
                    timestamp=obj.get("ts", 0),
                    detector=obj.get("detector", "unknown"),
                    severity=Severity[obj.get("severity", "LOW")],
                    src_ip=obj.get("src_ip", ""),
                    message=obj.get("message", ""),
                )
                alerts.append(a)
            except Exception:
                continue

    rep_dir = cfg.reporting.get("report_dir", "reports")
    reporter  = Reporter(rep_dir)
    visualizer = Visualizer(rep_dir)
    print(reporter.generate(alerts, save=True))
    visualizer.plot_traffic_distribution(alerts)
    visualizer.plot_severity_pie(alerts)


if __name__ == "__main__":
    main()
