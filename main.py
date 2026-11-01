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
        "--dashboard",
        action="store_true",
        help="Run the VIPER Vision dashboard against a live or historical JSON log.",
    )
    parser.add_argument(
        "--dashboard-demo",
        action="store_true",
        help="Run VIPER Vision with simulated demo data.",
    )
    parser.add_argument(
        "--dashboard-host",
        default=None,
        help="Dashboard bind host (default from config or 127.0.0.1).",
    )
    parser.add_argument(
        "--dashboard-port",
        type=int,
        default=None,
        help="Dashboard port (default from config or 5000).",
    )
    parser.add_argument(
        "--dashboard-api-key",
        default=None,
        help="API key required for VIPER Vision dashboard access.",
    )
    parser.add_argument(
        "--dashboard-auth-user",
        default="viper",
        help="Basic-auth username when dashboard API-key auth is enabled.",
    )
    parser.add_argument(
        "--log",
        metavar="FILE",
        help="Log file path (used with --report-only or --dashboard).",
    )

    parser.add_argument("--dashboard-development", action="store_true", help="Use the dashboard development server")

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
        cfg.set("logging", "level", value=args.log_level)
    if args.no_color:
        cfg.set("alerting", "console", "colorize", value=False)

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

    # VIPER Vision dashboard modes
    if args.dashboard or args.dashboard_demo:
        import os
        from dashboard.app import create_app

        dashboard_cfg = cfg.raw().get("dashboard", {})
        host = args.dashboard_host or dashboard_cfg.get("host", "127.0.0.1")
        dashboard_key = args.dashboard_api_key or os.getenv("VIPER_DASHBOARD_API_KEY", "")
        if host not in {"", "localhost", "127.0.0.1", "::1"} and not dashboard_key:
            print(
                "[ERROR] Set --dashboard-api-key or VIPER_DASHBOARD_API_KEY before binding the dashboard outside localhost.",
                file=sys.stderr,
            )
            sys.exit(1)
        import hashlib
        from pathlib import Path
        log_path = args.log or dashboard_cfg.get("log_file_path") or cfg.logging["file"]
        report_path = Path(cfg.reporting["report_dir"]) / "demo" if args.dashboard_demo else Path(cfg.reporting["report_dir"])
        index_path = report_path / ".index" / (hashlib.sha256(str(Path(log_path).resolve()).encode()).hexdigest()[:16] + ".sqlite")
        dashboard_cfg["enable_websocket"] = args.dashboard_development and dashboard_cfg.get("enable_websocket", False)
        app = create_app(
            log_path=args.log or dashboard_cfg.get("log_file_path") or cfg.logging.get("file", "logs/nids.log"),
            demo=args.dashboard_demo,
            captures_dir=cfg.capture.get("output_dir", "captures"),
            reports_dir=str(report_path),
            interface=args.interface or cfg.network.get("interface", "log replay"),
            api_key=dashboard_key,
            auth_username=args.dashboard_auth_user,
            dashboard_options=dashboard_cfg,
            analytics_options=cfg.analytics,
            database_path=str(index_path),
            settings_path=str(index_path.with_suffix(".settings.json")),
            report_retention={"max_files": cfg.reporting["max_files"],
                              "max_bytes": cfg.reporting["max_total_mb"] * 1024 * 1024,
                              "max_age_days": cfg.reporting["max_age_days"]},
        )
        port = args.dashboard_port or dashboard_cfg.get("port", 5000)
        mode = "demo mode" if args.dashboard_demo else "historical/live log mode"
        print(f"[*] VIPER Vision running at http://{host}:{port} ({mode})")
        from dashboard.server import serve_dashboard
        try:
            serve_dashboard(app, host, port, development=args.dashboard_development)
        finally:
            if app.extensions.get("viper_store"):
                app.extensions["viper_store"].close()
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
    if not p.is_file():
        print(f"[ERROR] Log file not found: {log_path}", file=sys.stderr)
        sys.exit(1)

    from dashboard.services.log_parser import parse_log
    normalized, stats = parse_log(p)
    alerts = [Alert(alert_id=a.alert_id, timestamp=a.timestamp, detector=a.detector,
                    severity=Severity[a.severity], src_ip=a.src_ip, dst_ip=a.dst_ip,
                    dst_port=a.dst_port, message=a.description, metadata=a.evidence)
              for a in normalized]

    rep_dir = cfg.reporting.get("report_dir", "reports")
    reporter  = Reporter(rep_dir)
    visualizer = Visualizer(rep_dir)
    print(reporter.generate(alerts, processor_stats=stats[-1] if stats else {}, save=True))
    visualizer.plot_traffic_distribution(alerts)
    visualizer.plot_severity_pie(alerts)


if __name__ == "__main__":
    main()
