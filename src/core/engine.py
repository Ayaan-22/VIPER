"""
engine.py
---------
The NIDS Engine is the top-level orchestrator.  It:

  1. Reads configuration.
  2. Instantiates detectors, the alert handler, and the packet processor.
  3. Optionally starts the PCAP writer.
  4. Starts Scapy's sniff() on the requested interface.
  5. On shutdown: prints a final report and visualisations.
"""

from __future__ import annotations

import signal
import threading
import time
from typing import List, Optional

from src.alerting.handler import AlertHandler
from src.capture.pcap_writer import RotatingPcapWriter
from src.core.packet_processor import PacketProcessor
from src.detectors.anomaly import AnomalyDetector
from src.detectors.base import BaseDetector
from src.detectors.brute_force import BruteForceDetector
from src.detectors.flood_detectors import (
    IcmpFloodDetector,
    SynFloodDetector,
    UdpFloodDetector,
)
from src.detectors.port_scan import PortScanDetector
from src.logger.logger import get_logger, setup_logger
from src.reporting.reporter import Reporter, Visualizer
from src.utils.config_loader import Config

log = get_logger("engine")


class NIDSEngine:
    def __init__(self, config: Config, interface: Optional[str] = None):
        self.cfg = config
        raw_iface = interface or config.network.get("interface", "eth0")
        self.interface = self._resolve_interface(raw_iface)
        self._running = False

        # Logging
        lcfg = config.logging
        setup_logger(
            name="nids",
            log_file=lcfg.get("file", "logs/nids.log"),
            level=lcfg.get("level", "INFO"),
            log_format=lcfg.get("format", "json"),
            max_bytes=lcfg.get("max_bytes", 10_485_760),
            backup_count=lcfg.get("backup_count", 5),
            console=lcfg.get("console", True),
            colorize=config.alerting.get("console", {}).get("colorize", True),
        )

        # Alert handler
        self.alert_handler = AlertHandler(config.alerting)

        # Detectors
        det_cfg = config.detection
        self.detectors: List[BaseDetector] = []
        self._register_detectors(det_cfg)

        # Packet processor
        perf = config.performance
        self.processor = PacketProcessor(
            detectors=self.detectors,
            worker_threads=perf.get("worker_threads", 4),
            queue_maxsize=perf.get("queue_maxsize", 10_000),
            stats_interval=perf.get("stats_interval", 10),
        )

        # PCAP writer
        cap_cfg = config.capture
        self.pcap_writer: Optional[RotatingPcapWriter] = None
        if cap_cfg.get("enabled", True):
            self.pcap_writer = RotatingPcapWriter(
                output_dir=cap_cfg.get("output_dir", "captures"),
                rotate_mb=cap_cfg.get("rotate_mb", 50),
                max_files=cap_cfg.get("max_files", 10),
            )

        # Reporter
        rep_cfg = config.reporting
        self.reporter = Reporter(rep_cfg.get("report_dir", "reports"))
        self.visualizer = Visualizer(rep_cfg.get("report_dir", "reports"))
        self._report_interval = rep_cfg.get("auto_report_interval", 300)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def start(self) -> None:
        # Lazy import scapy to keep startup fast when running tests
        from scapy.all import sniff

        self._running = True
        self.processor.start()

        if self.pcap_writer:
            self.pcap_writer.start()

        # Signal handler for clean shutdown
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, self._signal_handler)

        # Auto-report thread
        if self._report_interval > 0:
            t = threading.Thread(
                target=self._auto_report_loop, daemon=True, name="nids-autoreport"
            )
            t.start()

        log.info(f"NIDS engine starting on interface '{self.interface}'")
        print(f"\n{'━'*62}")
        print(f"  🛡   VIPER  –  Network Intrusion Detection System")
        print(f"{'━'*62}")
        print(f"  Interface  : {self.interface}")
        print(f"  Detectors  : {', '.join(d.name for d in self.detectors)}")
        print(f"  Log file   : {self.cfg.logging.get('file', 'logs/nids.log')}")
        print(f"  Press Ctrl-C to stop and generate a final report.")
        print(f"{'━'*62}\n")

        bpf = self.cfg.network.get("pcap_filter", "")
        promisc = self.cfg.network.get("promiscuous", True)

        try:
            sniff(
                iface=self.interface,
                filter=bpf or None,
                prn=self._packet_callback,
                store=False,
                promisc=promisc,
            )
        except PermissionError:
            log.critical("Permission denied – run as root / with CAP_NET_RAW.")
            raise
        except Exception as exc:
            log.critical(f"Fatal sniff error: {exc}", exc_info=True)
            raise

    def stop(self) -> None:
        self._running = False
        self.processor.stop()
        if self.pcap_writer:
            self.pcap_writer.stop()
        self._final_report()

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    @staticmethod
    def _resolve_interface(iface_hint: str):
        """Resolve a user-provided interface hint (index, name, or partial
        name) into a scapy-compatible interface object.

        Scapy's ``sniff()`` does not accept a raw Windows interface index
        (e.g. ``"16"``).  This helper looks up the correct
        ``NetworkInterface`` from scapy's ``IFACES`` registry so the caller
        can pass the result directly to ``sniff(iface=...)``.
        """
        try:
            from scapy.interfaces import IFACES, resolve_iface
            # 1. Try scapy's own resolver first (handles names / GUIDs)
            try:
                return resolve_iface(iface_hint)
            except ValueError:
                pass

            # 2. If the hint looks numeric, match by interface index
            if iface_hint.isdigit():
                idx = int(iface_hint)
                for iface in IFACES.values():
                    if getattr(iface, "index", None) == idx:
                        return iface

            # 3. Partial / case-insensitive name match
            hint_lower = iface_hint.lower()
            for iface in IFACES.values():
                iface_name = getattr(iface, "name", "") or ""
                iface_desc = getattr(iface, "description", "") or ""
                if hint_lower in iface_name.lower() or hint_lower in iface_desc.lower():
                    return iface

        except ImportError:
            pass  # scapy not available; fall through and return raw string

        # Fallback: return the original string and let scapy raise later
        return iface_hint

    def _register_detectors(self, det_cfg: dict) -> None:
        mapping = {
            "port_scan":   PortScanDetector,
            "syn_flood":   SynFloodDetector,
            "udp_flood":   UdpFloodDetector,
            "icmp_flood":  IcmpFloodDetector,
            "brute_force": BruteForceDetector,
            "anomaly":     AnomalyDetector,
        }
        for key, cls in mapping.items():
            cfg_section = det_cfg.get(key, {})
            if cfg_section.get("enabled", True):
                self.detectors.append(cls(cfg_section, self.alert_handler))
                log.info(f"Registered detector: {key}")

    def _packet_callback(self, packet) -> None:
        self.processor.enqueue(packet)
        if self.pcap_writer:
            self.pcap_writer.write(packet)

    def _signal_handler(self, signum, frame) -> None:
        print("\n[!] Shutdown signal received …")
        self.stop()
        raise SystemExit(0)

    def _auto_report_loop(self) -> None:
        while self._running:
            time.sleep(self._report_interval)
            if self._running:
                self._final_report(save=True, print_to_console=False)

    def _final_report(self, save: bool = True, print_to_console: bool = True) -> None:
        alerts = self.alert_handler.history
        report = self.reporter.generate(
            alerts,
            processor_stats=self.processor.stats,
            save=save,
        )
        if print_to_console:
            print(report)
        self.visualizer.plot_traffic_distribution(alerts)
        self.visualizer.plot_severity_pie(alerts)
