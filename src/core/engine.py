"""Sensor orchestration: controllable capture, draining workers, final evidence last."""
from __future__ import annotations

import signal
import threading
import time
from typing import List, Optional
from src.logger.logger import setup_logger, get_logger
from src.alerting.handler import AlertHandler
from src.core.packet_processor import PacketProcessor
from src.capture.pcap_writer import RotatingPcapWriter
from src.reporting.reporter import Reporter, Visualizer
from src.detectors.base import BaseDetector
from src.detectors.port_scan import PortScanDetector
from src.detectors.flood_detectors import SynFloodDetector, UdpFloodDetector, IcmpFloodDetector
from src.detectors.brute_force import BruteForceDetector
from src.detectors.anomaly import AnomalyDetector
from src.utils.config_loader import Config

log = get_logger("engine")


class NIDSEngine:
    def __init__(self, config: Config, interface=None):
        self.cfg = config
        self.interface = self._resolve_interface(interface or config.network.get("interface", "eth0"))
        lcfg = config.logging
        setup_logger(name="nids", log_file=lcfg.get("file", "logs/nids.log"),
                     level=lcfg.get("level", "INFO"), log_format=lcfg.get("format", "json"),
                     max_bytes=lcfg.get("max_bytes", 10485760), backup_count=lcfg.get("backup_count", 5),
                     console=lcfg.get("console", True),
                     colorize=config.alerting.get("console", {}).get("colorize", True))
        self.alert_handler = AlertHandler(config.alerting)
        self.detectors = []
        self._register_detectors(config.detection)
        perf = config.performance
        self.processor = PacketProcessor(self.detectors, perf["worker_threads"],
                                         perf["queue_maxsize"], perf["stats_interval"])
        self.alert_handler.session_id = self.processor.session_id
        cap = config.capture
        self.pcap_writer = RotatingPcapWriter(cap["output_dir"], cap["rotate_mb"], cap["max_files"]) if cap["enabled"] else None
        rep = config.reporting
        self.reporter = Reporter(rep["report_dir"])
        self.visualizer = Visualizer(rep["report_dir"])
        self._report_interval = rep["auto_report_interval"]
        self.processor.health_provider = self._health
        self._running = False
        self._stopped = False
        self._stop_event = threading.Event()
        self._stop_lock = threading.Lock()
        self._report_lock = threading.Lock()
        self._sniffer = None
        self._report_thread = None

    def start(self):
        from scapy.all import AsyncSniffer
        if self._stopped:
            raise RuntimeError("create a new engine to restart capture")
        if self._running:
            raise RuntimeError("sensor is already running")
        self._running = True
        old_handlers = {}
        try:
            self.processor.start()
            if self.pcap_writer:
                self.pcap_writer.start()
            if threading.current_thread() is threading.main_thread():
                for sig in (signal.SIGINT, signal.SIGTERM):
                    old_handlers[sig] = signal.signal(sig, self._signal_handler)
            if self._report_interval > 0:
                self._report_thread = threading.Thread(target=self._auto_report_loop,
                                                      name="nids-autoreport", daemon=True)
                self._report_thread.start()
            self._sniffer = AsyncSniffer(iface=self.interface,
                                        filter=self.cfg.network.get("pcap_filter") or None,
                                        prn=self._packet_callback, store=False,
                                        promisc=self.cfg.network.get("promiscuous", True))
            self._sniffer.start()
            log.info("Sensor starting", extra={"session_id": self.processor.session_id,
                                              "interface": str(self.interface)})
            while not self._stop_event.wait(0.25):
                if not self._sniffer.thread.is_alive():
                    self._sniffer.join()  # propagate capture startup/runtime errors
                    break
        finally:
            try:
                self.stop()
            finally:
                for sig, previous in old_handlers.items():
                    signal.signal(sig, previous)

    def stop(self):
        with self._stop_lock:
            if self._stopped:
                return
            self._stop_event.set()
            self._running = False
            errors = []
            if self._sniffer is not None and self._sniffer.running:
                try:
                    self._sniffer.stop(join=False)
                    self._sniffer.thread.join(timeout=10)
                    if self._sniffer.thread.is_alive():
                        raise TimeoutError("capture thread did not stop")
                except Exception as exc:
                    errors.append(exc)
            if self._report_thread is not None and self._report_thread is not threading.current_thread():
                self._report_thread.join(timeout=30)
                if self._report_thread.is_alive():
                    errors.append(TimeoutError("automatic report did not finish"))
            for component in (self.processor, self.pcap_writer):
                if component:
                    try:
                        component.stop()
                    except Exception as exc:
                        errors.append(exc)
            self.alert_handler.shutdown(wait=True)
            self.processor.log_stats()
            if errors:
                raise RuntimeError("Shutdown incomplete: " + "; ".join(str(e) for e in errors))
            self._final_report()
            self._stopped = True

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


    def _health(self):
        return {"capture": self.pcap_writer.stats if self.pcap_writer else {"enabled": False},
                "delivery": self.alert_handler.stats,
                "detector_state": {d.name: d.health for d in self.detectors},
                "interface": str(self.interface)}

    def _packet_callback(self, packet):
        self.processor.enqueue(packet)
        if self.pcap_writer:
            self.pcap_writer.write(packet)

    def _signal_handler(self, signum, frame):
        # Keep signal handling nonblocking; the capture loop owns cleanup.
        self._stop_event.set()

    def _auto_report_loop(self):
        while not self._stop_event.wait(self._report_interval):
            try:
                self._final_report(print_to_console=False)
            except Exception:
                log.exception("Automatic report failed")

    def _final_report(self, save=True, print_to_console=True):
        with self._report_lock:
            alerts = self.alert_handler.history
            text = self.reporter.generate(alerts, processor_stats=self.processor.stats, save=save,
                                          alert_totals=self.alert_handler.stats)
            if print_to_console:
                print(text)
            self.visualizer.plot_traffic_distribution(alerts)
            self.visualizer.plot_severity_pie(alerts)
            from src.reporting.retention import prune_reports
            prune_reports(self.cfg.reporting["report_dir"],
                          max_files=self.cfg.reporting.get("max_files", 500),
                          max_bytes=self.cfg.reporting.get("max_total_mb", 512) * 1024 * 1024,
                          max_age_days=self.cfg.reporting.get("max_age_days", 30))
