"""
pcap_writer.py
--------------
Writes captured packets to rotating PCAP files for offline forensic analysis.

* Files are rotated when they exceed ``rotate_mb`` megabytes.
* At most ``max_files`` files are kept; older ones are deleted.
* Writing is done from a dedicated thread to avoid blocking the capture path.
"""

from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path
from typing import Optional

from scapy.packet import Packet
from scapy.utils import PcapWriter

from src.logger.logger import get_logger

log = get_logger("capture.pcap")


class RotatingPcapWriter:
    def __init__(
        self,
        output_dir: str = "captures",
        rotate_mb: float = 50.0,
        max_files: int = 10,
    ):
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._rotate_bytes = int(rotate_mb * 1024 * 1024)
        self._max_files = max_files

        self._queue: queue.Queue = queue.Queue(maxsize=5000)
        self._writer: Optional[PcapWriter] = None
        self._current_path: Optional[Path] = None
        self._bytes_written = 0
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._running = True
        self._open_new_file()
        t = threading.Thread(target=self._write_loop, daemon=True, name="nids-pcap")
        t.start()
        log.info(f"PCAP writer started → {self._output_dir}")

    def stop(self) -> None:
        self._running = False
        self._queue.put(None)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def write(self, packet: Packet) -> None:
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            pass  # Drop silently; don't block the capture thread

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _write_loop(self) -> None:
        while True:
            try:
                pkt = self._queue.get(timeout=1.0)
            except queue.Empty:
                if not self._running:
                    break
                continue
            if pkt is None:
                break
            try:
                self._writer.write(pkt)
                self._bytes_written += len(pkt)
                if self._bytes_written >= self._rotate_bytes:
                    self._rotate()
            except Exception as exc:
                log.error(f"PCAP write error: {exc}")
        if self._writer:
            self._writer.close()

    def _open_new_file(self) -> None:
        ts = time.strftime("%Y%m%d_%H%M%S")
        self._current_path = self._output_dir / f"capture_{ts}.pcap"
        self._writer = PcapWriter(str(self._current_path), append=False, sync=True)
        self._bytes_written = 0
        log.info(f"Opened PCAP file: {self._current_path}")

    def _rotate(self) -> None:
        if self._writer:
            self._writer.close()
        log.info(f"Rotated PCAP: {self._current_path} ({self._bytes_written/1024/1024:.1f} MB)")
        self._open_new_file()
        self._cleanup_old_files()

    def _cleanup_old_files(self) -> None:
        files = sorted(self._output_dir.glob("capture_*.pcap"), key=os.path.getmtime)
        while len(files) > self._max_files:
            oldest = files.pop(0)
            oldest.unlink(missing_ok=True)
            log.info(f"Deleted old PCAP: {oldest}")
