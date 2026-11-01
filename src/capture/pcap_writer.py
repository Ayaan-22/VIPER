"""Bounded rotating PCAP export with observable loss and synchronous drain."""
from __future__ import annotations

import os
import queue
import threading
import time
from pathlib import Path
from scapy.utils import PcapWriter
from src.logger.logger import get_logger

log = get_logger("capture.pcap")


class RotatingPcapWriter:
    def __init__(self, output_dir="captures", rotate_mb=50.0, max_files=10):
        if rotate_mb <= 0 or max_files < 1:
            raise ValueError("capture rotation and retention must be positive")
        self._output_dir = Path(output_dir)
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self._rotate_bytes = int(rotate_mb * 1024 * 1024)
        self._max_files = max_files
        self._queue = queue.Queue(maxsize=5000)
        self._writer = None
        self._current_path = None
        self._bytes_written = 0
        self._running = False
        self._closed = False
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._written = self._dropped = self._errors = 0
        self._last_error = None
        self._sentinel_sent = False

    def start(self):
        with self._lifecycle:
            if self._closed:
                raise RuntimeError("PCAP writer cannot restart after stop")
            if self._running:
                return
            try:
                self._open_new_file()
                self._cleanup_old_files()
                with self._lock:
                    self._running = True
                worker = threading.Thread(target=self._write_loop, daemon=True, name="nids-pcap")
                worker.start()
                self._thread = worker
            except BaseException:
                with self._lock:
                    self._running = False
                if self._writer is not None:
                    try:
                        self._writer.close()
                    except Exception:
                        log.exception("PCAP close failed after startup failure")
                self._closed = True
                raise

    def stop(self, timeout=30.0):
        with self._lifecycle:
            if self._closed:
                return
            with self._lock:
                self._running = False
            if hasattr(self, "_thread"):
                deadline = time.monotonic() + timeout
                if not self._sentinel_sent:
                    self._queue.put(None, timeout=timeout)
                    self._sentinel_sent = True
                self._thread.join(max(0, deadline - time.monotonic()))
                if self._thread.is_alive():
                    raise TimeoutError("PCAP writer did not drain; capture is incomplete")
            elif self._writer is not None:
                # File creation/retention may fail before the worker starts.
                self._writer.close()
            self._closed = True

    def write(self, packet):
        with self._lock:
            if not self._running:
                self._dropped += 1
                return False
            try:
                self._queue.put_nowait(packet)
                return True
            except queue.Full:
                self._dropped += 1
                return False

    def _write_loop(self):
        try:
            while True:
                packet = self._queue.get()
                try:
                    if packet is None:
                        return
                    try:
                        self._writer.write(packet)
                        with self._lock:
                            self._written += 1
                        self._bytes_written += len(packet) + 16
                        if self._bytes_written >= self._rotate_bytes:
                            self._rotate()
                    except Exception as exc:
                        with self._lock:
                            self._errors += 1
                            self._last_error = str(exc)
                        log.exception("PCAP write failed")
                finally:
                    self._queue.task_done()
        finally:
            if self._writer:
                try:
                    self._writer.close()
                except Exception as exc:
                    with self._lock:
                        self._errors += 1
                        self._last_error = str(exc)
                    log.exception("PCAP close failed")

    def _open_new_file(self):
        self._current_path = self._output_dir / f"capture_{time.strftime('%Y%m%d_%H%M%S')}_{time.time_ns()}.pcap"
        self._writer = PcapWriter(str(self._current_path), append=False, sync=True)
        self._bytes_written = 24

    def _rotate(self):
        if self._writer:
            self._writer.close()
        self._open_new_file()
        self._cleanup_old_files()

    def _cleanup_old_files(self):
        files = sorted(self._output_dir.glob("capture_*.pcap"), key=os.path.getmtime)
        for old in files[:-self._max_files]:
            if old != self._current_path:
                old.unlink(missing_ok=True)

    @property
    def stats(self):
        with self._lock:
            return {"written": self._written, "dropped": self._dropped, "errors": self._errors,
                    "queued": self._queue.qsize(), "running": self._running,
                    "last_error": self._last_error}
