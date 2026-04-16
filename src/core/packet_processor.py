"""
packet_processor.py
-------------------
The PacketProcessor decouples packet capture from detection using a
bounded in-memory queue and a pool of worker threads.

Architecture
------------
                  ┌──────────────┐
  Scapy capture   │  Capture     │
  (main thread)──►│  Thread      │──► Queue ──► Worker[0]
                  │  (sniff())   │         ├──► Worker[1]
                  └──────────────┘         └──► Worker[N]
                                                  │
                                            Detectors[]
                                                  │
                                            AlertHandler

Benefits
--------
* The capture loop is never blocked by slow detectors.
* Worker threads can be scaled (``worker_threads`` in config).
* Queue overflow drops packets gracefully with a counter, preventing OOM.
"""

from __future__ import annotations

import queue
import threading
import time
from typing import List

from scapy.packet import Packet

from src.detectors.base import BaseDetector
from src.logger.logger import get_logger

log = get_logger("processor")


class PacketProcessor:
    def __init__(
        self,
        detectors: List[BaseDetector],
        worker_threads: int = 4,
        queue_maxsize: int = 10_000,
        stats_interval: float = 10.0,
    ):
        self._detectors = detectors
        self._queue: queue.Queue = queue.Queue(maxsize=queue_maxsize)
        self._worker_count = worker_threads
        self._stats_interval = stats_interval

        # Metrics
        self._pkt_received = 0
        self._pkt_dropped = 0
        self._pkt_processed = 0
        self._lock = threading.Lock()
        self._running = False

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        self._running = True
        # Worker threads
        for i in range(self._worker_count):
            t = threading.Thread(
                target=self._worker_loop, name=f"nids-worker-{i}", daemon=True
            )
            t.start()
        # Stats reporter
        t = threading.Thread(
            target=self._stats_loop, name="nids-stats", daemon=True
        )
        t.start()
        log.info(f"PacketProcessor started with {self._worker_count} workers")

    def stop(self) -> None:
        self._running = False
        # Unblock workers
        for _ in range(self._worker_count):
            self._queue.put(None)

    # ------------------------------------------------------------------
    # Public enqueue (called from Scapy capture callback)
    # ------------------------------------------------------------------

    def enqueue(self, packet: Packet) -> None:
        with self._lock:
            self._pkt_received += 1
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            with self._lock:
                self._pkt_dropped += 1

    # ------------------------------------------------------------------
    # Worker loop
    # ------------------------------------------------------------------

    def _worker_loop(self) -> None:
        while True:
            try:
                packet = self._queue.get(timeout=1.0)
            except queue.Empty:
                if not self._running:
                    return
                continue

            if packet is None:           # stop sentinel
                return

            try:
                for detector in self._detectors:
                    detector.process(packet)
            except Exception as exc:
                log.error(f"Detector exception: {exc}", exc_info=True)
            finally:
                with self._lock:
                    self._pkt_processed += 1
                self._queue.task_done()

    # ------------------------------------------------------------------
    # Stats reporter
    # ------------------------------------------------------------------

    def _stats_loop(self) -> None:
        while self._running:
            time.sleep(self._stats_interval)
            with self._lock:
                log.info(
                    "packet_stats",
                    extra={
                        "received":  self._pkt_received,
                        "processed": self._pkt_processed,
                        "dropped":   self._pkt_dropped,
                        "queued":    self._queue.qsize(),
                    },
                )

    # ------------------------------------------------------------------
    # Accessors
    # ------------------------------------------------------------------

    @property
    def stats(self) -> dict:
        with self._lock:
            return {
                "received":  self._pkt_received,
                "processed": self._pkt_processed,
                "dropped":   self._pkt_dropped,
                "queued":    self._queue.qsize(),
            }
