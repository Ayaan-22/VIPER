"""Bounded source-partitioned workers with event-time ordering and draining shutdown."""
from __future__ import annotations

import queue
import logging
import threading
import time
import uuid
from collections import Counter, OrderedDict
from src.core.traffic import PacketEvent, current_event, network_layer, packet_timestamp, protocol
from src.logger.logger import get_logger

log = get_logger("processor")


class PacketProcessor:
    def __init__(self, detectors, worker_threads=4, queue_maxsize=10000, stats_interval=10.0):
        if not 1 <= worker_threads <= 64 or queue_maxsize < 1 or stats_interval <= 0:
            raise ValueError("invalid processor capacity or interval")
        self._detectors = detectors
        self._worker_count = worker_threads
        self._queues = [queue.Queue(maxsize=queue_maxsize) for _ in range(worker_threads)]
        self._queue = self._queues[0]
        self._slots = threading.BoundedSemaphore(queue_maxsize)
        self._stats_interval = stats_interval
        self._pkt_received = self._pkt_dropped = self._pkt_processed = 0
        self._late = self._errors = self._rejected = 0
        self._protocols = Counter()
        self._lock = threading.RLock()
        self._lifecycle = threading.Lock()
        self._running = False
        self._closed = False
        self._threads = []
        self._sentinels_sent = 0
        self._stop_event = threading.Event()
        self.session_id = str(uuid.uuid4())
        self.started_at = time.time()
        self.health_provider = lambda: {}

    def start(self):
        with self._lifecycle:
            if self._closed:
                raise RuntimeError("processor cannot be restarted after stop")
            if self._running:
                return
            with self._lock:
                self._running = True
            self._threads = [threading.Thread(target=self._worker_loop, args=(q,),
                             name=f"nids-worker-{i}", daemon=True) for i, q in enumerate(self._queues)]
            for thread in self._threads:
                thread.start()
            self._stats_thread = threading.Thread(target=self._stats_loop, name="nids-stats", daemon=True)
            self._stats_thread.start()

    def stop(self, timeout=30.0):
        with self._lifecycle:
            if self._closed:
                return
            with self._lock:
                was_running, self._running = self._running, False
            self._stop_event.set()
            if self._threads:
                deadline = time.monotonic() + timeout
                for q in self._queues[self._sentinels_sent:]:
                    q.put(None, timeout=max(0.01, deadline - time.monotonic()))
                    self._sentinels_sent += 1
                for thread in self._threads:
                    thread.join(max(0, deadline - time.monotonic()))
                if any(thread.is_alive() for thread in self._threads):
                    raise TimeoutError("packet workers did not drain; final evidence is incomplete")
                self._stats_thread.join(timeout=1)
            self._closed = True

    def enqueue(self, packet):
        with self._lock:
            if not self._running:
                self._rejected += 1
                return False
            self._pkt_received += 1
            if not self._slots.acquire(blocking=False):
                self._pkt_dropped += 1
                return False
            try:
                net = network_layer(packet)
                source = str(net.src) if net is not None else "non-ip"
                captured = packet_timestamp(packet)
                event = PacketEvent(packet, time.time() if captured is None else captured,
                                    time.monotonic(), self._pkt_received)
                self._queues[hash(source) % self._worker_count].put_nowait((source, event))
                return True
            except Exception:
                self._slots.release()
                self._pkt_dropped += 1
                raise

    def _worker_loop(self, work_queue=None):
        q = work_queue if work_queue is not None else self._queue
        latest = OrderedDict()
        while True:
            item = q.get()
            try:
                if item is None:
                    return
                source, event = item
                previous = latest.get(source)
                if previous is not None and event.timestamp < previous:
                    with self._lock:
                        self._late += 1
                        self._pkt_dropped += 1
                    continue
                latest[source] = event.timestamp
                latest.move_to_end(source)
                if len(latest) > 8192:
                    latest.popitem(last=False)
                token = current_event.set(event)
                try:
                    for detector in self._detectors:
                        try:
                            detector.process(event.packet)
                        except Exception:
                            with self._lock:
                                self._errors += 1
                            log.exception("Detector %s failed", detector.name)
                    with self._lock:
                        self._pkt_processed += 1
                        self._protocols[protocol(event.packet)] += 1
                finally:
                    current_event.reset(token)
            finally:
                if item is not None:
                    self._slots.release()
                q.task_done()

    def log_stats(self):
        telemetry = get_logger("telemetry")
        telemetry.setLevel(logging.INFO)
        telemetry.info("packet_stats", extra={**self.stats, **self.health_provider()})

    def _stats_loop(self):
        while not self._stop_event.wait(self._stats_interval):
            self.log_stats()

    @property
    def stats(self):
        with self._lock:
            return {"received": self._pkt_received, "processed": self._pkt_processed,
                    "dropped": self._pkt_dropped, "queued": sum(q.qsize() for q in self._queues),
                    "late_packets": self._late, "detector_errors": self._errors,
                    "rejected_after_stop": self._rejected, "protocol_counts": dict(self._protocols),
                    "session_id": self.session_id, "started_at": self.started_at,
                    "heartbeat_interval": self._stats_interval,
                    "sensor_running": self._running}
