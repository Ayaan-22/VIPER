"""
anomaly.py
----------
Statistical anomaly detector using a rolling mean ± N·σ baseline.

How it works
------------
1. During the *baseline phase* (first ``min_samples`` packets per src),
   the detector silently accumulates packet sizes and inter-arrival times
   to build a statistical profile.
2. After the baseline is established, every new packet is scored against
   the profile.  If the observed metric deviates by more than
   ``deviation_factor`` standard deviations from the mean, an alert fires.

Two signals are monitored per source IP:
  * **Packet size** – very large or very small packets can indicate
    tunnelling, fragmentation attacks, or malformed traffic.
  * **Packet rate** – sudden rate spikes beyond the learnt baseline
    suggest volumetric attacks or scanning.

Limitations
-----------
This is a *lightweight* statistical model (no ML library required).
It can produce false positives during warm-up or for highly variable
legitimate traffic.  Tune ``deviation_factor`` and ``min_samples``
in config.yaml to balance sensitivity vs. noise.
"""

from __future__ import annotations

import math
import time
import threading
from collections import defaultdict
from typing import Dict, List

from scapy.layers.inet import IP
from scapy.packet import Packet

from src.alerting.alert import Severity
from src.alerting.handler import AlertHandler
from src.core.sliding_window import SlidingWindowDict
from src.detectors.base import BaseDetector


class _RunningStats:
    """
    Welford's online algorithm for running mean and variance.
    O(1) per update, numerically stable.
    """

    __slots__ = ("n", "mean", "_M2")

    def __init__(self):
        self.n: int = 0
        self.mean: float = 0.0
        self._M2: float = 0.0

    def update(self, x: float) -> None:
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self._M2 += delta * (x - self.mean)

    @property
    def variance(self) -> float:
        return self._M2 / self.n if self.n > 1 else 0.0

    @property
    def std(self) -> float:
        return math.sqrt(self.variance)

    def z_score(self, x: float) -> float:
        if self.std == 0:
            return 0.0
        return abs(x - self.mean) / self.std


class _SourceProfile:
    def __init__(self):
        self.size_stats = _RunningStats()
        self.last_ts: float = time.monotonic()
        self.iat_stats = _RunningStats()     # inter-arrival time
        self.lock = threading.Lock()


class AnomalyDetector(BaseDetector):
    name = "anomaly"

    def __init__(self, cfg: dict, handler: AlertHandler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._deviation_factor: float = cfg.get("deviation_factor", 3.0)
        self._min_samples: int = cfg.get("min_samples", 20)
        self._baseline_window: float = cfg.get("baseline_window_seconds", 60)
        self._profiles: Dict[str, _SourceProfile] = defaultdict(_SourceProfile)
        self._throttle = SlidingWindowDict(10)   # alert at most once per 10 s per src

    def process(self, packet: Packet) -> None:
        if not self.enabled:
            return
        if not packet.haslayer(IP):
            return

        src_ip = packet[IP].src
        if self.is_whitelisted(src_ip):
            return

        pkt_len = len(packet)
        now = time.monotonic()

        profile = self._profiles[src_ip]
        with profile.lock:
            # Update inter-arrival time
            iat = now - profile.last_ts
            profile.last_ts = now

            # Update stats
            profile.size_stats.update(pkt_len)
            if profile.iat_stats.n > 0:         # skip the very first packet
                profile.iat_stats.update(iat)
            else:
                profile.iat_stats.update(iat)   # seed with first IAT

            n = profile.size_stats.n

        # --- still in baseline phase ---
        if n < self._min_samples:
            return

        # --- check for anomalies ---
        anomalies = []

        size_z = profile.size_stats.z_score(pkt_len)
        if size_z > self._deviation_factor:
            anomalies.append(
                f"pkt_size={pkt_len}B (mean={profile.size_stats.mean:.0f}, "
                f"z={size_z:.1f})"
            )

        iat_z = profile.iat_stats.z_score(iat)
        if iat_z > self._deviation_factor and iat < 0.001:
            # Very fast arrival (possible burst) is more interesting than slow
            anomalies.append(
                f"iat={iat*1000:.2f}ms (mean={profile.iat_stats.mean*1000:.2f}ms, "
                f"z={iat_z:.1f})"
            )

        if anomalies and self._throttle.count(src_ip) == 0:
            self._throttle.add(src_ip)
            self.emit(
                severity=Severity.MEDIUM,
                src_ip=src_ip,
                message=f"Anomalous traffic pattern: {'; '.join(anomalies)}",
                anomalies=anomalies,
                samples=n,
            )
