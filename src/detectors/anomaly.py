"""Bounded rolling trusted baseline; anomalous samples do not train the model."""
from __future__ import annotations

import math
import threading
from collections import OrderedDict, deque
from src.alerting.alert import Severity
from src.core.traffic import event_time, network_layer
from src.detectors.base import BaseDetector


class _RunningStats:
    def __init__(self):
        self.n, self.mean, self._M2 = 0, 0.0, 0.0

    def update(self, x):
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self._M2 += delta * (x - self.mean)

    def remove(self, x):
        if self.n <= 1:
            self.n, self.mean, self._M2 = 0, 0.0, 0.0
            return
        mean = (self.mean * self.n - x) / (self.n - 1)
        self._M2 = max(0.0, self._M2 - (x - self.mean) * (x - mean))
        self.mean = mean
        self.n -= 1

    @property
    def variance(self):
        return self._M2 / self.n if self.n > 1 else 0.0

    @property
    def std(self):
        return math.sqrt(self.variance)

    def z_score(self, x):
        return abs(x - self.mean) / self.std if self.std else (math.inf if self.n and x != self.mean else 0.0)


class _SourceProfile:
    def __init__(self):
        self.size_stats = _RunningStats()
        self.iat_stats = _RunningStats()
        self.last_ts = None
        self.samples = deque()
        self.lock = threading.Lock()

    def remove_oldest(self):
        _, size, iat = self.samples.popleft()
        self.size_stats.remove(size)
        if iat is not None:
            self.iat_stats.remove(iat)


class AnomalyDetector(BaseDetector):
    name = "anomaly"

    def __init__(self, cfg, handler):
        super().__init__(cfg, handler, whitelist=cfg.get("whitelist_ips", []))
        self._deviation_factor = cfg.get("deviation_factor", 3.0)
        self._min_samples = cfg.get("min_samples", 20)
        self._baseline_window = cfg.get("baseline_window_seconds", 60)
        self._max_samples = cfg.get("max_baseline_samples", 512)
        self._max_profiles = cfg.get("max_state_keys", 2048)
        self._profiles = OrderedDict()
        self._profiles_lock = self._state_lock
        self._throttle = self.throttle(10)
        self._evictions = 0
        self._late = 0

    def process(self, packet):
        net = network_layer(packet)
        if not self.enabled or net is None or self.is_whitelisted(net.src):
            return
        now, size = event_time(packet), len(packet)
        anomalies = []
        with self._profiles_lock:
            if net.src not in self._profiles:
                if len(self._profiles) >= self._max_profiles:
                    self._profiles.popitem(last=False)
                    self._evictions += 1
                self._profiles[net.src] = _SourceProfile()
            profile = self._profiles[net.src]
            self._profiles.move_to_end(net.src)
            if profile.last_ts is not None and now < profile.last_ts:
                self._late += 1
                return
            while profile.samples and profile.samples[0][0] < now - self._baseline_window:
                profile.remove_oldest()
            iat = None if profile.last_ts is None else now - profile.last_ts
            profile.last_ts = now
            n = profile.size_stats.n
            if n >= self._min_samples:
                if profile.size_stats.z_score(size) > self._deviation_factor:
                    anomalies.append(f"packet size {size} B outside trusted baseline (mean {profile.size_stats.mean:.0f} B)")
                if (iat is not None and profile.iat_stats.n >= self._min_samples and
                        iat < 0.001 and profile.iat_stats.z_score(iat) > self._deviation_factor):
                    anomalies.append("inter-arrival time outside trusted baseline")
            if not anomalies:
                while len(profile.samples) >= self._max_samples:
                    profile.remove_oldest()
                profile.samples.append((now, size, iat))
                profile.size_stats.update(size)
                if iat is not None:
                    profile.iat_stats.update(iat)
            fire = anomalies and self._throttle.acquire(net.src, now)
        if fire:
            self.emit_packet(packet, severity=Severity.MEDIUM,
                             message="Anomalous traffic pattern: " + "; ".join(anomalies),
                             anomalies=anomalies, samples=n, baseline_policy="rolling_trusted",
                             baseline_window_seconds=self._baseline_window)

    @property
    def health(self):
        return {**super().health, "profile_evictions": self._evictions,
                "late_packets": self._late, "profiles": len(self._profiles)}
