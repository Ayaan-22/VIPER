# VIPER — Code & Security Audit (Complete)

**Repository:** https://github.com/Ayaan-22/VIPER
**Commit audited:** `967b1c8` ("Add VIPER Vision dashboard & analytics")
**Previous audit baseline:** commit `370ef98` ("Bound memory, smooth rates, dedupe alerts")
**Audit date:** 2026-07-01
**Scope:** Full source tree (`src/`, `dashboard/`, `main.py`), test suite, Docker/Compose config, and documentation.
**Size:** ~3,570 lines of Python across 30 files (up from ~2,720 lines / 21 files at the prior audit — the VIPER Vision dashboard is new since then).
**Method:** Manual line-by-line review of every module, `pytest --cov` execution against the live test suite, direct comparison against the prior audit's 12 findings to verify remediation status, and review of the Docker/Compose configuration.

---

## 0. Post-Audit Remediation Update — 2026-07-01

The audit findings below have been remediated in the working tree after the original review. Verification was run with:

```text
.venv\Scripts\python.exe -m pytest --cov=src --cov=dashboard --cov-report=term-missing
```

Result: **59 tests passed**, total coverage increased to **73%**, and the previously untested runtime modules now have direct coverage (`src/core/engine.py` 43%, `src/capture/pcap_writer.py` 47%, `src/reporting/reporter.py` 48%).

| Finding | Remediation status |
|---|---|
| §3.1 Dashboard API has no authentication | ✅ Fixed. Dashboard supports API key, bearer token, and Basic auth; non-local binds require a key; Docker Compose requires `VIPER_DASHBOARD_API_KEY`; `log_file_path` updates are confined to the allowed log directory. |
| §3.2 Anomaly detector scores after updating baseline | ✅ Fixed. Packets are scored against the pre-update profile, then folded into the baseline. Zero-variance baselines now treat a different observed value as anomalous instead of producing `z=0`. |
| §3.3 Dashboard severity sorting is alphabetical | ✅ Fixed. `/api/alerts?sort=severity` now uses `severity_rank()`. |
| §3.4 Engine/reporter/PCAP writer had 0% test coverage | ✅ Partially closed. Added deterministic tests for engine detector registration, reporter filename generation, and PCAP cleanup. Live sniffing and visual chart rendering remain outside unit-test scope. |
| §3.5 Unbounded email/webhook delivery threads | ✅ Fixed. Alert delivery now uses a bounded `ThreadPoolExecutor` plus a bounded semaphore for max in-flight work. |
| §3.6 Docker disables APT freshness checks | ✅ Fixed. The `Acquire::Check-Valid-Until` / `Acquire::Check-Date` bypass was removed from both Docker stages. |
| §3.7 Duplicate flood detector classes | ⚪ Still open. This remains a maintainability-only refactor candidate. |
| §3.8 Severity strings from config are not validated | ✅ Fixed. Config load normalizes/validates severity fields with clear `ValueError`s; handler-level fallback parsing remains defensive. |
| §3.9 `main.py` mutates `Config._data` directly | ✅ Fixed. Added `Config.set(...)` and updated CLI overrides to use it. |
| §3.10 Report/visualisation filenames collide | ✅ Fixed. Report, visualisation, dashboard HTML report, and PCAP filenames now include `time.time_ns()`. |

---

## 1. Executive Summary

VIPER is a modular Python NIDS: packet capture is decoupled from detection via a bounded queue and worker pool, configuration uses a deep-merge-over-defaults pattern that degrades gracefully rather than crashing, and the multi-threaded core (sliding windows, packet processor, anomaly profiles) is now genuinely thread-safe throughout.

This is the second audit of this codebase. The first (against `370ef98`) found 12 issues, including one critical bug (a broken `Enum` that made `Severity` comparison operators crash) and two high-severity bugs (a silently-corrupting `--report-only` mode, and a packet processor that let one failing detector blind every other detector for that packet). **9 of those 12 findings are now fixed**, confirmed by direct re-reading of the current code — including all three Critical/High findings. Full remediation verification is in §2.

Since that audit, the codebase grew substantially: a full Flask-based dashboard ("VIPER Vision") was added, with its own API layer, analytics services, and rewritten frontend. That rewrite is where this audit's **new** findings originally lived — most notably, the dashboard shipped with **no authentication on any endpoint**, and was explicitly configured in `docker-compose.yml` to bind to `0.0.0.0`. The post-audit remediation above fixes the high-risk dashboard exposure and most of the medium/low findings.

| Severity | Count | Status |
|---|---|---|
| 🔴 Critical | 0 | — |
| 🟠 High | 1 | ✅ Fixed post-audit |
| 🟡 Medium | 4 | ✅ Fixed or partially closed post-audit |
| 🔵 Low | 5 | ✅ 4 fixed post-audit; 1 maintainability item still open |

None of the new findings are as severe as the prior audit's worst (a crashing core enum). The overall trajectory of this codebase between audits is positive: critical and high-severity defects were fixed, test coverage roughly doubled the ratio (37% → 62%) with the previously-untested `AnomalyDetector` going from 0% to 90%, and a genuine XSS-shaped pattern in the old dashboard was eliminated in the rewrite. The main outstanding gap is that the *new* dashboard code wasn't held to the same bar as the fixes applied to the core detection engine.

---

## 2. Remediation Verification — Prior Audit (`370ef98`) vs. Current (`967b1c8`)

Every finding from the prior audit was re-checked directly against the current source, not inferred from commit messages.

| # | Prior finding | Severity | Status | Evidence |
|---|---|---|---|---|
| 3.1 | `Severity._ORDER` registers as a 5th enum member, breaking `<`/`<=`/`>`/`>=` | 🔴 Critical | ✅ **Fixed** | `src/alerting/alert.py` now defines `_SEVERITY_ORDER` as a **module-level** dict (not inside the enum body) and implements `__lt__`/`__le__`/`__gt__`/`__ge__` against it. `list(Severity)` correctly yields exactly 4 members. |
| 3.2 | `--report-only` reads `obj.get("message", ...)` instead of `"alert_message"`, corrupting every parsed alert | 🟠 High | ✅ **Fixed** | `main.py`'s `_report_from_log()` now reads `obj.get("alert_message", "")`, matching what `Alert.to_log_dict()` actually writes. |
| 3.3 | `try/except` wraps the *entire* detector loop, so one failing detector blinds all others for that packet | 🟠 High | ✅ **Fixed** | `src/core/packet_processor.py::_worker_loop` now wraps `detector.process(packet)` individually, inside the `for` loop, with the failing detector's name in the log line. |
| 3.4 | `AnomalyDetector._profiles` dict mutated/read across threads with no lock (only per-profile locks existed) | 🟡 Medium | ✅ **Fixed** | `src/detectors/anomaly.py` now has a dedicated `self._profiles_lock` guarding dict lookup, insertion, and cleanup, separate from each `_SourceProfile.lock`. |
| 3.5 | `SlidingWindow.rate()` always divides by the full `window_seconds`, overstating burst rates on short (1s) windows | 🟡 Medium | ✅ **Fixed** | `rate()` now computes `elapsed = now - self._events[0][0]` and divides by `min(self.window_seconds, elapsed)`, with a comment explaining the trade-off. |
| 3.6 | Test coverage concentrated on safe code; `engine.py`, `packet_processor.py`, `pcap_writer.py`, `reporter.py`, `AnomalyDetector` at 0% | 🟡 Medium | ✅ **Further closed post-audit** | Initial remediation raised overall coverage 37% → 62% and brought `AnomalyDetector` to 90%. The post-audit pass added runtime wiring tests; coverage now reports `engine.py` 43%, `reporter.py` 48%, `pcap_writer.py` 47%, and total coverage 73%. |
| 3.7 | Dashboard interpolates alert fields into `innerHTML` with no escaping (stored-XSS-shaped pattern) | 🔵 Low | ✅ **Fixed** | The dashboard was rewritten entirely. `dashboard/static/vision.js` now runs every interpolated alert/connection/timeline field through a dedicated `escapeHtml()` helper before insertion (verified across all render functions: alert table, suspicious-connections table, timeline). |
| 3.8 | `BaseDetector._alert_count += 1` not guarded by `self._lock` despite the lock existing for this purpose | 🔵 Low | ✅ **Fixed** | `src/detectors/base.py::emit()` now wraps the increment in `with self._lock:`. |
| 3.9 | `taskName` (Python 3.12 asyncio field) leaks into every JSON log line | 🔵 Low | ✅ **Fixed** | `JsonFormatter.SKIP_ATTRS` in `src/logger/logger.py` now includes `"taskName"` with an explanatory comment. |
| 3.10 | Three near-identical flood detector classes (`Syn`/`Udp`/`Icmp`) — maintainability, not a bug | 🔵 Low | ❌ **Still open** | `src/detectors/flood_detectors.py` still has three separate classes differing only in layer check and message text. Not urgent, but any future fix to shared logic still needs applying three times. |
| 3.11 | `Dockerfile` disables `Acquire::Check-Valid-Until`/`Check-Date`, weakening apt repo freshness validation | 🔵 Low | ✅ **Fixed post-audit** | The APT freshness/date bypass was removed from both build and runtime stages. |
| 3.12 | Dead `if/else` in `AnomalyDetector.process()` where both branches did the same thing | 🔵 Low | ✅ **Fixed** | The current `process()` has a single unconditional `profile.iat_stats.update(iat)` call; the dead branch is gone. |

**Net: 9 fixed, 1 partially fixed, 2 still open.** All three highest-severity findings (the one Critical, both Highs) are confirmed fixed.

---

## 3. New Findings (introduced or newly identified since `370ef98`)

These are issues in code that either didn't exist at the prior audit (the dashboard rewrite) or wasn't previously flagged.

### 3.1 [HIGH] Dashboard API has no authentication or authorization — fixed post-audit

**File:** `dashboard/app.py`, all routes (lines 92–260)

`create_app()` exposes roughly 20 routes — `/api/alerts`, every `/api/analytics/*` endpoint, `/api/reports/generate`, `/api/settings` (both GET and PATCH), the SSE streams, and the WebSocket routes — with **zero auth, CSRF protection, or rate limiting** anywhere in the app factory.

This is materially worse than a hypothetical "add auth eventually" note because of how it's actually deployed:

```yaml
# docker-compose.yml, dashboard service
command: [..., "--host", "0.0.0.0", "--port", "5000", ...]
ports:
  - "5000:5000"
```

The dashboard is explicitly configured to bind beyond localhost and publish the port to the host. Combined with the unauthenticated `PATCH /api/settings` endpoint:

```python
# dashboard/app.py, lines 206–226
@app.patch("/api/settings")
def api_patch_settings():
    updates = request.get_json(silent=True) or {}
    ...
    app.viper_settings[key] = value
    if key == "log_file_path":
        app.config["VIPER_LOG_PATH"] = str(value)
    return jsonify(app.viper_settings)
```

any unauthenticated caller can redirect which log file the entire dashboard reads and displays on every subsequent request. This doesn't grant arbitrary file *write* or code execution, but it does let an anonymous party read and expose the contents of any file the dashboard process can access, framed as "alert data," and overwrite the operator's intended configuration with no audit trail.

**Recommendation:** Put the dashboard behind a reverse proxy that enforces auth (nginx/Caddy with basic auth or OIDC), or add a minimal API-key check to `create_app()`'s routes. At minimum, validate `log_file_path` against an allow-listed directory before accepting it via `PATCH`.

**Remediation:** Implemented dashboard API-key enforcement with `X-VIPER-API-Key`, bearer token, and Basic auth support. Non-local dashboard binds now fail unless an API key is configured, Docker Compose requires `VIPER_DASHBOARD_API_KEY`, Compose dashboard ports bind to localhost, and `PATCH /api/settings` validates `log_file_path` against the allowed log directory.

### 3.2 [MEDIUM] Anomaly detector's z-score includes the very sample it's scoring — fixed post-audit

**File:** `src/detectors/anomaly.py`, `process()` (lines ~139–171)

```python
profile.size_stats.update(pkt_len)      # sample folded into mean/std FIRST
profile.iat_stats.update(iat)
...
n = profile.size_stats.n
if n < self._min_samples:
    return
size_z = profile.size_stats.z_score(pkt_len)   # then scored against updated stats
```

`update()` is called before `z_score()` for the *same* packet, so every packet contributes to its own baseline before being judged against it. This "self-masking" effect systematically shrinks the z-score of genuine outliers, most noticeably right after baseline completion where one new point measurably shifts the running mean/variance. It's not a crash-level bug, and Welford's algorithm itself (`_RunningStats`) is implemented correctly — the issue is purely the *ordering* of update-then-score versus score-then-update.

**Recommendation:** Compute `z_score()` against the pre-update statistics, then call `update()` — or keep a periodically-refreshed frozen baseline snapshot rather than updating every packet before scoring it.

**Remediation:** `AnomalyDetector.process()` now computes z-scores against the pre-update profile and updates stats afterward. `_RunningStats.z_score()` also treats a different value against a zero-variance established baseline as `inf`, preserving sensitivity for perfectly stable baselines.

### 3.3 [MEDIUM] Dashboard alert sorting doesn't respect severity rank — fixed post-audit

**File:** `dashboard/app.py`, `api_alerts()` (lines 129–138)

```python
if sort in {"timestamp", "severity", "detector", "src_ip", "dst_ip", "protocol"}:
    filtered.sort(key=lambda a: getattr(a, sort) or "", reverse=reverse)
```

When `sort=severity`, this sorts the raw strings alphabetically — `CRITICAL, HIGH, LOW, MEDIUM` — not by actual urgency. `dashboard/api/models.py` already defines a correct `severity_rank()` helper and `metrics_service.py` uses it properly elsewhere (e.g. `top_talkers()`'s `highest_severity` computation); it just isn't wired into this endpoint. A user sorting "by severity, descending" in the UI will see HIGH-severity alerts before CRITICAL ones.

**Recommendation:** `key=lambda a: severity_rank(a.severity) if sort == "severity" else getattr(a, sort) or ""`.

**Remediation:** `/api/alerts` now uses `severity_rank(a.severity)` when `sort=severity`.

### 3.4 [MEDIUM] Core engine, reporter, and PCAP writer still have 0% test coverage — partially closed post-audit

**Files:** `src/core/engine.py`, `src/reporting/reporter.py`, `src/capture/pcap_writer.py`

Coverage run (`pytest --cov=src --cov=dashboard --cov-report=term-missing`, 48 tests, all passing):

```text
Name                                    Stmts   Miss  Cover
------------------------------------------------------------
src/core/engine.py                        124    124    0%
src/reporting/reporter.py                 102    102    0%
src/capture/pcap_writer.py                 73     73    0%
dashboard/app.py                          238    133   44%
dashboard/services/report_service.py       30     18   40%
------------------------------------------------------------
TOTAL                                    1653    623   62%
```

This is the same set of files the *prior* audit called out (§3.6 above) — they weren't touched by the remediation pass that fixed `AnomalyDetector`'s coverage. The detector layer itself is now well tested (89–97% per file, including a dedicated concurrency stress test for the anomaly detector and a detector-isolation test verifying §3.3's fix), which is good — but the modules that wire the whole system together at runtime (signal handling, detector registration, interface resolution, the auto-report loop, PCAP rotation/cleanup, text/JSON/PNG report generation) remain completely unverified by automation. New dashboard code (`dashboard/app.py` at 44%, `report_service.py` at 40%) inherited the same gap rather than closing it.

**Recommendation:** Prioritize `Reporter.generate()` with 0/1/N alerts, `RotatingPcapWriter._cleanup_old_files()` retention logic, and `NIDSEngine._register_detectors()` config wiring — none of these require live packet capture (`sniff()` itself can stay mocked/untested).

**Remediation:** Added deterministic coverage for `Reporter.generate()` filename collision behavior, `RotatingPcapWriter._cleanup_old_files()` retention, and `NIDSEngine` detector registration/config wiring. Coverage now reports `engine.py` at 43%, `pcap_writer.py` at 47%, and `reporter.py` at 48%; live packet sniffing and chart rendering remain intentionally outside the unit suite.

### 3.5 [MEDIUM] Unbounded thread spawning for email/webhook alert delivery — fixed post-audit

**File:** `src/alerting/handler.py`, `dispatch()` (lines 56–67)

```python
threading.Thread(target=self._to_email, args=(alert, email_cfg), daemon=True).start()
...
threading.Thread(target=self._to_webhook, args=(alert, wh_cfg), daemon=True).start()
```

Every qualifying alert spawns a fresh OS thread for email and/or webhook delivery — no pool, queue, or concurrency cap. Under a real attack (exactly the condition this system exists to handle — e.g. a flood generating many per-source alerts across many IPs before per-source throttle windows catch up), this can spawn threads faster than a slow SMTP server or webhook endpoint can drain them, degrading the process precisely when it matters most.

**Recommendation:** Route `_to_email`/`_to_webhook` through a bounded `ThreadPoolExecutor` or small work queue with a max-inflight cap.

**Remediation:** Email and webhook notifications are now submitted through a bounded `ThreadPoolExecutor` guarded by a bounded semaphore. Excess async notification work is dropped with a warning instead of spawning unlimited OS threads.

### 3.6 [LOW] Docker build disables APT repository freshness/signature-date validation *(carried over, fixed post-audit)*

**File:** `Dockerfile`, both build and runtime stages

```dockerfile
RUN echo "Acquire::Check-Valid-Until \"false\";\nAcquire::Check-Date \"false\";" > /etc/apt/apt.conf.d/10no-check-valid-until
```

Restating the prior audit's §3.11, unchanged: this disables apt's validation that repository metadata hasn't expired or been backdated, in both stages. The comment frames it as a clock-skew workaround, which is a legitimate CI problem, but it also removes a defense against a compromised/misconfigured mirror serving stale, known-vulnerable package metadata during the build. If it's genuinely CI-only, scope it there rather than in the shipped Dockerfile; if it's not needed anymore, removing it costs nothing.

**Remediation:** Removed the APT freshness/date validation bypass from both Docker stages.

### 3.7 [LOW] Three near-duplicate flood detector classes *(carried over, still unfixed)*

**File:** `src/detectors/flood_detectors.py`, all three classes

Restating the prior audit's §3.10, unchanged: `SynFloodDetector`, `UdpFloodDetector`, and `IcmpFloodDetector` remain identical except for the layer check and log message prefix. Still a maintainability note rather than a bug — any future fix to the shared rate/throttle/severity-escalation logic needs applying three times, and the current test suite reflects this (each has its own near-duplicate test class).

### 3.8 [LOW] Severity strings from config aren't validated before enum lookup — fixed post-audit

**File:** `src/alerting/handler.py`

```python
self._min_severity = Severity[cfg.get("severity_filter", "LOW")]
...
severity_gte(alert.severity, Severity[email_cfg.get("min_severity", "HIGH")])
```

`Severity[...]` does an exact-name dict-style lookup. A config typo like `severity_filter: "low"` (lowercase) or `"medim"` raises an uncaught `KeyError` — for the handler-level filter, at startup in `AlertHandler.__init__`; for the email/webhook filters, on the *first alert dispatched*, which is a worse time to discover the typo. `config_loader.py` otherwise validates gracefully via deep-merge defaults but doesn't check enum-like string fields.

**Recommendation:** Normalize with `.upper()` and validate against `Severity.__members__` at config-load time with a clear error message.

**Remediation:** `load_config()` now normalizes and validates alerting severity fields with clear `ValueError` messages. `AlertHandler` also defensively normalizes severity values and falls back to safe defaults for channel-level filters.

### 3.9 [LOW] `main.py` mutates `Config._data` directly instead of using a public API — fixed post-audit

**File:** `main.py`, lines 157, 159

```python
cfg._data["logging"]["level"] = args.log_level
cfg._data["alerting"]["console"]["colorize"] = False
```

`Config` (`config_loader.py`) exposes `.get()` and attribute-style section access but no public setter, so CLI overrides reach past the underscore-prefixed private attribute. Works today only because default-merging guarantees those keys always exist — a leaky abstraction that would silently `KeyError` under a config-schema refactor.

**Recommendation:** Add `Config.set(*keys, value)` or an `override()` method and use that from `main.py`.

**Remediation:** Added `Config.set(*keys, value=...)` and updated CLI overrides in `main.py` to use the public setter.

### 3.10 [LOW] Report/visualisation filenames collide at second resolution — fixed post-audit

**File:** `src/reporting/reporter.py`

```python
fname = self._report_dir / f"report_{time.strftime('%Y%m%d_%H%M%S')}.txt"
```

`Visualizer`'s PNG filenames use the same pattern. Fine under normal auto-report intervals (default 300s), but `main.py`'s `--report-only` mode or any rapid manual calls within the same second will silently overwrite the previous file. Easy fix — append a short uuid or use `time.time_ns()`.

**Remediation:** Text/JSON reports, visualisation PNGs, dashboard HTML reports, and rotating PCAP files now append `time.time_ns()` to generated filenames.

---

## 4. Things Done Well

- **All three highest-severity issues from the prior audit are genuinely fixed**, not just papered over — verified by reading the actual comparison logic, exception handling, and locking code, not by trusting a changelog line.
- **Concurrency design across the core is now solid throughout.** `SlidingWindow`/`SlidingWindowDict` are properly locked, `AnomalyDetector` now has correct dict-level *and* per-profile locking, and `PacketProcessor` isolates failures per-detector so one bad packet/detector can't blind the rest of the pipeline.
- **Welford's algorithm** in `anomaly.py` remains correctly implemented for numerically stable running mean/variance.
- **The dashboard rewrite fixed the one real security-shaped bug from the prior audit** (stored-XSS pattern) comprehensively — every interpolated field in `vision.js` now goes through `escapeHtml()`, and the new `report_service.py` HTML report generator uses Python's `html.escape()` equally consistently.
- **Path traversal is safe by default** on `/reports/<path:filename>` via Flask's `send_from_directory`.
- **Config resilience:** deep-merge-over-defaults means a sparse or partially broken `config.yaml` degrades gracefully rather than crashing.
- **Detector test coverage is strong and specifically closed the prior audit's biggest gap** — `AnomalyDetector` went from 0% to 90%, including a dedicated thread-safety stress test that would have caught the old `_profiles` race directly.
- **`docker-compose.yml`'s privilege split remains correct**: the sniffer service legitimately needs root + `NET_ADMIN`/`NET_RAW`, while the dashboard service explicitly runs as the unprivileged `viperuser`.

---

## 5. Remaining Recommendations After Remediation

1. **Consolidate the three flood detector classes** (§3.7) when there is appetite for a maintainability refactor. This is the only audit item still intentionally open.
2. **Continue growing runtime coverage** around `NIDSEngine.start()` shutdown behavior, PCAP write-loop rotation, and visual report rendering. The 0%-coverage gap is closed, but these integration paths still deserve broader tests.
3. **Consider rate limiting dashboard endpoints** if VIPER Vision will be exposed through a reverse proxy to multiple operators. Auth now gates access, but request throttling remains a useful deployment hardening layer.

---

*This audit reflects a point-in-time review of commit `967b1c8`, cross-verified against the findings of the prior audit at commit `370ef98`. Every "fixed" determination in §2 was confirmed by reading the current implementation directly, not inferred from commit messages or documentation.*
