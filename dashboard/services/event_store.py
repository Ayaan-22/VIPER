"""Rotation-aware incremental SQLite index shared by dashboard requests.

Positions and events commit together. Partial final lines are retried. The
bounded index survives restarts when a database path is supplied.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import asdict
from pathlib import Path
from dashboard.api.models import AlertEvent
from dashboard.services.log_parser import normalize_alert_record, _normalize_packet_stats


def _checkpoint(stream, offset):
    """Fingerprint both ends of the consumed region without rereading the log."""
    if not offset:
        return ""
    stream.seek(0)
    digest = hashlib.sha256(stream.read(min(offset, 64)))
    stream.seek(max(0, offset - 64))
    digest.update(stream.read(min(offset, 64)))
    return digest.hexdigest()


class EventStore:
    def __init__(self, log_path, database=":memory:", max_alerts=25000, max_stats=10000,
                 max_bytes=128 * 1024 * 1024):
        self.log_path = Path(log_path).resolve()
        self.max_alerts, self.max_stats = max_alerts, max_stats
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        if database != ":memory:":
            Path(database).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(database), check_same_thread=False)
        self.db.execute("PRAGMA auto_vacuum=INCREMENTAL")
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA busy_timeout=5000")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT, event_key TEXT UNIQUE,
                ts REAL NOT NULL, kind TEXT NOT NULL, payload TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS event_kind_ts ON events(kind, ts);
            CREATE TABLE IF NOT EXISTS files (identity TEXT PRIMARY KEY, offset INTEGER, skipping INTEGER);
            CREATE TABLE IF NOT EXISTS health (key TEXT PRIMARY KEY, value INTEGER);
        """)
        if "checkpoint" not in {row[1] for row in self.db.execute("PRAGMA table_info(files)")}:
            self.db.execute("ALTER TABLE files ADD COLUMN checkpoint TEXT NOT NULL DEFAULT ''")
            self.db.commit()
        self.revision = 0
        self._cache_revision = -1
        self._cache = ([], [])
        self._last_sync = 0.0
        self._health = dict(self.db.execute("SELECT key,value FROM health"))
        for key in ("invalid_records", "pruned_records", "read_errors", "pruned_alert_seq", "source_resets"):
            self._health.setdefault(key, 0)
        self._health["catching_up"] = False

    def sync(self, force=False):
        with self._lock:
            if not force and time.monotonic() - self._last_sync < 0.5:
                return
            self._last_sync = time.monotonic()
            base = self.log_path
            paths = [p for p in base.parent.glob(base.name + ".*") if p.suffix[1:].isdigit()]
            paths.append(base)
            try:
                paths = sorted((p for p in paths if p.is_file() and not p.is_symlink()), key=lambda p: p.stat().st_mtime)
            except OSError:
                self._health["read_errors"] += 1
                return
            budget, changed = 2 * 1024 * 1024, False
            self._health["catching_up"] = False
            with self.db:
                for path in paths:
                    try:
                        stat = path.stat()
                        identity = f"{stat.st_dev}:{stat.st_ino}"
                        row = self.db.execute("SELECT offset,skipping,checkpoint FROM files WHERE identity=?", (identity,)).fetchone()
                        offset, skipping, checkpoint = row if row else (0, 0, "")
                        if stat.st_size < offset:
                            offset, skipping = 0, 0
                            self._health["source_resets"] += 1
                            changed = True
                        with path.open("rb") as stream:
                            if offset and checkpoint:
                                actual = _checkpoint(stream, offset)
                                if actual != checkpoint:
                                    offset, skipping = 0, 0
                                    self._health["source_resets"] += 1
                                    changed = True
                            if stat.st_size <= offset and checkpoint:
                                continue
                            stream.seek(offset)
                            while budget > 0:
                                line = stream.readline(65537)
                                if not line:
                                    break
                                if not line.endswith(b"\n") and len(line) <= 65536 and not skipping:
                                    break
                                offset = stream.tell()
                                budget -= len(line)
                                if skipping or len(line) > 65536:
                                    if not skipping:
                                        self._health["invalid_records"] += 1
                                    skipping = int(not line.endswith(b"\n"))
                                    changed = True
                                    continue
                                try:
                                    record = json.loads(line)
                                    if not isinstance(record, dict):
                                        raise ValueError("record must be an object")
                                    if record.get("message") == "packet_stats":
                                        payload = _normalize_packet_stats(record)
                                        kind = "stats"
                                        event_key = "stats:" + hashlib.sha256(line).hexdigest()
                                    elif record.get("alert_id"):
                                        payload = asdict(normalize_alert_record(record))
                                        kind = "alert"
                                        event_key = "alert:" + str(record.get("session_id", "")) + ":" + payload["alert_id"]
                                    else:
                                        continue
                                    self.db.execute("INSERT OR IGNORE INTO events(event_key,ts,kind,payload) VALUES(?,?,?,?)",
                                                    (event_key, payload.get("timestamp", 0), kind,
                                                     json.dumps(payload, allow_nan=False)))
                                    changed = True
                                except (ValueError, TypeError, OverflowError, RecursionError, AttributeError):
                                    self._health["invalid_records"] += 1
                                    changed = True
                            checkpoint = _checkpoint(stream, offset)
                        self.db.execute("INSERT OR REPLACE INTO files(identity,offset,skipping,checkpoint) VALUES(?,?,?,?)",
                                        (identity, offset, skipping, checkpoint))
                        if offset < stat.st_size:
                            self._health["catching_up"] = True
                    except OSError:
                        self._health["read_errors"] += 1
                        changed = True
                    if budget <= 0:
                        self._health["catching_up"] = True
                        break
                if changed:
                    for kind, limit in (("alert", self.max_alerts), ("stats", self.max_stats)):
                        if kind == "alert":
                            watermark = self.db.execute("SELECT max(seq) FROM events WHERE kind='alert' AND seq NOT IN "
                                "(SELECT seq FROM events WHERE kind='alert' ORDER BY seq DESC LIMIT ?)", (limit,)).fetchone()[0]
                            self._health["pruned_alert_seq"] = max(self._health["pruned_alert_seq"], watermark or 0)
                        cursor = self.db.execute("DELETE FROM events WHERE kind=? AND seq NOT IN "
                                                 "(SELECT seq FROM events WHERE kind=? ORDER BY seq DESC LIMIT ?)",
                                                 (kind, kind, limit))
                        self._health["pruned_records"] += cursor.rowcount
                    # Cap encoded data size as well as row counts. Each sync
                    # ingests at most 2 MiB, so transient overshoot is bounded.
                    total = self.db.execute("SELECT coalesce(sum(length(payload)),0) FROM events").fetchone()[0]
                    if total > self.max_bytes:
                        reclaim = total - self.max_bytes
                        removed, cutoff = 0, 0
                        for seq, size in self.db.execute("SELECT seq,length(payload) FROM events ORDER BY seq"):
                            removed += size
                            cutoff = seq
                            if removed >= reclaim:
                                break
                        watermark = self.db.execute("SELECT max(seq) FROM events WHERE kind='alert' AND seq<=?", (cutoff,)).fetchone()[0]
                        self._health["pruned_alert_seq"] = max(self._health["pruned_alert_seq"], watermark or 0)
                        deleted = self.db.execute("DELETE FROM events WHERE seq<=?", (cutoff,)).rowcount
                        self._health["pruned_records"] += deleted
                    self.db.execute("DELETE FROM files WHERE rowid NOT IN (SELECT rowid FROM files ORDER BY rowid DESC LIMIT 128)")
                    for key in ("invalid_records", "pruned_records", "read_errors", "pruned_alert_seq", "source_resets"):
                        self.db.execute("INSERT OR REPLACE INTO health VALUES(?,?)", (key, self._health[key]))
                    self.revision += 1
            if changed:
                self.db.execute("PRAGMA incremental_vacuum(128)")

    def snapshot(self):
        self.sync()
        with self._lock:
            if self._cache_revision != self.revision:
                alerts, stats = [], []
                for kind, payload in self.db.execute("SELECT kind,payload FROM events ORDER BY ts,seq"):
                    record = json.loads(payload)
                    (alerts if kind == "alert" else stats).append(AlertEvent(**record) if kind == "alert" else record)
                self._cache = alerts, stats
                self._cache_revision = self.revision
            return self._cache

    @property
    def health(self):
        with self._lock:
            return {**self._health, "revision": self.revision,
                    "retained_alerts": self.db.execute("SELECT count(*) FROM events WHERE kind='alert'").fetchone()[0]}

    def after(self, cursor=0, limit=1000):
        with self._lock:
            oldest = self.db.execute("SELECT min(seq) FROM events WHERE kind='alert'").fetchone()[0]
            newest = self.db.execute("SELECT max(seq) FROM events").fetchone()[0]
            gap = bool(cursor and (cursor < self._health["pruned_alert_seq"] or newest is None or cursor > newest))
            if newest is None or cursor > newest:
                cursor = 0
            rows = self.db.execute("SELECT seq,payload FROM events WHERE kind='alert' AND seq>? ORDER BY seq LIMIT ?",
                                   (cursor, limit)).fetchall()
            return [(seq, AlertEvent(**json.loads(payload)).to_dict()) for seq, payload in rows], gap

    def close(self):
        with self._lock:
            self.db.close()
