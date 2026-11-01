"""Retention only touches report files owned by VIPER; unknown files are preserved."""
import threading
import time
from pathlib import Path

report_lock = threading.RLock()


def prune_reports(directory, max_files=500, max_bytes=512 * 1024 * 1024, max_age_days=30):
    with report_lock:
        files = sorted((p for p in Path(directory).iterdir()
                        if p.is_file() and not p.is_symlink()
                        and p.name.startswith(("report_", "viz_", "severity_", "viper_vision_"))
                        and p.suffix in {".json", ".txt", ".html", ".png"}),
                       key=lambda p: p.stat().st_mtime, reverse=True)
        used = 0
        cutoff = time.time() - max_age_days * 86400
        for index, path in enumerate(files):
            stat = path.stat()
            used += stat.st_size
            if index >= max_files or used > max_bytes or stat.st_mtime < cutoff:
                path.unlink(missing_ok=True)
