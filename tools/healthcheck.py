"""Exit nonzero for absent/stale/stopped sensor telemetry; no live capture."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import time


def sensor_health(path, max_age=35):
    try:
        with Path(path).open("rb") as stream:
            stream.seek(0, 2)
            end = stream.tell()
            stream.seek(max(0, end - 131072))
            lines = stream.read().splitlines()
        for line in reversed(lines):
            try:
                record = json.loads(line)
                if record.get("message") != "packet_stats":
                    continue
                stamp = record.get("ts", 0)
                if not isinstance(stamp, (int, float)):
                    from datetime import datetime
                    stamp = datetime.fromisoformat(stamp.replace("Z", "+00:00")).timestamp()
                freshness = max(max_age, float(record.get("heartbeat_interval", 10)) * 3)
                return record.get("sensor_running") is True and -5 <= time.time() - stamp <= freshness
            except (ValueError, TypeError, AttributeError):
                continue
    except OSError:
        return False
    return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--log", default="logs/nids.log")
    parser.add_argument("--max-age", type=float, default=35)
    args = parser.parse_args()
    sys.exit(0 if sensor_health(args.log, args.max_age) else 1)
