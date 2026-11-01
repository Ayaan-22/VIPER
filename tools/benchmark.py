"""Small, offline index/API benchmark; not a live-capture throughput claim."""
import json
from pathlib import Path
import statistics
import sys
import tempfile
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dashboard.app import create_app


def main():
    with tempfile.TemporaryDirectory() as folder:
        log = Path(folder) / "nids.log"
        with log.open("w", encoding="utf-8") as stream:
            for index in range(10000):
                stream.write(json.dumps({"message": "alert", "ts": 1700000000 + index,
                                          "alert_id": str(index), "severity": "HIGH", "detector": "port_scan",
                                          "src_ip": "192.0.2.1", "dst_ip": "198.51.100.1",
                                          "sample_ports": [22, 80, 443]}) + "\n")
        app = create_app(log_path=str(log), api_key="benchmark-only")
        store = app.extensions["viper_store"]
        try:
            started = time.perf_counter()
            while True:
                store.sync(force=True)
                if not store.health["catching_up"]:
                    break
            ingestion = time.perf_counter() - started
            timings = []
            with app.test_client() as client:
                for _ in range(20):
                    started = time.perf_counter()
                    response = client.get("/api/snapshot?minutes=10080", headers={"X-VIPER-API-Key": "benchmark-only"})
                    assert response.status_code == 200
                    assert response.get_json()["alerts"]["total"] == 10000
                    timings.append((time.perf_counter() - started) * 1000)
            print(json.dumps({"fixture_alerts": 10000, "index_ingest_seconds": round(ingestion, 3),
                              "snapshot_requests": len(timings), "median_snapshot_ms": round(statistics.median(timings), 2),
                              "max_snapshot_ms": round(max(timings), 2),
                              "index_health": store.health, "scope": "offline local Flask client; no HTTP/capture throughput tested"}, indent=2))
        finally:
            store.close()


if __name__ == "__main__":
    main()
