"""
report_service.py
-----------------
HTML reporting for VIPER Vision analytics.
"""

from __future__ import annotations

import html
import json
import time
from pathlib import Path
from typing import Any, Dict, Sequence

from dashboard.api.models import AlertEvent
from dashboard.services.metrics_service import build_metrics, to_plain
from dashboard.services.suspicious_connection_service import group_suspicious_connections
from dashboard.services.timeline_service import build_timeline


def generate_html_report(
    alerts: Sequence[AlertEvent],
    packet_stats: Sequence[Dict[str, Any]],
    *,
    output_dir: str = "reports",
    mode: str = "historical",
) -> str:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    metrics = build_metrics(alerts, packet_stats, engine_status=mode)
    suspicious = group_suspicious_connections(alerts)[:10]
    timeline = build_timeline(alerts)[-15:]
    payload = to_plain(metrics)
    generated = time.strftime("%Y-%m-%d %H:%M:%S")
    filename = Path(output_dir) / f"viper_vision_{time.strftime('%Y%m%d_%H%M%S')}_{time.time_ns()}.html"
    html_text = _render(generated, payload, alerts[-25:], suspicious, timeline)
    filename.write_text(html_text, encoding="utf-8")

    json_name = filename.with_suffix(".json")
    json_name.write_text(
        json.dumps(
            {
                "generated_at": generated,
                "mode": mode,
                "metrics": payload,
                "recent_alerts": [a.to_dict() for a in alerts[-100:]],
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return str(filename)


def _render(generated: str, metrics: Dict[str, Any], alerts, suspicious, timeline) -> str:
    summary = metrics["summary"]
    severity = metrics["alerts_by_severity"]
    rows = "\n".join(
        f"<tr><td>{html.escape(a.title)}</td><td>{html.escape(a.severity)}</td><td>{html.escape(a.src_ip)}</td><td>{html.escape(a.description)}</td></tr>"
        for a in reversed(alerts)
    )
    group_rows = "\n".join(
        f"<tr><td>{html.escape(g.src_ip)}</td><td>{html.escape(g.dst_ip)}</td><td>{html.escape(g.detector)}</td><td>{g.alert_count}</td><td>{html.escape(g.severity)}</td></tr>"
        for g in suspicious
    )
    timeline_rows = "\n".join(
        f"<li><strong>{html.escape(e.severity)}</strong> {html.escape(e.event_type)} - {html.escape(e.summary)}</li>"
        for e in timeline
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>VIPER Vision Report</title>
<style>
body{{margin:0;background:#0b1020;color:#e7edf8;font-family:Segoe UI,Arial,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:40px 24px}}
h1,h2{{letter-spacing:.02em}} .muted{{color:#91a4bd}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px}}
.card{{background:#111a2e;border:1px solid #243553;border-radius:8px;padding:18px}}
.value{{font-size:28px;font-weight:800;color:#7dd3fc}}
table{{width:100%;border-collapse:collapse;margin-top:12px}}td,th{{padding:10px;border-bottom:1px solid #25364f;text-align:left}}th{{color:#91a4bd}}
li{{margin:8px 0}}
</style>
</head>
<body><main>
<p class="muted">Generated {html.escape(generated)}</p>
<h1>VIPER Vision Security Report</h1>
<section class="grid">
<div class="card"><div class="muted">Total packets</div><div class="value">{summary["total_packets"]}</div></div>
<div class="card"><div class="muted">Alerts</div><div class="value">{summary["alerts_generated"]}</div></div>
<div class="card"><div class="muted">Critical</div><div class="value">{severity.get("CRITICAL", 0)}</div></div>
<div class="card"><div class="muted">High</div><div class="value">{severity.get("HIGH", 0)}</div></div>
</section>
<h2>Executive Summary</h2>
<p>VIPER observed {summary["alerts_generated"]} alert(s), {summary["active_sources"]} source IP(s), and {summary["active_protocols"]} protocol family/families. Review high and critical sources first, then correlate with PCAP captures and host logs.</p>
<h2>Suspicious Connection Groups</h2><table><thead><tr><th>Source</th><th>Destination</th><th>Detector</th><th>Alerts</th><th>Severity</th></tr></thead><tbody>{group_rows}</tbody></table>
<h2>Recent Alerts</h2><table><thead><tr><th>Title</th><th>Severity</th><th>Source</th><th>Description</th></tr></thead><tbody>{rows}</tbody></table>
<h2>Attack Timeline</h2><ul>{timeline_rows}</ul>
<h2>Recommendations</h2>
<p>Confirm authorization for observed traffic, preserve the JSON log and related PCAP files, review exposed services, and apply rate limits or access controls for abusive sources.</p>
</main></body></html>"""
