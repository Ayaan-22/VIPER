"""
dashboard/app.py
----------------
Optional lightweight Flask dashboard.
Run separately from the NIDS engine and point it at the JSON log file.

Usage:
    python dashboard/app.py --log logs/nids.log --port 5000

Then open http://localhost:5000 in a browser.
"""

from __future__ import annotations

import json
import os
import sys
import time
from collections import Counter, deque
from pathlib import Path

# ---------------------------------------------------------------------------
# Guard: only import Flask when the dashboard is actually used
# ---------------------------------------------------------------------------
try:
    from flask import Flask, jsonify, render_template_string
except ImportError:
    print("Flask is not installed. Run: pip install flask", file=sys.stderr)
    sys.exit(1)

app = Flask(__name__)

# In-memory alert store (populated by tailing the log file)
_alerts: deque = deque(maxlen=500)
_seen_alert_ids: set = set()
_log_path: str = "logs/nids.log"

# ---------------------------------------------------------------------------
# HTML template (single-file SPA, no external CDN dependency required)
# ---------------------------------------------------------------------------
_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>VIPER Dashboard</title>
<style>
  :root{--bg:#0f1117;--card:#1a1d2e;--accent:#e74c3c;--ok:#2ecc71;--warn:#f39c12;--info:#3498db;--txt:#ecf0f1;--sub:#95a5a6}
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--txt);font-family:'Segoe UI',Roboto,monospace;font-size:14px}
  header{display:flex;align-items:center;padding:1rem 2rem;background:var(--card);border-bottom:2px solid var(--accent)}
  header h1{font-size:1.3rem;letter-spacing:.05em}header span{margin-left:.5rem;font-size:.8rem;color:var(--sub)}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;padding:1.5rem 2rem}
  .card{background:var(--card);border-radius:8px;padding:1.2rem;border-left:4px solid var(--accent)}
  .card.ok{border-color:var(--ok)} .card.warn{border-color:var(--warn)} .card.info{border-color:var(--info)}
  .card h3{font-size:.75rem;color:var(--sub);text-transform:uppercase;letter-spacing:.08em}
  .card .val{font-size:2rem;font-weight:700;margin-top:.25rem}
  table{width:calc(100% - 4rem);margin:0 2rem 2rem;border-collapse:collapse}
  th{text-align:left;padding:.5rem 1rem;background:var(--card);font-size:.75rem;text-transform:uppercase;letter-spacing:.08em;color:var(--sub)}
  td{padding:.5rem 1rem;border-bottom:1px solid #1e2135;font-size:.82rem}
  tr:hover td{background:#1e2135}
  .CRITICAL{color:#c0392b;font-weight:bold} .HIGH{color:#e74c3c} .MEDIUM{color:#f39c12} .LOW{color:#27ae60}
  #refresh{display:block;text-align:right;padding:.5rem 2rem;color:var(--sub);font-size:.75rem}
</style>
</head>
<body>
<header>
  <h1>🛡 VIPER Dashboard</h1>
  <span id="ts">—</span>
</header>
<div class="grid" id="stats"></div>
<span id="refresh"></span>
<table>
  <thead><tr><th>Time</th><th>Severity</th><th>Detector</th><th>Source IP</th><th>Message</th></tr></thead>
  <tbody id="alerts"></tbody>
</table>
<script>
async function refresh(){
  const r=await fetch('/api/alerts');
  const d=await r.json();
  document.getElementById('ts').textContent=new Date().toLocaleTimeString();
  // Stats cards
  const sc=document.getElementById('stats');
  sc.innerHTML='';
  const cards=[
    {label:'Total Alerts',val:d.total,cls:''},
    {label:'Critical',val:d.by_severity.CRITICAL||0,cls:''},
    {label:'High',val:d.by_severity.HIGH||0,cls:'warn'},
    {label:'Medium',val:d.by_severity.MEDIUM||0,cls:'info'},
    {label:'Low',val:d.by_severity.LOW||0,cls:'ok'},
  ];
  cards.forEach(c=>{
    sc.innerHTML+=`<div class="card ${c.cls}"><h3>${c.label}</h3><div class="val">${c.val}</div></div>`;
  });
  // Alert table
  const tb=document.getElementById('alerts');
  tb.innerHTML='';
  d.alerts.slice().reverse().forEach(a=>{
    const ts=new Date(a.ts*1000).toLocaleTimeString();
    tb.innerHTML+=`<tr><td>${ts}</td><td class="${a.severity}">${a.severity}</td><td>${a.detector}</td><td>${a.src_ip}</td><td>${a.message}</td></tr>`;
  });
  document.getElementById('refresh').textContent='Auto-refresh in 5s | '+d.total+' alerts total';
}
refresh();setInterval(refresh,5000);
</script>
</body>
</html>
"""


# ---------------------------------------------------------------------------
# Log tail helper
# ---------------------------------------------------------------------------

def _tail_log(path: str, n: int = 200):
    """Read and parse the last n JSON log lines that contain alert data."""
    p = Path(path)
    if not p.exists():
        return
    with p.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()[-n:]
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if "alert_id" in obj:
            aid = obj["alert_id"]
            if aid not in _seen_alert_ids:
                _seen_alert_ids.add(aid)
                _alerts.append(obj)


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    return render_template_string(_HTML)


@app.route("/api/alerts")
def api_alerts():
    _tail_log(_log_path)
    by_sev = Counter(a.get("severity", "LOW") for a in _alerts)
    return jsonify({
        "total": len(_alerts),
        "by_severity": dict(by_sev),
        "alerts": list(_alerts)[-100:],
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="VIPER Web Dashboard")
    parser.add_argument("--log",  default="logs/nids.log", help="Path to NIDS JSON log")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()
    _log_path = args.log
    print(f"[*] Dashboard running at http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=False)
