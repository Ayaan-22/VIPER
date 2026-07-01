const state = {
  metrics: null,
  alerts: [],
  timeline: [],
  portScans: [],
  connections: [],
  reports: [],
  captures: [],
  settings: null,
  paused: false,
};

const titles = {
  "/": "Dashboard Overview",
  "/alerts": "Live Alerts",
  "/packets": "Packet Summary",
  "/talkers": "Top Talkers",
  "/protocols": "Protocol Breakdown",
  "/port-scans": "Port Scan Visualizer",
  "/connections": "Suspicious Connections",
  "/timeline": "Attack Timeline",
  "/reports": "Reports",
  "/captures": "PCAP Captures",
  "/settings": "Settings",
  "/about": "About VIPER",
};

const $ = (selector) => document.querySelector(selector);
const fmt = new Intl.NumberFormat();

async function getJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

async function refreshData() {
  try {
    const [status, metrics, alerts, timeline, scans, connections, reports, captures, settings] = await Promise.all([
      getJson("/api/status"),
      getJson("/api/metrics/summary").then((summary) => getJsonBundle(summary)),
      getJson("/api/alerts?limit=500"),
      getJson("/api/analytics/timeline"),
      getJson("/api/analytics/port-scans"),
      getJson("/api/analytics/suspicious-connections"),
      getJson("/api/reports"),
      getJson("/api/captures"),
      getJson("/api/settings"),
    ]);
    $("#modeLabel").textContent = status.demo ? "Demo mode: simulated traffic" : "Historical mode: JSON log analytics";
    $("#engineStatus").textContent = status.engine_status;
    state.alerts = alerts.alerts || [];
    state.timeline = timeline;
    state.portScans = scans;
    state.connections = connections;
    state.reports = reports;
    state.captures = captures;
    state.settings = settings;
    render();
  } catch (error) {
    showToast(`Dashboard refresh failed: ${error.message}`);
  }
}

async function getJsonBundle(summary) {
  const [severity, detectors, sources, destinations, ports, protocols] = await Promise.all([
    getJson("/api/alerts/severity"),
    getJson("/api/alerts").then((data) => countBy(data.alerts || [], "detector")),
    getJson("/api/analytics/top-sources"),
    getJson("/api/analytics/top-destinations"),
    getJson("/api/analytics/top-ports"),
    getJson("/api/analytics/protocols"),
  ]);
  state.metrics = { summary, severity, detectors, sources, destinations, ports, protocols };
  return state.metrics;
}

function render() {
  const route = window.location.pathname in titles ? window.location.pathname : "/";
  $("#pageTitle").textContent = titles[route];
  document.querySelectorAll("nav a").forEach((link) => link.classList.toggle("active", link.dataset.route === route));
  const views = {
    "/": renderOverview,
    "/alerts": renderAlerts,
    "/packets": renderPackets,
    "/talkers": renderTalkers,
    "/protocols": renderProtocols,
    "/port-scans": renderPortScans,
    "/connections": renderConnections,
    "/timeline": renderTimeline,
    "/reports": renderReports,
    "/captures": renderCaptures,
    "/settings": renderSettings,
    "/about": renderAbout,
  };
  $("#view").innerHTML = views[route]();
  bindView(route);
}

function renderOverview() {
  const m = state.metrics || emptyMetrics();
  return `
    ${metricCards(m.summary)}
    <div class="grid two" style="margin-top:16px">
      <section class="panel"><h2>Alerts by Severity</h2>${bars(m.severity, severityColor)}</section>
      <section class="panel"><h2>Protocol Distribution</h2>${protocolBars(m.protocols)}</section>
      <section class="panel"><h2>Top Suspicious Sources</h2>${talkerTable(m.sources.slice(0, 6))}</section>
      <section class="panel"><h2>Attack Timeline Preview</h2>${timelineList(state.timeline.slice(-6).reverse())}</section>
    </div>`;
}

function renderAlerts() {
  return `
    <section class="panel">
      <div class="toolbar">
        <input id="alertSearch" placeholder="Search alerts">
        <select id="severityFilter"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option></select>
        <select id="protocolFilter"><option value="">All protocols</option><option>TCP</option><option>UDP</option><option>ICMP</option><option>DNS</option><option>HTTP</option><option>HTTPS</option></select>
        <button id="pauseFeed">${state.paused ? "Resume" : "Pause"} feed</button>
      </div>
      ${alertTable(state.alerts)}
    </section>`;
}

function renderPackets() {
  const s = (state.metrics || emptyMetrics()).summary;
  return `${metricCards(s)}
    <section class="panel" style="margin-top:16px">
      <h2>Packet Processing</h2>
      ${bars({
        Received: s.total_packets,
        Processed: s.processed_packets,
        Dropped: s.dropped_packets,
        Queued: s.queue_size,
      })}
    </section>`;
}

function renderTalkers() {
  const m = state.metrics || emptyMetrics();
  return `<div class="grid two">
    <section class="panel"><h2>Top Source IPs</h2>${talkerTable(m.sources)}</section>
    <section class="panel"><h2>Top Destination IPs</h2>${talkerTable(m.destinations)}</section>
    <section class="panel"><h2>Top Targeted Ports</h2>${portTable(m.ports)}</section>
    <section class="panel"><h2>Detector Analytics</h2>${bars(m.detectors)}</section>
  </div>`;
}

function renderProtocols() {
  const protocols = (state.metrics || emptyMetrics()).protocols;
  return `<div class="grid two">
    <section class="panel"><h2>Protocol Breakdown</h2>${protocolBars(protocols)}</section>
    <section class="panel"><h2>Protocol Details</h2>${protocolTable(protocols)}</section>
  </div>`;
}

function renderPortScans() {
  if (!state.portScans.length) return `<section class="empty">No port scan alerts found in the current dataset.</section>`;
  return `<div class="grid">${state.portScans.map((scan) => `
    <section class="panel">
      <h2>${escapeHtml(scan.source_ip)} probing ${escapeHtml(scan.target_ip)}</h2>
      <p class="muted">VIPER detected this because one source IP contacted many unique destination ports within the configured sliding window.</p>
      <div class="grid cards">
        ${smallMetric("Unique ports", scan.unique_ports)}
        ${smallMetric("Threshold", scan.detection_threshold)}
        ${smallMetric("Severity", badge(scan.severity))}
        ${smallMetric("Window", `${timeOnly(scan.first_seen)} - ${timeOnly(scan.last_seen)}`)}
      </div>
      <h3 style="margin-top:16px">Port heatmap</h3>
      <div class="bars">${scan.ports_touched.slice(0, 40).map((port) => `<span class="badge">${port}</span>`).join(" ") || "<span class='muted'>Ports not recorded in log metadata</span>"}</div>
    </section>`).join("")}</div>`;
}

function renderConnections() {
  if (!state.connections.length) return `<section class="empty">No suspicious connection groups found.</section>`;
  return `<section class="panel">${connectionTable(state.connections)}</section>`;
}

function renderTimeline() {
  return `<section class="panel"><h2>Attack Timeline</h2>${timelineList(state.timeline.slice().reverse())}</section>`;
}

function renderReports() {
  return `<section class="panel">
    <div class="toolbar"><button id="generateReport">Generate HTML report</button></div>
    ${fileTable(state.reports, "reports")}
  </section>`;
}

function renderCaptures() {
  return `<section class="panel"><h2>PCAP Captures</h2>${fileTable(state.captures, "captures")}</section>`;
}

function renderSettings() {
  const s = state.settings || {};
  return `<section class="panel">
    <div class="grid cards">
      ${settingInput("refresh_interval_seconds", "Refresh interval", s.refresh_interval_seconds)}
      ${settingInput("max_alerts_displayed", "Max alerts displayed", s.max_alerts_displayed)}
      ${settingInput("default_time_range_minutes", "Default time range", s.default_time_range_minutes)}
      ${settingInput("chart_window_size", "Chart window size", s.chart_window_size)}
    </div>
    <div class="toolbar" style="margin-top:16px"><input id="log_file_path" value="${escapeHtml(s.log_file_path || "")}" style="min-width:320px"><button id="saveSettings">Save settings</button></div>
  </section>`;
}

function renderAbout() {
  return `<section class="panel">
    <h2>VIPER Vision</h2>
    <p>VIPER Vision is a defensive Network Intrusion Detection and Visualization dashboard built on the existing VIPER Python engine. It visualizes alerts, packet statistics, protocol trends, suspicious connection groups, port scans, PCAP captures, and reports from authorized monitoring data.</p>
    <p class="muted">Use only on networks where you have explicit permission to monitor traffic.</p>
  </section>`;
}

function bindView(route) {
  if (route === "/alerts") {
    $("#pauseFeed").onclick = () => { state.paused = !state.paused; render(); };
    ["alertSearch", "severityFilter", "protocolFilter"].forEach((id) => {
      $(`#${id}`).addEventListener("input", filterAlertTable);
    });
  }
  if (route === "/reports") {
    $("#generateReport").onclick = async () => {
      const result = await getJson("/api/reports/generate", { method: "POST" });
      showToast(`Generated ${result.path}`);
      await refreshData();
    };
  }
  if (route === "/settings") {
    $("#saveSettings").onclick = saveSettings;
  }
}

function metricCards(s) {
  return `<div class="grid cards">
    ${smallMetric("Total packets", fmt.format(s.total_packets || 0), `${s.packets_per_second || 0} pkt/s`)}
    ${smallMetric("Alerts", fmt.format(s.alerts_generated || 0), "generated")}
    ${smallMetric("Sources", fmt.format(s.active_sources || 0), "active")}
    ${smallMetric("Destinations", fmt.format(s.active_destinations || 0), "active")}
    ${smallMetric("Protocols", fmt.format(s.active_protocols || 0), "observed")}
    ${smallMetric("Queue", fmt.format(s.queue_size || 0), `${s.dropped_packets || 0} dropped`)}
  </div>`;
}

function smallMetric(label, value, sub = "") {
  return `<div class="metric-card"><div class="metric-label">${label}</div><div class="metric-value">${value}</div>${sub ? `<div class="metric-sub">${sub}</div>` : ""}</div>`;
}

function bars(data, colorFn = () => "linear-gradient(90deg, var(--cyan), var(--green))") {
  const entries = Array.isArray(data) ? data : Object.entries(data || {}).map(([label, value]) => ({ label, value }));
  const max = Math.max(...entries.map((item) => Number(item.value || item.alert_count || item.packet_count || 0)), 1);
  return `<div class="bars">${entries.map((item) => {
    const label = item.label || item.protocol || item[0];
    const value = Number(item.value ?? item.alert_count ?? item.packet_count ?? item[1] ?? 0);
    return `<div class="bar-row"><span>${escapeHtml(label)}</span><span class="bar-track"><span class="bar-fill" style="width:${Math.max(2, value / max * 100)}%;background:${colorFn(label)}"></span></span><strong>${fmt.format(value)}</strong></div>`;
  }).join("")}</div>`;
}

function protocolBars(protocols) {
  return bars((protocols || []).filter((p) => p.packet_count || p.alert_count).map((p) => ({ label: p.protocol, value: p.packet_count || p.alert_count })));
}

function alertTable(alerts) {
  const rows = alerts.map((a) => `<tr data-severity="${a.severity}" data-protocol="${a.protocol}" data-search="${escapeHtml([a.title, a.description, a.detector, a.src_ip, a.dst_ip, a.protocol].join(" ").toLowerCase())}">
    <td>${timeOnly(a.timestamp)}</td><td>${badge(a.severity)}</td><td>${escapeHtml(a.detector)}</td><td>${escapeHtml(a.src_ip)}</td><td>${escapeHtml(a.dst_ip || "")}</td><td>${escapeHtml(a.protocol)}</td><td><strong>${escapeHtml(a.title)}</strong><br><span class="muted">${escapeHtml(a.description || "")}</span></td>
  </tr>`).join("");
  return `<div class="table-wrap"><table id="alertTable"><thead><tr><th>Time</th><th>Severity</th><th>Detector</th><th>Source</th><th>Destination</th><th>Protocol</th><th>Alert</th></tr></thead><tbody>${rows}</tbody></table></div>`;
}

function talkerTable(rows) {
  if (!rows.length) return `<div class="empty">No talker data yet.</div>`;
  return `<div class="table-wrap"><table><thead><tr><th>IP</th><th>Class</th><th>Alerts</th><th>Protocol</th><th>Severity</th><th>Last Seen</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${escapeHtml(r.ip)}</td><td>${escapeHtml(r.classification)}</td><td>${r.alert_count}</td><td>${escapeHtml(r.most_common_protocol)}</td><td>${badge(r.highest_severity)}</td><td>${timeOnly(r.last_seen)}</td></tr>`).join("")}</tbody></table></div>`;
}

function portTable(rows) {
  if (!rows.length) return `<div class="empty">No port data yet.</div>`;
  return `<div class="table-wrap"><table><thead><tr><th>Port</th><th>Alerts</th><th>Severity</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${r.port}</td><td>${r.alert_count}</td><td>${badge(r.highest_severity)}</td></tr>`).join("")}</tbody></table></div>`;
}

function protocolTable(rows) {
  return `<div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Packets</th><th>Alerts</th><th>Share</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${escapeHtml(r.protocol)}</td><td>${fmt.format(r.packet_count)}</td><td>${fmt.format(r.alert_count)}</td><td>${r.percentage}%</td></tr>`).join("")}</tbody></table></div>`;
}

function connectionTable(rows) {
  return `<div class="table-wrap"><table><thead><tr><th>Source</th><th>Destination</th><th>Detector</th><th>Alerts</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>${rows.map((r) => `<tr><td>${escapeHtml(r.src_ip)}</td><td>${escapeHtml(r.dst_ip)}</td><td>${escapeHtml(r.detector)}</td><td>${r.alert_count}</td><td>${badge(r.severity)}</td><td>${escapeHtml(r.evidence_summary)}</td></tr>`).join("")}</tbody></table></div>`;
}

function timelineList(items) {
  if (!items.length) return `<div class="empty">No timeline events yet.</div>`;
  return `<div class="timeline">${items.map((e) => `<article class="timeline-item"><strong>${badge(e.severity)} ${escapeHtml(e.event_type)}</strong><span>${escapeHtml(e.summary || "")}</span><br><small>${timeOnly(e.timestamp)} · ${escapeHtml(e.src_ip || "")} ${e.dst_ip ? "→ " + escapeHtml(e.dst_ip) : ""}</small></article>`).join("")}</div>`;
}

function fileTable(files, kind) {
  if (!files.length) return `<div class="empty">No ${kind} found.</div>`;
  return `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Path</th></tr></thead><tbody>${files.map((f) => `<tr><td>${escapeHtml(f.name)}</td><td>${formatBytes(f.size_bytes)}</td><td>${timeOnly(f.modified)}</td><td><span class="muted">${escapeHtml(f.path)}</span></td></tr>`).join("")}</tbody></table></div>`;
}

function settingInput(id, label, value) {
  return `<label class="metric-card"><span class="metric-label">${label}</span><input id="${id}" type="number" value="${Number(value || 1)}"></label>`;
}

async function saveSettings() {
  const body = {
    refresh_interval_seconds: $("#refresh_interval_seconds").value,
    max_alerts_displayed: $("#max_alerts_displayed").value,
    default_time_range_minutes: $("#default_time_range_minutes").value,
    chart_window_size: $("#chart_window_size").value,
    log_file_path: $("#log_file_path").value,
  };
  await getJson("/api/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  showToast("Settings saved");
  await refreshData();
}

function filterAlertTable() {
  const q = ($("#alertSearch").value || "").toLowerCase();
  const sev = $("#severityFilter").value;
  const protocol = $("#protocolFilter").value;
  document.querySelectorAll("#alertTable tbody tr").forEach((row) => {
    const ok = (!q || row.dataset.search.includes(q)) && (!sev || row.dataset.severity === sev) && (!protocol || row.dataset.protocol === protocol);
    row.style.display = ok ? "" : "none";
  });
}

function badge(value) { return `<span class="badge ${escapeHtml(value)}">${escapeHtml(value)}</span>`; }
function severityColor(label) {
  return { LOW: "var(--green)", MEDIUM: "var(--yellow)", HIGH: "#fb923c", CRITICAL: "var(--red)" }[label] || "var(--cyan)";
}
function timeOnly(seconds) {
  if (!seconds) return "";
  return new Date(seconds * 1000).toLocaleString();
}
function formatBytes(bytes) {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const index = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), units.length - 1);
  return `${(bytes / Math.pow(1024, index)).toFixed(index ? 1 : 0)} ${units[index]}`;
}
function countBy(rows, field) {
  return rows.reduce((acc, row) => {
    const key = row[field] || "unknown";
    acc[key] = (acc[key] || 0) + 1;
    return acc;
  }, {});
}
function emptyMetrics() {
  return { summary: {}, severity: {}, detectors: {}, sources: [], destinations: [], ports: [], protocols: [] };
}
function showToast(text) {
  const toast = $("#toast");
  toast.textContent = text;
  toast.hidden = false;
  setTimeout(() => toast.hidden = true, 3500);
}
function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
}

window.addEventListener("popstate", render);
document.addEventListener("click", (event) => {
  const link = event.target.closest("a[data-route]");
  if (!link) return;
  event.preventDefault();
  history.pushState({}, "", link.href);
  render();
});
setInterval(() => { $("#clock").textContent = new Date().toLocaleTimeString(); }, 1000);
setInterval(() => { if (!state.paused) refreshData(); }, 5000);
refreshData();

