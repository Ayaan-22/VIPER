"use strict";
const $ = (selector) => document.querySelector(selector);
const escapeHtml = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[char]));
const num = (value) => Number.isFinite(Number(value)) ? Number(value) : 0;
const fmt = (value) => value === null || value === undefined ? "Unknown" : new Intl.NumberFormat().format(num(value));
const timeText = (value) => value ? new Date(num(value) * 1000).toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "Not observed";
const shortTime = (value) => value ? new Date(num(value) * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "—";
const colors = { CRITICAL: "var(--red)", HIGH: "var(--amber)", MEDIUM: "var(--blue)", LOW: "var(--faint)" };
const routes = {
  "/": ["Network overview", "A clear view of your traffic, detection signals, and sensor health.", "SECURITY OPERATIONS"],
  "/alerts": ["Alert inbox", "Triage detection signals and inspect the evidence behind each alert.", "DETECTION & RESPONSE"],
  "/packets": ["Traffic & sensor health", "Measured processing counters, packet rates, and evidence completeness.", "SENSOR TELEMETRY"],
  "/talkers": ["Sources & targets", "Rank alerting hosts and targeted services within the selected range.", "NETWORK INVESTIGATION"],
  "/protocols": ["Protocol analytics", "Separate measured traffic counters from alert distributions.", "TRAFFIC INTELLIGENCE"],
  "/port-scans": ["Scan activity", "Investigate observed multi-port probes and service sweeps.", "NETWORK INVESTIGATION"],
  "/connections": ["Connection groups", "Related alerts grouped by source, target, detector, and time window.", "NETWORK INVESTIGATION"],
  "/timeline": ["Event timeline", "Follow detection signals in order and identify severity changes.", "EVENT RECONSTRUCTION"],
  "/reports": ["Security reports", "Generate and download portable summaries for your investigations.", "EVIDENCE & REPORTING"],
  "/captures": ["Packet captures", "Download retained PCAP evidence for authorized offline investigation.", "EVIDENCE & REPORTING"],
  "/settings": ["Workspace settings", "Tune the monitoring workspace to fit your investigation workflow.", "WORKSPACE"],
  "/about": ["About VIPER Vision", "Understand this sensor's detection coverage and evidence model.", "WORKSPACE"],
};
const paths = {
  overview: '<rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>',
  alerts: '<path d="M12 3 2 20h20L12 3Z"/><path d="M12 9v5m0 3h.01"/>',
  activity: '<path d="M2 12h4l3-8 6 16 3-8h4"/>',
  layers: '<path d="m12 3 10 5-10 5L2 8l10-5Zm-10 9 10 5 10-5M2 16l10 5 10-5"/>',
  network: '<rect x="9" y="2" width="6" height="6" rx="1"/><rect x="2" y="16" width="6" height="6" rx="1"/><rect x="16" y="16" width="6" height="6" rx="1"/><path d="M12 8v4M5 16v-4h14v4"/>',
  scan: '<path d="M8 3H3v5m13-5h5v5M3 16v5h5m13-5v5h-5M7 12h10M12 7v10"/>',
  connections: '<circle cx="5" cy="6" r="3"/><circle cx="19" cy="6" r="3"/><circle cx="12" cy="19" r="3"/><path d="m7 8 4 8m6-8-4 8"/>',
  timeline: '<path d="M6 3v18m0-14h14M6 17h14"/><circle cx="6" cy="7" r="2"/><circle cx="6" cy="17" r="2"/>',
  capture: '<path d="M4 3h12l4 4v14H4V3Zm11 0v5h5M8 12h8m-8 4h6"/>',
  report: '<path d="M5 3h14v18H5zM9 8h6m-6 4h6m-6 4h4"/>',
  settings: '<path d="m9 3-1 3-3 1-2 4 2 2v4l4 3 3-1 3 1 4-3v-4l2-2-2-4-3-1-1-3H9Z"/><circle cx="12" cy="12" r="3"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10h.01"/>',
  refresh: '<path d="M20 7V3l-3 3a8 8 0 1 0 2 11M20 3h-5"/>',
  pause: '<path d="M8 5v14m8-14v14"/>',
  play: '<path d="m8 4 12 8-12 8V4Z"/>',
  arrow: '<path d="M4 12h16m-6-6 6 6-6 6"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v5h16v-5"/>',
  search: '<circle cx="10" cy="10" r="6"/><path d="m15 15 6 6"/>',
  check: '<path d="m5 12 4 4L20 5"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l4 2"/>',
  shield: '<path d="m12 2 9 4v6c0 5-9 10-9 10S3 17 3 12V6l9-4Z"/><path d="m8 12 3 3 5-6"/>',
};
function icon(name) { return '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' + (paths[name] || paths.info) + "</svg>"; }
function hydrateIcons(root = document) { root.querySelectorAll("[data-icon]").forEach((element) => { if (element.matches("nav a")) element.insertAdjacentHTML("afterbegin", icon(element.dataset.icon)); else element.innerHTML = icon(element.dataset.icon); }); }
const state = { snapshot: null, extra: null, route: location.pathname in routes ? location.pathname : "/", paused: false,
  minutes: null, q: "", severity: "", protocol: "", detector: "", sort: "timestamp", offset: 0,
  timer: null, request: null, loaded: false, dirty: false, extraError: "", toastTimer: null, focusBeforeDrawer: null };
let searchTimer;

async function api(url, options = {}) {
  const response = await fetch(url, { credentials: "same-origin", ...options });
  if (!response.ok) {
    const error = await response.json().catch(() => null);
    throw new Error(error?.error || (response.status === 401 ? "Authentication required. Sign in with your dashboard credentials." : response.status + " " + response.statusText));
  }
  return response.json();
}
function query() {
  const params = new URLSearchParams();
  if (state.minutes) params.set("minutes", state.minutes);
  if (state.q) params.set("q", state.q);
  if (state.severity) params.set("severity", state.severity);
  else if (state.snapshot?.settings.severity_filters?.length < 4) params.set("severity", state.snapshot.settings.severity_filters.join(","));
  if (state.protocol) params.set("protocol", state.protocol);
  if (state.detector) params.set("detector", state.detector);
  params.set("offset", state.offset);
  params.set("sort", state.sort);
  return params;
}
function schedule() {
  clearTimeout(state.timer);
  if (!state.paused) state.timer = setTimeout(() => refresh(), (state.snapshot?.settings.refresh_interval_seconds || 5) * 1000);
}
async function refresh() {
  if (state.request) state.request.abort();
  const controller = new AbortController();
  state.request = controller;
  $("#refreshButton").disabled = true;
  try {
    const snapshot = await api("/api/snapshot?" + query(), { signal: controller.signal });
    if (state.request !== controller) return;
    state.snapshot = snapshot;
    if (!state.minutes) {
      state.minutes = String(snapshot.settings.default_time_range_minutes);
      if (![...$("#timeRange").options].some((option) => option.value === state.minutes)) $("#timeRange").add(new Option("Last " + state.minutes + " minutes", state.minutes));
      $("#timeRange").value = state.minutes;
    }
    state.loaded = true;
    applyTheme(snapshot.settings.theme);
    await loadExtra(controller.signal);
    if (state.request !== controller) return;
    updateChrome();
    const editing = document.activeElement?.closest("#view input, #view select");
    if (state.route === "/alerts" && editing && $("#alertResults")) {
      $("#alertResults").innerHTML = alertTable(snapshot.alerts.items);
    } else if (!(state.route === "/settings" && (state.dirty || editing)) && !editing) render();
  } catch (error) {
    if (error.name !== "AbortError") {
      $("#updateLabel").textContent = "Connection interrupted · displaying last successful snapshot";
      $("#updateDot").className = "status-dot error";
      if (!state.snapshot) $("#view").innerHTML = empty("Workspace unavailable", error.message, "refresh");
      else toast(error.message, true);
    }
  } finally {
    if (state.request === controller) {
      state.request = null;
      $("#refreshButton").disabled = false;
      schedule();
    }
  }
}
async function loadExtra(signal) {
  state.extraError = "";
  const endpoints = { "/port-scans": "/api/analytics/port-scans", "/connections": "/api/analytics/suspicious-connections",
    "/timeline": "/api/analytics/timeline", "/reports": "/api/reports", "/captures": "/api/captures" };
  if (!endpoints[state.route]) { state.extra = null; return; }
  try { state.extra = await api(endpoints[state.route] + "?" + query(), { signal }); }
  catch (error) { if (error.name === "AbortError") throw error; state.extraError = error.message; state.extra = []; }
}
function applyTheme(theme) {
  document.documentElement.dataset.theme = theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : theme || "dark";
}
function updateChrome() {
  const status = state.snapshot.status;
  $("#navAlertCount").textContent = fmt(state.snapshot.alerts.total);
  $("#modeLabel").textContent = status.demo ? "SIMULATED DATA" : status.mode === "live" ? "LIVE SENSOR" : "HISTORICAL DATA";
  $("#updateLabel").textContent = state.paused ? "Updates paused · manual refresh available" : status.demo ? "Demo workspace · all events are simulated" : status.engine_status === "running" ? "Receiving sensor telemetry" : status.engine_status === "waiting" ? "Waiting for sensor telemetry" : "Historical snapshot · sensor " + status.engine_status;
  $("#updateDot").className = "status-dot" + (status.demo || status.engine_status !== "running" || state.paused ? " warning" : "");
  $("#lastUpdated").textContent = "Updated " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  $("#sensorDot").className = "status-dot" + (status.demo || status.engine_status !== "running" ? " warning" : "");
  $("#sensorLabel").innerHTML = escapeHtml(status.demo ? "Demo sensor" : status.interface) + "<small>" + escapeHtml(status.demo ? "Simulated reference dataset" : "Sensor " + status.engine_status) + "</small>";
  $("#pauseLabel").textContent = state.paused ? "Resume" : "Pause";
  $("#pauseFeed [data-icon]").innerHTML = icon(state.paused ? "play" : "pause");
  const quality = status.data_quality || {};
  const notices = [];
  if (status.demo) notices.push("Demo environment. Traffic counters, alerts, and hosts shown here are simulated.");
  if (!status.demo && status.mode === "historical" && status.alerts_loaded) notices.push("Historical data. Alert ranges are anchored to the latest recorded event; traffic totals describe the latest sensor session.");
  if (quality.invalid_records) notices.push(fmt(quality.invalid_records) + " invalid records were skipped.");
  if (quality.pruned_records) notices.push(fmt(quality.pruned_records) + " records were removed by index retention.");
  if (quality.read_errors) notices.push(fmt(quality.read_errors) + " log read errors have been recorded.");
  if (quality.catching_up) notices.push("Indexing remaining log records. Counts may increase as ingestion catches up.");
  $("#dataNotice").hidden = !notices.length;
  $("#dataNotice").textContent = notices.join(" ");
}
function badge(value) {
  const safe = value in colors ? value : "LOW";
  return '<span class="badge ' + safe + '">' + safe + "</span>";
}
function panel(title, subtitle, content, action = "") {
  return '<section class="panel"><div class="panel-header"><div><h2>' + escapeHtml(title) + "</h2>" + (subtitle ? "<p>" + escapeHtml(subtitle) + "</p>" : "") + "</div>" + action + '</div><div class="panel-body">' + content + "</div></section>";
}
function routeLink(path, text) { return '<a class="link-button" data-route="' + path + '" href="' + path + '">' + escapeHtml(text) + icon("arrow") + "</a>"; }
function empty(title, description, action = "") {
  return '<div class="empty-state">' + icon("scan") + "<h3>" + escapeHtml(title) + "</h3><p>" + escapeHtml(description) + "</p>" + (action === "refresh" ? '<button class="button" data-action="refresh">Try again</button>' : "") + "</div>";
}
function sparkline(values) {
  if (values.length < 2) return "";
  const max = Math.max(...values.map(num), 1);
  return '<svg class="sparkline" viewBox="0 0 80 30" aria-hidden="true"><polyline fill="none" stroke="var(--accent)" stroke-width="1.4" points="' + values.map((value, index) => (index * 80 / (values.length - 1)).toFixed(1) + "," + (28 - num(value) / max * 24).toFixed(1)).join(" ") + '"/></svg>';
}
function cards() {
  const m = state.snapshot.metrics, summary = m.summary;
  const losses = num(summary.dropped_packets) + num(summary.capture_dropped) + num(summary.capture_errors) + num(summary.detector_errors) + num(summary.notification_losses);
  const critical = num(m.alerts_by_severity.CRITICAL), high = num(m.alerts_by_severity.HIGH);
  const definitions = [
    ["Packets processed", fmt(summary.processed_packets), "<strong>" + fmt(summary.packets_per_second) + " pkt/s</strong> · latest sensor session", "activity", (m.packet_rate_over_time || []).slice(-12).map((p) => p.packets_per_second)],
    ["Alerts in range", fmt(summary.alerts_generated), "<strong>" + fmt(critical + high) + " high & critical</strong> · selected range", "alerts", (m.alerts_over_time || []).slice(-12).map((p) => p.total)],
    ["Alerting sources", fmt(summary.active_sources), fmt(summary.active_destinations) + " observed target hosts", "network", []],
    ["Evidence loss & errors", summary.dropped_packets === null ? "Unknown" : fmt(losses), summary.dropped_packets === null ? "Waiting for sensor telemetry" : losses ? "<strong>Review sensor health</strong> · counters may overlap" : "<strong>No recorded loss</strong> · latest sensor session", "shield", []],
  ];
  return '<div class="metrics-grid">' + definitions.map(([label, value, sub, symbol, series], index) => '<section class="metric' + (index === 3 && losses ? " red" : "") + '"><div class="metric-top"><span>' + label + '</span><span class="metric-symbol">' + icon(symbol) + '</span></div><div class="metric-value">' + value + '</div><div class="metric-sub">' + sub + "</div>" + sparkline(series) + "</section>").join("") + "</div>";
}
function trafficChart() {
  const points = state.snapshot.metrics.packet_rate_over_time || [];
  if (points.length < 2) return empty("Waiting for rate samples", "At least two sensor heartbeat records are needed to calculate a measured packet rate.");
  const stride = Math.max(1, Math.ceil(points.length / 150));
  const data = points.filter((_, index) => index % stride === 0 || index === points.length - 1).slice(-150);
  const max = Math.max(...data.map((p) => num(p.packets_per_second)), 1);
  const coords = data.map((p, i) => [45 + i / (data.length - 1) * 605, 155 - num(p.packets_per_second) / max * 135]);
  const line = coords.map((p) => p.map((n) => n.toFixed(2)).join(",")).join(" ");
  const lines = [0, .25, .5, .75, 1].map((v) => '<line class="grid-line" x1="45" x2="650" y1="' + (155 - v * 135) + '" y2="' + (155 - v * 135) + '"/><text x="34" y="' + (159 - v * 135) + '" text-anchor="end">' + escapeHtml(new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 }).format(max * v)) + "</text>").join("");
  const labels = [0, .25, .5, .75, 1].map((v) => { const index = Math.round(v * (data.length - 1)); return '<text x="' + (45 + v * 605) + '" y="178" text-anchor="middle">' + escapeHtml(shortTime(data[index].timestamp)) + "</text>"; }).join("");
  return '<svg class="chart" viewBox="0 0 680 190" role="img" aria-label="Measured processed packets per second">' + lines + '<polygon class="area" points="45,155 ' + line + ' 650,155"/><polyline class="line" points="' + line + '"/>' + labels + "</svg>";
}
function trafficPanel() {
  const summary = state.snapshot.metrics.summary;
  return '<section class="panel"><div class="panel-header"><div><h2>Packet activity</h2><p>Measured processed traffic · sensor heartbeat samples</p></div><span class="pill">' + escapeHtml(state.snapshot.status.interface) + '</span></div><div class="panel-body"><div class="chart-summary"><strong>' + fmt(summary.packets_per_second) + "</strong><span>packets / second</span></div>" + trafficChart() + '</div><div class="chart-footer"><span class="legend"><i></i>Processed packets / second</span><span>Counter resets start a new session</span></div></section>';
}
function severityPanel() {
  const counts = state.snapshot.metrics.alerts_by_severity;
  const total = Object.values(counts).reduce((sum, value) => sum + num(value), 0);
  let start = 0;
  const gradient = Object.keys(colors).map((severity) => { const end = start + (total ? num(counts[severity]) / total * 100 : 0); const part = colors[severity] + " " + start + "% " + end + "%"; start = end; return part; }).join(",");
  return '<section class="panel"><div class="panel-header"><div><h2>Alert severity</h2><p>Detection signals in selected range</p></div>' + icon("alerts") + '</div><div class="donut-wrap"><div class="donut" style="background:' + (total ? "conic-gradient(" + gradient + ")" : "var(--line)") + '" role="img" aria-label="' + escapeHtml(Object.entries(counts).map(([key, value]) => key + " " + value).join(", ")) + '"><div class="donut-hole"><strong>' + fmt(total) + '</strong><small>total alerts</small></div></div><div class="severity-legend">' + Object.keys(colors).map((severity) => '<div><i class="legend-dot" style="background:' + colors[severity] + '"></i>' + severity.charAt(0) + severity.slice(1).toLowerCase() + "<b>" + fmt(counts[severity] || 0) + "</b></div>").join("") + '</div></div><div class="severity-note">Prioritize high-impact signals; validate against packet and host evidence.</div></section>';
}
function healthPanel() {
  const s = state.snapshot.metrics.summary, status = state.snapshot.status, latest = state.snapshot.metrics.latest_health || {};
  const stateLoss = Object.values(latest.detector_state || {}).reduce((sum, x) => sum + num(x.evicted_keys) + num(x.discarded_events) + num(x.throttle_evictions) + num(x.profile_evictions), 0);
  const values = [["Sensor status", status.demo ? "Simulated" : status.engine_status], ["Queue depth", fmt(s.queue_size)],
    ["Processing drops", fmt(s.dropped_packets)], ["Capture drops", fmt(s.capture_dropped)], ["Capture write errors", fmt(s.capture_errors)],
    ["Detector errors", fmt(s.detector_errors)], ["Notification losses", fmt(s.notification_losses)], ["State budget losses", fmt(stateLoss)]];
  return panel("Sensor health", "Completeness and operational status", '<div class="health-grid">' + values.map(([label, value]) => '<div class="health-row"><span>' + label + '</span><strong class="' + (value === "0" || value === "running" ? "ok" : "") + '">' + escapeHtml(value) + "</strong></div>").join("") + '</div><p class="health-note">Last heartbeat: ' + escapeHtml(timeText(s.last_seen)) + '. Loss and error counters can overlap; a zero counter does not establish network-wide capture coverage.</p>');
}
function alertTable(alerts, compact = false) {
  if (!alerts.length) return empty("No alerts in this range", "Try a wider time range or clear your filters. An empty inbox does not establish complete capture coverage.");
  return '<div class="table-wrap"><table><thead><tr><th>Severity</th><th>Detection signal</th><th>Source → target</th><th>Observed</th><th></th></tr></thead><tbody>' + alerts.map((a) => '<tr><td>' + badge(a.severity) + '</td><td><span class="primary-text">' + escapeHtml(a.title) + '</span><small>' + escapeHtml(a.protocol) + ' · ' + escapeHtml(a.detector.replaceAll("_", " ")) + '</small></td><td><span class="ip primary-text">' + escapeHtml(a.src_ip || "Unknown") + '</span><small class="mono">→ ' + escapeHtml(a.dst_ip || "Not recorded") + (a.dst_port ? ":" + num(a.dst_port) : "") + '</small></td><td>' + escapeHtml(timeText(a.timestamp)) + '</td><td><button class="row-button" data-alert="' + escapeHtml(a.alert_id) + '">Inspect ' + iconInlineArrow() + "</button></td></tr>").join("") + "</tbody></table></div>" + (compact ? "" : pagination());
}
function iconInlineArrow() { return "↗"; }
function pagination() {
  const count = state.snapshot.alerts.total, limit = state.snapshot.settings.max_alerts_displayed;
  return '<div class="table-footer"><span>' + (count ? fmt(state.offset + 1) + "–" + fmt(Math.min(state.offset + limit, count)) : "0") + " of " + fmt(count) + ' alerts</span><div><button class="button subtle" data-page="previous"' + (state.offset === 0 ? " disabled" : "") + '>Previous</button><button class="button subtle" data-page="next"' + (state.offset + limit >= count ? " disabled" : "") + ">Next</button></div></div>";
}
function talkerTable(rows) {
  if (!rows?.length) return empty("No alerting hosts recorded", "Host rankings use observed alert counts, not estimated traffic volumes.");
  return '<div class="table-wrap"><table><thead><tr><th>Host</th><th>Alerts</th><th>Highest severity</th><th>Last seen</th></tr></thead><tbody>' + rows.map((row, index) => '<tr><td><span class="rank">' + (index + 1) + '</span><span class="ip primary-text">' + escapeHtml(row.ip) + '</span><small>' + escapeHtml(row.classification) + '</small></td><td>' + fmt(row.alert_count) + "</td><td>" + badge(row.highest_severity) + "</td><td>" + escapeHtml(timeText(row.last_seen)) + "</td></tr>").join("") + "</tbody></table></div>";
}
function portTable() {
  const rows = state.snapshot.metrics.top_ports;
  if (!rows.length) return empty("No recorded port evidence", "Only ports actually recorded in alerts are included.");
  return '<div class="table-wrap"><table><thead><tr><th>Recorded port</th><th>Alerts mentioning port</th><th>Highest severity</th></tr></thead><tbody>' + rows.map((row) => '<tr><td class="mono primary-text">' + num(row.port) + "</td><td>" + fmt(row.alert_count) + "</td><td>" + badge(row.highest_severity) + "</td></tr>").join("") + "</tbody></table></div>";
}
function protocolPanel() {
  const rows = state.snapshot.metrics.protocols;
  const measured = rows.some((p) => p.packet_count !== null);
  return '<section class="panel"><div class="panel-header"><div><h2>Protocol distribution</h2><p>' + (measured ? "Measured counter changes · sampled interval up to " + num(state.snapshot.metrics.scope.protocol_window_seconds) + " seconds" : "Traffic counts unavailable · alert counts remain observable") + '</p></div><span class="pill">' + (measured ? "MEASURED" : "COUNTS UNKNOWN") + '</span></div><div class="panel-body">' + (measured ? "" : '<div class="notice">Two measured protocol snapshots are required. Packet shares remain unknown until available.</div>') + '<div class="table-wrap"><table><thead><tr><th>Protocol</th><th>Measured packets</th><th>Traffic share</th><th>Alerts in range</th></tr></thead><tbody>' + rows.map((row) => '<tr><td class="mono primary-text">' + escapeHtml(row.protocol) + "</td><td>" + fmt(row.packet_count) + '</td><td>' + (row.percentage === null ? "Unknown" : '<span class="mini-track"><span style="width:' + Math.max(0, Math.min(100, num(row.percentage))) + '%"></span></span>' + num(row.percentage).toFixed(1) + "%") + "</td><td>" + fmt(row.alert_count) + "</td></tr>").join("") + "</tbody></table></div></div></section>";
}
function overview() {
  return cards() + '<div class="grid grid-main">' + trafficPanel() + severityPanel() + '</div><div class="grid grid-main"><section class="panel"><div class="panel-header"><div><h2>Recent detection signals</h2><p>Newest alerts · selected range</p></div>' + routeLink("/alerts", "Open inbox") + '</div><div class="panel-body"></div>' + alertTable(state.snapshot.alerts.items.slice(0, 5), true) + "</section>" + healthPanel() + '</div><section class="panel"><div class="panel-header"><div><h2>Top alerting sources</h2><p>Ranked by observed alerts, not inferred packet volume</p></div>' + routeLink("/talkers", "All hosts") + '</div><div class="panel-body"></div>' + talkerTable(state.snapshot.metrics.top_sources.slice(0, 5)) + "</section>";
}
function alertsView() {
  const options = (values, current, all) => '<option value="">' + all + "</option>" + values.map((value) => '<option value="' + escapeHtml(value) + '"' + (value === current ? " selected" : "") + ">" + escapeHtml(value) + "</option>").join("");
  return '<section class="panel"><div class="toolbar"><div class="search-field">' + icon("search") + '<input id="alertSearch" aria-label="Search all indexed alerts" placeholder="Search hosts, detectors, or evidence…" value="' + escapeHtml(state.q) + '"></div><select id="severityFilter" aria-label="Filter by severity">' + options(Object.keys(colors), state.severity, "All severities") + '</select><select id="protocolFilter" aria-label="Filter by protocol">' + options(state.snapshot.metrics.protocols.map((row) => row.protocol), state.protocol, "All protocols") + '</select><select id="detectorFilter" aria-label="Filter by detector">' + options(["port_scan", "syn_flood", "udp_flood", "icmp_flood", "brute_force", "anomaly"], state.detector, "All detectors") + '</select><select id="sortFilter" aria-label="Sort alerts"><option value="timestamp"' + (state.sort === "timestamp" ? " selected" : "") + '>Newest first</option><option value="severity"' + (state.sort === "severity" ? " selected" : "") + '>Highest severity</option></select><button class="button subtle" data-action="clear-filters">Clear</button></div>' + '<div id="alertResults">' + alertTable(state.snapshot.alerts.items) + "</div></section>";
}
function scansView() {
  const rows = state.extra || [];
  if (!rows.length) return panel("Scan investigations", "Observed port probes and host sweeps", empty("No scan evidence in this range", "Only actual observed sample ports are shown. Port identities are never inferred from a count."));
  return '<div class="grid grid-half">' + rows.map((row) => panel(row.scan_type === "host_sweep" ? "Host sweep" : "Port scan", "Recorded episode · two-minute grouping", '<div class="scan-header"><h3>' + escapeHtml(row.source_ip) + ' → ' + escapeHtml(row.target_ip) + "</h3>" + badge(row.severity) + '</div><div class="scan-stats"><div><small>' + (row.scan_type === "host_sweep" ? "REPORTED UNIQUE TARGETS" : "REPORTED UNIQUE PORTS") + '</small><strong>' + fmt(row.scan_type === "host_sweep" ? row.unique_targets : row.unique_ports) + '</strong></div><div><small>THRESHOLD</small><strong>' + fmt(row.detection_threshold) + '</strong></div></div><div class="port-tags">' + (row.scan_type === "host_sweep" ? (row.sample_targets || []) : row.ports_touched).map((value) => "<span>" + escapeHtml(value) + "</span>").join("") + '</div><p class="health-note">Observed evidence samples only · ' + escapeHtml(timeText(row.first_seen)) + " – " + escapeHtml(timeText(row.last_seen)) + "</p>")).join("") + "</div>";
}
function connectionsView() {
  const rows = state.extra || [];
  if (!rows.length) return panel("Connection groups", "Related signals, not confirmed authentication outcomes", empty("No related connection signals", "Groups appear when matching source, destination, detector, and window evidence is present."));
  return '<section class="panel"><div class="table-wrap"><table><thead><tr><th>Source</th><th>Target</th><th>Detection</th><th>Alerts</th><th>Severity</th><th>Evidence</th></tr></thead><tbody>' + rows.map((row) => '<tr><td class="ip">' + escapeHtml(row.src_ip) + '</td><td class="ip">' + escapeHtml(row.dst_ip) + "</td><td>" + escapeHtml(row.detector) + "</td><td>" + fmt(row.alert_count) + "</td><td>" + badge(row.severity) + "</td><td>" + escapeHtml(row.evidence_summary) + "</td></tr>").join("") + "</tbody></table></div></section>";
}
function timelineView() {
  const rows = [...(state.extra || [])].reverse();
  if (!rows.length) return panel("Event chronology", "Detection events ordered by capture timestamp", empty("No events in this range", "Widen the time range to inspect earlier recorded signals."));
  return panel("Event chronology", "Most recent first · capture-time evidence", '<div class="timeline">' + rows.map((row) => '<article class="timeline-entry"><time>' + escapeHtml(timeText(row.timestamp)) + '</time><span class="timeline-marker"></span><div><h3>' + escapeHtml(row.event_type) + " " + badge(row.severity) + "</h3><p>" + escapeHtml(row.summary) + '</p><small class="mono">' + escapeHtml(row.src_ip || "Unknown") + " → " + escapeHtml(row.dst_ip || "Not recorded") + "</small></div></article>").join("") + "</div>");
}
function formatBytes(bytes) {
  const value = Math.max(0, num(bytes));
  const index = Math.min(4, Math.floor(Math.log(Math.max(value, 1)) / Math.log(1024)));
  return (value / Math.pow(1024, index)).toFixed(index ? 1 : 0) + " " + ["B", "KiB", "MiB", "GiB", "TiB"][index];
}
function filesView(kind) {
  const rows = state.extra || [], reports = kind === "reports";
  const header = '<div class="panel-header"><div><h2>' + (reports ? "Generated reports" : "Retained packet captures") + "</h2><p>" + (reports ? "Portable HTML and JSON summaries · downloads preserve original artifacts" : "PCAP exports · verify sensor health for known capture loss") + "</p></div>" + (reports ? '<button class="button primary" data-action="generate-report">' + icon("report") + "Generate report</button>" : "") + "</div>";
  const body = !rows.length ? empty(reports ? "No reports generated yet" : "No packet captures available", reports ? "Generate a report to preserve the current investigation range." : "Start an authorized sensor with PCAP export enabled. Captures must be mounted into the dashboard.") :
    '<div class="table-wrap"><table><thead><tr><th>Artifact</th><th>Size</th><th>Created / modified</th><th></th></tr></thead><tbody>' + rows.map((file) => '<tr><td><span class="file-name">' + icon(reports ? "report" : "capture") + '<span class="mono primary-text">' + escapeHtml(file.name) + "</span></span></td><td>" + formatBytes(file.size_bytes) + "</td><td>" + escapeHtml(timeText(file.modified)) + '</td><td><a class="button subtle" href="/' + kind + "/" + encodeURIComponent(file.name) + '" download>' + icon("download") + "Download</a></td></tr>").join("") + "</tbody></table></div>";
  return '<section class="panel">' + header + '<div class="panel-body"></div>' + body + "</section>";
}
function settingsView() {
  const s = state.snapshot.settings;
  const field = (name, label, help, min, max) => '<label class="form-field">' + label + '<input name="' + name + '" type="number" min="' + min + '" max="' + max + '" required value="' + num(s[name]) + '"><small>' + help + "</small></label>";
  return '<section class="panel"><form id="settingsForm"><div class="settings-layout"><div class="settings-intro"><h2>Monitoring preferences</h2><p>Apply changes to this dashboard workspace. Sensor detection thresholds are managed in the sensor configuration.</p></div><div><div class="form-grid">' +
    field("refresh_interval_seconds", "Refresh interval (seconds)", "Polling interval, from 1 to 300 seconds.", 1, 300) +
    field("max_alerts_displayed", "Alerts per page", "Server-side pagination, from 1 to 1,000.", 1, 1000) +
    field("default_time_range_minutes", "Default alert range (minutes)", "Applied when a workspace is opened.", 1, 10080) +
    field("chart_window_size", "Alert chart bucket (seconds)", "Time bucket used for alert analytics.", 1, 3600) +
    '<label class="form-field">Appearance<select name="theme">' + ["dark", "light", "system"].map((theme) => '<option value="' + theme + '"' + (s.theme === theme ? " selected" : "") + ">" + theme.charAt(0).toUpperCase() + theme.slice(1) + "</option>").join("") + '</select><small>Dark, light, or operating system preference.</small></label><div class="form-field"><span>Default severities</span><div class="checkbox-row">' + Object.keys(colors).map((severity) => '<label><input type="checkbox" name="severity" value="' + severity + '"' + (s.severity_filters.includes(severity) ? " checked" : "") + ">" + severity.charAt(0) + severity.slice(1).toLowerCase() + "</label>").join("") + '</div></div><label class="form-field wide">Log source<input name="log_file_path" value="' + escapeHtml(s.log_file_path) + '" required><small>Restricted to the configured allowed log directory. Changing source uses a separate event index.</small></label></div><div class="form-actions"><button class="button subtle" type="button" data-action="reset-settings">Discard changes</button><button class="button primary" type="submit">Save preferences</button></div></div></div></form></section>';
}
function aboutView() {
  return '<section class="panel"><div class="prose"><span class="pill success">VIPER VISION 2.0</span><h2 style="margin-top:16px">A workspace for defensible investigation.</h2><p>VIPER combines a passive packet sensor, bounded detection heuristics, indexed event history, and an evidence-focused dashboard. Its alerts are investigation signals that require validation.</p><h3>Detection coverage</h3><ul><li>IPv4 and IPv6 SYN, UDP, and ICMP volume heuristics.</li><li>Same-target multi-port probes and many-target service sweeps.</li><li>Repeated service connection attempts with SYN retransmission deduplication.</li><li>A bounded rolling statistical baseline for size and inter-arrival anomalies.</li></ul><h3>Evidence you can distinguish</h3><p>Packet totals and protocol shares come from measured sensor counters. Host rankings use alert counts. Unknown values remain unknown. Connection attempts do not establish failed authentication. Flood destination context identifies the packet crossing a per-source threshold.</p><h3>Operational boundaries</h3><p>A passive sensor sees traffic exposed to its selected interface. Encrypted application content, full stream reassembly, distributed correlation, and authentication outcomes require additional sources. Capture and processing loss are reported separately. Demo data is explicitly labeled.</p><h3>Deployment</h3><p>Use a configured API key and a TLS reverse proxy for shared access. Keep the sensor and dashboard storage persistent and follow the deployment and acceptance runbooks in the repository. Only capture traffic on networks you are authorized to monitor.</p></div></section>';
}
function render() {
  const [title, description, eyebrow] = routes[state.route];
  $("#pageTitle").textContent = title; $("#pageDescription").textContent = description; $("#pageEyebrow").textContent = eyebrow;
  document.title = title + " · VIPER Vision";
  document.querySelectorAll("nav a").forEach((link) => { const active = link.dataset.route === state.route; link.classList.toggle("active", active); if (active) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); });
  if (!state.snapshot) return;
  if (state.extraError) { $("#view").innerHTML = panel("Could not load this view", "", empty("Data unavailable", state.extraError, "refresh")); return; }
  const views = {
    "/": overview, "/alerts": alertsView,
    "/packets": () => cards() + '<div class="grid grid-main">' + trafficPanel() + healthPanel() + "</div>" + protocolPanel(),
    "/talkers": () => '<div class="grid grid-half">' + panel("Alerting sources", "Observed alerts in selected range", talkerTable(state.snapshot.metrics.top_sources)) + panel("Observed targets", "Destination context recorded in alerts", talkerTable(state.snapshot.metrics.top_destinations)) + "</div>" + panel("Targeted ports", "Observed samples only", portTable()),
    "/protocols": protocolPanel, "/port-scans": scansView, "/connections": connectionsView, "/timeline": timelineView,
    "/reports": () => filesView("reports"), "/captures": () => filesView("captures"), "/settings": settingsView, "/about": aboutView,
  };
  $("#view").innerHTML = views[state.route]();
}
function openAlert(id, trigger) {
  const alert = state.snapshot.alerts.items.find((a) => a.alert_id === id);
  if (!alert) return;
  state.focusBeforeDrawer = trigger;
  $("#drawerContent").innerHTML = badge(alert.severity) + '<h2 id="drawerTitle">' + escapeHtml(alert.title) + "</h2><p>" + escapeHtml(alert.description) + '</p><dl><dt>Source</dt><dd class="mono">' + escapeHtml(alert.src_ip) + '</dd><dt>Target</dt><dd class="mono">' + escapeHtml(alert.dst_ip || "Not recorded") + (alert.dst_port ? ":" + num(alert.dst_port) : "") + '</dd><dt>Protocol</dt><dd>' + escapeHtml(alert.protocol) + "</dd><dt>Observed at</dt><dd>" + escapeHtml(timeText(alert.timestamp)) + '</dd><dt>Alert ID</dt><dd class="mono">' + escapeHtml(alert.alert_id) + '</dd></dl><h3>Recommended investigation</h3><p>' + escapeHtml(alert.recommended_action || "Correlate this signal with packet captures and host logs before taking action.") + '</p><h3>Recorded evidence</h3><pre>' + escapeHtml(JSON.stringify(alert.evidence, null, 2)) + "</pre>";
  $("#detailDrawer").hidden = $("#drawerBackdrop").hidden = false;
  $(".shell").inert = true; $("#sidebar").inert = true;
  $("#closeDrawer").focus();
}
function syncNavigationAccessibility() { $("#sidebar").inert = matchMedia("(max-width: 700px)").matches && !$("#sidebar").classList.contains("open"); }
function closeDrawer() {
  const wasOpen = !$("#detailDrawer").hidden;
  $("#detailDrawer").hidden = $("#drawerBackdrop").hidden = true;
  $(".shell").inert = false; syncNavigationAccessibility();
  if (wasOpen) (state.focusBeforeDrawer?.isConnected ? state.focusBeforeDrawer : $("#view")).focus();
}
async function navigate(path, push = true) {
  if (!(path in routes)) path = "/";
  if (state.dirty && path !== "/settings" && !window.confirm("Discard unsaved workspace preferences?")) return;
  closeDrawer(); state.dirty = false; state.route = path; state.offset = 0; state.extra = null; state.extraError = "";
  if (push) history.pushState({}, "", path);
  $("#sidebar").classList.remove("open"); $("#menuToggle").setAttribute("aria-expanded", "false"); syncNavigationAccessibility();
  render(); await refresh();
}
function toast(message, error = false) {
  $("#toast").textContent = message; $("#toast").hidden = false; $("#toast").classList.toggle("error", error);
  clearTimeout(state.toastTimer); state.toastTimer = setTimeout(() => { $("#toast").hidden = true; }, 5000);
}
async function generateReport(button) {
  button.disabled = true;
  try { const result = await api("/api/reports/generate?" + query(), { method: "POST" }); toast("Report generated: " + result.name); await refresh(); }
  catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
}
document.addEventListener("click", (event) => {
  const link = event.target.closest("a[data-route]");
  if (link && !event.ctrlKey && !event.metaKey) { event.preventDefault(); navigate(link.dataset.route); return; }
  const alert = event.target.closest("[data-alert]");
  if (alert) { openAlert(alert.dataset.alert, alert); return; }
  const page = event.target.closest("[data-page]");
  if (page) { state.offset = Math.max(0, state.offset + (page.dataset.page === "next" ? 1 : -1) * state.snapshot.settings.max_alerts_displayed); refresh(); return; }
  const action = event.target.closest("[data-action]");
  if (!action) return;
  if (action.dataset.action === "refresh") refresh();
  if (action.dataset.action === "generate-report") generateReport(action);
  if (action.dataset.action === "reset-settings") { state.dirty = false; render(); }
  if (action.dataset.action === "clear-filters") { state.q = state.severity = state.protocol = state.detector = ""; state.offset = 0; render(); refresh(); }
});
$("#view").addEventListener("input", (event) => {
  if (event.target.closest("#settingsForm")) state.dirty = true;
  if (event.target.id === "alertSearch") {
    state.q = event.target.value; state.offset = 0; clearTimeout(searchTimer);
    searchTimer = setTimeout(() => refresh(), 300);
  }
});
$("#view").addEventListener("change", (event) => {
  if (event.target.closest("#settingsForm")) state.dirty = true;
  const key = { severityFilter: "severity", protocolFilter: "protocol", detectorFilter: "detector", sortFilter: "sort" }[event.target.id];
  if (key) { state[key] = event.target.value; state.offset = 0; event.target.blur(); refresh(); }
});
$("#view").addEventListener("submit", async (event) => {
  if (event.target.id !== "settingsForm") return;
  event.preventDefault();
  const form = event.target, data = new FormData(form), button = form.querySelector('[type="submit"]');
  const body = Object.fromEntries([...data.entries()].filter(([key]) => key !== "severity"));
  body.severity_filters = data.getAll("severity");
  button.disabled = true;
  try {
    const saved = await api("/api/settings", { method: "PATCH", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
    state.snapshot.settings = saved; state.dirty = false; state.minutes = null; state.offset = 0;
    toast("Workspace preferences saved"); await refresh();
  } catch (error) { toast(error.message, true); }
  finally { button.disabled = false; }
});
$("#refreshButton").addEventListener("click", () => refresh());
$("#pauseFeed").addEventListener("click", () => { state.paused = !state.paused; clearTimeout(state.timer); if (!state.paused) refresh(); if (state.snapshot) updateChrome(); });
$("#timeRange").addEventListener("change", (event) => { state.minutes = event.target.value; state.offset = 0; refresh(); });
$("#menuToggle").addEventListener("click", () => { const open = $("#sidebar").classList.toggle("open"); $("#menuToggle").setAttribute("aria-expanded", String(open)); syncNavigationAccessibility(); });
$("#closeDrawer").addEventListener("click", closeDrawer);
$("#drawerBackdrop").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (event) => {
  if ($("#detailDrawer").hidden) return;
  if (event.key === "Escape") closeDrawer();
  if (event.key === "Tab") {
    const controls = [...$("#detailDrawer").querySelectorAll("button,a,input,select,[tabindex]")];
    if (controls.length === 1) { event.preventDefault(); controls[0].focus(); }
  }
});
window.addEventListener("popstate", () => navigate(location.pathname, false));
window.addEventListener("beforeunload", (event) => { if (state.dirty) { event.preventDefault(); event.returnValue = ""; } });
setInterval(() => { $("#clock").textContent = new Date().toLocaleDateString([], { month: "short", day: "numeric" }) + " · " + new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }); }, 1000);
window.addEventListener("resize", syncNavigationAccessibility);
hydrateIcons(); syncNavigationAccessibility(); render(); refresh();

