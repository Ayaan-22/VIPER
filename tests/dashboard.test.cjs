// Pure rendering regressions. Browser workflows are validated separately.
const test = require("node:test");
const assert = require("node:assert/strict");
const vm = require("node:vm");
const fs = require("node:fs");
const path = require("node:path");

function runtime() {
  const source = fs.readFileSync(path.join(__dirname, "../dashboard/static/vision.js"), "utf8");
  const context = vm.createContext({ location: { pathname: "/" }, document: { querySelector() { return null; } },
    console, setTimeout, clearTimeout, URLSearchParams });
  vm.runInContext(source.split('document.addEventListener("click",')[0], context);
  return context;
}

test("all HTML delimiters are escaped", () => {
  const context = runtime();
  context.fixture = '<img \'x\'="y" &>';
  assert.equal(vm.runInContext("escapeHtml(fixture)", context),
    "&lt;img &#39;x&#39;=&quot;y&quot; &amp;&gt;");
});

test("alert data cannot break text or attribute boundaries", () => {
  const context = runtime();
  const alert = { alert_id: '" onmouseover="alert(1)', severity: 'HIGH" onfocus="alert(1)',
    title: "<img src=x onerror=alert(1)>", detector: "scan", src_ip: "<script>bad()</script>",
    dst_ip: "example", dst_port: 22, protocol: '" onmouseover="alert(1)', timestamp: 1000 };
  context.fixture = [alert];
  const html = vm.runInContext("alertTable(fixture, true)", context);
  assert.ok(html.includes("&lt;img"));
  assert.ok(html.includes('data-alert="&quot; onmouseover=&quot;alert(1)"'));
  assert.ok(!html.includes("<script>"));
  assert.ok(!html.includes("<img"));
  assert.ok(html.includes('class="badge LOW"'));
});

test("icon hydration preserves navigation labels and count elements", () => {
  const context = runtime();
  const nav = { dataset: { icon: "overview" }, innerHTML: "Overview <span>9</span>", matches: () => true,
    insertAdjacentHTML(where, value) { this.innerHTML = value + this.innerHTML; } };
  const placeholder = { dataset: { icon: "pause" }, innerHTML: "", matches: () => false };
  context.fixture = { querySelectorAll: () => [nav, placeholder] };
  vm.runInContext("hydrateIcons(fixture)", context);
  assert.ok(nav.innerHTML.endsWith("Overview <span>9</span>"));
  assert.ok(placeholder.innerHTML.startsWith("<svg"));
});

test("zero packet rate chart contains only finite SVG coordinates", () => {
  const context = runtime();
  vm.runInContext('state.snapshot = {metrics: {packet_rate_over_time: [{timestamp:1000,packets_per_second:0},{timestamp:1010,packets_per_second:0}]}}', context);
  const html = vm.runInContext("trafficChart()", context);
  assert.ok(html.includes("<svg"));
  assert.ok(!html.includes("NaN"));
  assert.ok(!html.includes("Infinity"));
});

test("unknown protocol counters stay unknown", () => {
  const context = runtime();
  vm.runInContext('state.snapshot = {metrics: {scope:{protocol_window_seconds:60}, protocols: [{protocol:"TCP",packet_count:null,percentage:null,alert_count:3}]}}', context);
  const html = vm.runInContext("protocolPanel()", context);
  assert.ok(html.includes("COUNTS UNKNOWN"));
  assert.ok(html.includes("Unknown"));
  assert.ok(!html.includes("100.0%"));
});

test("settings escape an imported log source value", () => {
  const context = runtime();
  context.fixture = {settings:{log_file_path:'a" onfocus="alert(1)',theme:"dark",severity_filters:[]}};
  vm.runInContext("state.snapshot = fixture", context);
  const html = vm.runInContext("settingsView()", context);
  assert.ok(html.includes('value="a&quot; onfocus=&quot;alert(1)"'));
});
