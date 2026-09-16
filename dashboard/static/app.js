/**
 * Track C — Dashboard Frontend (Terminal Edition)
 * WebSocket client + Chart.js live updates styled for terminal aesthetic.
 */
"use strict";

// ── Chart theme ──────────────────────────────────────────────────────────────
const GREEN      = "#00ff41";
const GREEN_DIM  = "#00b32c";
const AMBER      = "#ffb300";
const RED        = "#ff3131";
const CYAN       = "#00e5ff";
const GRID_COLOR = "rgba(0,180,50,0.07)";
const TICK_COLOR = "#1a5c1a";

const APP_COLORS = [GREEN, AMBER, RED, CYAN, "#ff6600", "#cc00ff", "#00ffcc", "#ff0099", "#99ff00", "#ff9900"];

// ── Throughput ring buffer ───────────────────────────────────────────────────
const N = 30;
const tpLabels = Array.from({length: N}, (_, i) => i === N - 1 ? "now" : `${i - N + 1}s`);
const tpValues = new Array(N).fill(0);

// ── Uptime counter ───────────────────────────────────────────────────────────
let startTime = Date.now();
setInterval(() => {
  const s = Math.floor((Date.now() - startTime) / 1000);
  const h = String(Math.floor(s / 3600)).padStart(2, "0");
  const m = String(Math.floor((s % 3600) / 60)).padStart(2, "0");
  const sec = String(s % 60).padStart(2, "0");
  const el = document.getElementById("uptime-display");
  if (el) el.textContent = `UPTIME: ${h}:${m}:${sec}`;
}, 1000);

// ── Chart factory ────────────────────────────────────────────────────────────
function terminalDefaults(extra = {}) {
  return {
    responsive: true,
    maintainAspectRatio: true,
    animation: false,
    plugins: { legend: { display: false } },
    scales: {
      x: { ticks: { color: TICK_COLOR, font: { family: "Share Tech Mono, monospace", size: 10 }, maxTicksLimit: 6 },
           grid: { color: GRID_COLOR }, border: { color: GRID_COLOR } },
      y: { ticks: { color: TICK_COLOR, font: { family: "Share Tech Mono, monospace", size: 10 } },
           grid: { color: GRID_COLOR }, border: { color: GRID_COLOR }, beginAtZero: true },
    },
    ...extra,
  };
}

let throughputChart, appChart, blockedChart;

function initCharts() {
  // Throughput — green line
  throughputChart = new Chart(
    document.getElementById("throughput-chart").getContext("2d"),
    {
      type: "line",
      data: {
        labels: tpLabels,
        datasets: [{
          data: tpValues,
          borderColor: GREEN,
          backgroundColor: "rgba(0,255,65,0.06)",
          borderWidth: 1.5,
          pointRadius: 0,
          tension: 0.3,
          fill: true,
        }],
      },
      options: terminalDefaults(),
    }
  );

  // App breakdown — donut
  appChart = new Chart(
    document.getElementById("app-chart").getContext("2d"),
    {
      type: "doughnut",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: APP_COLORS,
          borderColor: "#040d04",
          borderWidth: 2,
        }],
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: true,
        cutout: "62%",
        plugins: {
          legend: {
            display: true,
            position: "right",
            labels: {
              color: TICK_COLOR,
              font: { family: "Share Tech Mono, monospace", size: 10 },
              boxWidth: 10,
              padding: 8,
            },
          },
        },
      },
    }
  );

  // Blocked by reason — bar
  blockedChart = new Chart(
    document.getElementById("blocked-chart").getContext("2d"),
    {
      type: "bar",
      data: {
        labels: [],
        datasets: [{
          data: [],
          backgroundColor: RED,
          borderColor: "#8b0000",
          borderWidth: 1,
          borderRadius: 0,
        }],
      },
      options: terminalDefaults({
        plugins: { legend: { display: false } },
      }),
    }
  );
}

// ── Format helpers ───────────────────────────────────────────────────────────
function fmtBytes(b) {
  if (b >= 1e9) return (b / 1e9).toFixed(2) + " GB";
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return b + " B";
}
function fmtBps(bps) {
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " Kbps";
  return Math.round(bps) + " bps";
}
function nowTs() {
  return new Date().toLocaleTimeString("en-GB", { hour12: false });
}

// ── Stat cards ───────────────────────────────────────────────────────────────
function updateStats(snap) {
  document.getElementById("s-packets").textContent    = snap.total_packets.toLocaleString();
  document.getElementById("s-bytes").textContent      = fmtBytes(snap.total_bytes);
  document.getElementById("s-throughput").textContent = fmtBps(snap.throughput_bps);
  document.getElementById("s-blocked").textContent    = snap.blocked_total.toLocaleString();
  document.getElementById("s-scans").textContent      = snap.scan_alerts;
  document.getElementById("s-floods").textContent     = snap.syn_flood_alerts;
  document.getElementById("s-tunnels").textContent    = snap.dns_tunnel_alerts;
}

// ── Throughput chart ─────────────────────────────────────────────────────────
function updateThroughput(bps) {
  tpValues.push(bps);
  if (tpValues.length > N) tpValues.shift();
  throughputChart.data.datasets[0].data = [...tpValues];
  throughputChart.update("none");
}

// ── App breakdown donut ──────────────────────────────────────────────────────
function updateAppChart(breakdown) {
  const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]).slice(0, 10);
  appChart.data.labels                    = entries.map(e => e[0]);
  appChart.data.datasets[0].data          = entries.map(e => e[1]);
  appChart.data.datasets[0].backgroundColor = APP_COLORS.slice(0, entries.length);
  appChart.update("none");
}

// ── Blocked bar ──────────────────────────────────────────────────────────────
function updateBlockedChart(reasons) {
  const entries = Object.entries(reasons);
  blockedChart.data.labels            = entries.map(e => e[0]);
  blockedChart.data.datasets[0].data  = entries.map(e => e[1]);
  blockedChart.update("none");
}

// ── Top talkers (htop-style bars) ────────────────────────────────────────────
function updateTopTalkers(breakdown) {
  const list = document.getElementById("talkers-list");
  const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const total = entries.reduce((s, e) => s + e[1], 0) || 1;

  document.getElementById("talker-count").textContent = `${entries.length} apps`;

  if (!entries.length) return;
  list.innerHTML = "";
  for (const [app, count] of entries) {
    const pct = ((count / total) * 100).toFixed(1);
    const li = document.createElement("li");

    const nameSpan = document.createElement("span");
    nameSpan.className = "talker-name";
    nameSpan.textContent = String(app);

    const trackDiv = document.createElement("div");
    trackDiv.className = "bar-track";
    const fillDiv = document.createElement("div");
    fillDiv.className = "bar-fill";
    fillDiv.style.width = `${pct}%`;
    trackDiv.appendChild(fillDiv);

    const pctSpan = document.createElement("span");
    pctSpan.className = "talker-pct";
    pctSpan.textContent = `${pct}%`;

    li.appendChild(nameSpan);
    li.appendChild(trackDiv);
    li.appendChild(pctSpan);
    list.appendChild(li);
  }
}

// ── Alert feed ───────────────────────────────────────────────────────────────
const alertFeed = document.getElementById("alert-feed");
let alertTotal = 0;
const seenEventKeys = new Set();

function getEventKey(event) {
  if (!event) return "";
  if (event.id != null) return `id_${event.id}`;
  return `${event.ts || ""}_${event.type || ""}_${JSON.stringify(event.detail || {})}`;
}

function appendAlert(event) {
  if (!event || event.event !== "anomaly") return;

  const eventKey = getEventKey(event);
  if (eventKey && seenEventKeys.has(eventKey)) return;
  if (eventKey) {
    seenEventKeys.add(eventKey);
    if (seenEventKeys.size > 1000) {
      const iter = seenEventKeys.values();
      for (let i = 0; i < 200; i++) seenEventKeys.delete(iter.next().value);
    }
  }

  alertTotal++;
  document.getElementById("alert-count").textContent = `${alertTotal} events`;

  if (alertTotal === 1) alertFeed.innerHTML = "";

  // trim
  while (alertFeed.children.length >= 40) alertFeed.removeChild(alertFeed.lastChild);

  const allowedTypes = ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"];
  const typeClass = allowedTypes.includes(event.type) ? event.type : "OTHER";
  const detail = event.detail
    ? Object.entries(event.detail).map(([k, v]) => `${k}=${v}`).join(" ")
    : "";

  const li = document.createElement("li");

  const tsSpan = document.createElement("span");
  tsSpan.className = "ts";
  tsSpan.textContent = nowTs();

  const badgeSpan = document.createElement("span");
  badgeSpan.className = `badge ${typeClass}`;
  badgeSpan.textContent = String(event.type || "UNKNOWN");

  const detailSpan = document.createElement("span");
  detailSpan.className = "alert-detail";
  detailSpan.textContent = detail;

  li.appendChild(tsSpan);
  li.appendChild(badgeSpan);
  li.appendChild(detailSpan);
  alertFeed.prepend(li);
}

// ── Master update ────────────────────────────────────────────────────────────
function handleSnapshot(snap) {
  updateStats(snap);
  updateThroughput(snap.throughput_bps);
  updateAppChart(snap.app_breakdown);
  updateBlockedChart(snap.blocked_reasons);
  updateTopTalkers(snap.app_breakdown);
}

// ── Clear alerts ─────────────────────────────────────────────────────────────
function clearAlerts() {
  alertFeed.innerHTML = "";
  const li = document.createElement("li");
  const tsSpan = document.createElement("span");
  tsSpan.className = "ts";
  tsSpan.textContent = nowTs();
  const detailSpan = document.createElement("span");
  detailSpan.className = "alert-detail";
  detailSpan.textContent = "Log cleared.";
  li.appendChild(tsSpan);
  li.appendChild(detailSpan);
  alertFeed.appendChild(li);

  alertTotal = 0;
  document.getElementById("alert-count").textContent = "0 events";
  showToast("LOG CLEARED");
}

// ── Toast ────────────────────────────────────────────────────────────────────
function showToast(msg) {
  const t = document.getElementById("toast");
  t.textContent = `> ${msg}`;
  t.classList.add("show");
  setTimeout(() => t.classList.remove("show"), 2500);
}

// ── Report export ────────────────────────────────────────────────────────────
function exportReport(format) {
  window.open(`/api/report?format=${format}`, "_blank");
  showToast(`GENERATING ${format.toUpperCase()} REPORT…`);
}

// ── WebSocket ────────────────────────────────────────────────────────────────
const statusDot  = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
let ws;

function connect() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    statusDot.classList.add("live");
    statusText.textContent = "LIVE";
    showToast("ENGINE CONNECTED — MONITORING ACTIVE");
  };

  ws.onclose = () => {
    statusDot.classList.remove("live");
    statusText.textContent = "RECONNECTING";
    setTimeout(connect, 3000);
  };

  ws.onerror = () => ws.close();

  ws.onmessage = ({ data }) => {
    try {
      const msg = JSON.parse(data);
      if (msg.event === "anomaly") appendAlert(msg);
      else handleSnapshot(msg);
    } catch(_) {}
  };
}

// ── Periodic event poll ──────────────────────────────────────────────────────
async function pollEvents() {
  try {
    const res = await fetch("/api/events");
    const events = await res.json();
    if (Array.isArray(events)) {
      for (const ev of events.slice().reverse()) {
        appendAlert(ev);
      }
    }
  } catch(_) {}
}

// ── Boot ─────────────────────────────────────────────────────────────────────
initCharts();
connect();
setInterval(pollEvents, 12000);
