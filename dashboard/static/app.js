/**
 * Track C — Dashboard Frontend
 * Connects to the FastAPI WebSocket, updates Chart.js charts + UI panels live.
 */

"use strict";

// ── Chart colour palette ─────────────────────────────────────────────────────
const PALETTE = [
  "#3b82f6","#22c55e","#f59e0b","#ef4444","#a855f7",
  "#06b6d4","#ec4899","#84cc16","#f97316","#6366f1",
];

// ── Throughput history (last 30 s) ───────────────────────────────────────────
const THROUGHPUT_MAX_POINTS = 30;
const throughputData = {
  labels: Array.from({length: THROUGHPUT_MAX_POINTS}, (_, i) => `${i - THROUGHPUT_MAX_POINTS + 1}s`),
  values: new Array(THROUGHPUT_MAX_POINTS).fill(0),
};

// ── Chart instances ──────────────────────────────────────────────────────────
let throughputChart, appChart, blockedChart;

function initCharts() {
  // Throughput line chart
  throughputChart = new Chart(
    document.getElementById("throughput-chart").getContext("2d"),
    {
      type: "line",
      data: {
        labels: throughputData.labels,
        datasets: [{
          label: "Throughput (bps)",
          data: throughputData.values,
          borderColor: "#3b82f6",
          backgroundColor: "rgba(59,130,246,0.12)",
          borderWidth: 2,
          pointRadius: 0,
          tension: 0.35,
          fill: true,
        }],
      },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#64748b", maxTicksLimit: 6 }, grid: { color: "#1e293b" } },
          y: { ticks: { color: "#64748b" }, grid: { color: "#334155" }, beginAtZero: true },
        },
      },
    }
  );

  // App breakdown donut
  appChart = new Chart(
    document.getElementById("app-chart").getContext("2d"),
    {
      type: "doughnut",
      data: { labels: [], datasets: [{ data: [], backgroundColor: PALETTE, borderWidth: 0 }] },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: true,
        plugins: {
          legend: { position: "right", labels: { color: "#94a3b8", boxWidth: 12 } },
        },
      },
    }
  );

  // Blocked-by-reason bar chart
  blockedChart = new Chart(
    document.getElementById("blocked-chart").getContext("2d"),
    {
      type: "bar",
      data: { labels: [], datasets: [{ label: "Blocked", data: [], backgroundColor: "#ef4444", borderRadius: 4 }] },
      options: {
        animation: false,
        responsive: true,
        maintainAspectRatio: true,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: "#64748b" }, grid: { color: "#1e293b" } },
          y: { ticks: { color: "#64748b" }, grid: { color: "#334155" }, beginAtZero: true },
        },
      },
    }
  );
}

// ── Helper: format bytes ─────────────────────────────────────────────────────
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

// ── Update stat cards ────────────────────────────────────────────────────────
function updateStats(snap) {
  document.getElementById("s-packets").textContent   = snap.total_packets.toLocaleString();
  document.getElementById("s-bytes").textContent     = fmtBytes(snap.total_bytes);
  document.getElementById("s-throughput").textContent = fmtBps(snap.throughput_bps);
  document.getElementById("s-blocked").textContent   = snap.blocked_total.toLocaleString();
  document.getElementById("s-scans").textContent     = snap.scan_alerts;
  document.getElementById("s-floods").textContent    = snap.syn_flood_alerts;
  document.getElementById("s-tunnels").textContent   = snap.dns_tunnel_alerts;
}

// ── Update throughput chart ──────────────────────────────────────────────────
function updateThroughput(bps) {
  throughputData.values.push(bps);
  if (throughputData.values.length > THROUGHPUT_MAX_POINTS)
    throughputData.values.shift();
  throughputChart.data.datasets[0].data = [...throughputData.values];
  throughputChart.update("none");
}

// ── Update app breakdown donut ───────────────────────────────────────────────
function updateAppChart(breakdown) {
  const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]).slice(0, 10);
  appChart.data.labels = entries.map(e => e[0]);
  appChart.data.datasets[0].data = entries.map(e => e[1]);
  appChart.update("none");
}

// ── Update blocked-by-reason bar ─────────────────────────────────────────────
function updateBlockedChart(reasons) {
  const entries = Object.entries(reasons);
  blockedChart.data.labels = entries.map(e => e[0]);
  blockedChart.data.datasets[0].data = entries.map(e => e[1]);
  blockedChart.update("none");
}

// ── Top talkers panel ────────────────────────────────────────────────────────
function updateTopTalkers(breakdown) {
  const list = document.getElementById("talkers-list");
  const entries = Object.entries(breakdown).sort((a, b) => b[1] - a[1]).slice(0, 8);
  if (entries.length === 0) return;
  const total = entries.reduce((s, e) => s + e[1], 0) || 1;
  list.innerHTML = entries.map(([app, count]) => {
    const pct = ((count / total) * 100).toFixed(1);
    return `<li><span>${app}</span><span style="color:#60a5fa">${count.toLocaleString()} pkts (${pct}%)</span></li>`;
  }).join("");
}

// ── Security alert feed ───────────────────────────────────────────────────────
const MAX_ALERTS_DISPLAYED = 30;
const alertFeed = document.getElementById("alert-feed");
let alertCount = 0;

function appendAlert(event) {
  if (event.event !== "anomaly") return;

  alertCount++;
  // Remove placeholder
  if (alertCount === 1) alertFeed.innerHTML = "";
  // Trim old entries
  while (alertFeed.children.length >= MAX_ALERTS_DISPLAYED)
    alertFeed.removeChild(alertFeed.lastChild);

  const typeClass = ["PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"].includes(event.type)
    ? event.type : "OTHER";

  const ts = new Date(event.ts * 1000).toLocaleTimeString();
  const detail = event.detail ? JSON.stringify(event.detail) : "";
  const li = document.createElement("li");
  li.innerHTML = `
    <span class="badge ${typeClass}">${event.type}</span>
    <span style="color:#94a3b8">${ts}</span>
    <span style="color:#cbd5e1; word-break:break-all">${detail}</span>`;
  alertFeed.prepend(li);
}

// ── Master update function ────────────────────────────────────────────────────
function handleSnapshot(snap) {
  updateStats(snap);
  updateThroughput(snap.throughput_bps);
  updateAppChart(snap.app_breakdown);
  updateBlockedChart(snap.blocked_reasons);
  updateTopTalkers(snap.app_breakdown);
}

// ── WebSocket connection ──────────────────────────────────────────────────────
const statusDot  = document.getElementById("status-dot");
const statusText = document.getElementById("status-text");
let ws;

function connect() {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  ws = new WebSocket(`${proto}//${location.host}/ws`);

  ws.onopen = () => {
    statusDot.classList.add("live");
    statusText.textContent = "Live";
  };

  ws.onclose = () => {
    statusDot.classList.remove("live");
    statusText.textContent = "Reconnecting…";
    setTimeout(connect, 3000);   // auto-reconnect
  };

  ws.onerror = () => ws.close();

  ws.onmessage = (msg) => {
    try {
      const data = JSON.parse(msg.data);
      // Could be a stats snapshot OR an anomaly event
      if (data.event === "anomaly") {
        appendAlert(data);
      } else {
        handleSnapshot(data);
        // Also poll /api/events for alert feed (covers missed events)
      }
    } catch (_) {}
  };
}

// ── Periodic alert feed refresh (belt-and-suspenders) ────────────────────────
async function refreshAlerts() {
  try {
    const res  = await fetch("/api/events");
    const data = await res.json();
    data.slice(0, 5).forEach(appendAlert);
  } catch (_) {}
}

// ── Report export ────────────────────────────────────────────────────────────
function exportReport(format) {
  window.open(`/api/report?format=${format}`, "_blank");
}

// ── Bootstrap ────────────────────────────────────────────────────────────────
initCharts();
connect();
setInterval(refreshAlerts, 10_000);
