/**
 * Track C — Packet Analyzer Pro Frontend
 * Live WebSocket telemetry, alert feed, charts with smoothed Y-axis scaling,
 * D3 network topology map, and accessible dual-pane packet inspector.
 */
"use strict";

// ── Global State ─────────────────────────────────────────────────────────────
let isStreamPaused = false;
const MAX_CONN_ROWS = 200;
const MAX_ALERT_ITEMS = 100;
const TP_WINDOW = 30;

let connStore = [];
let alertStore = [];
const seenAlertKeys = new Set();

let selectedRow = null;
let lastPacketCount = 0;
let lastTime = Date.now();
let activeFilterText = "";
let activeAlertFilter = "ALL";
let ws = null;
let hasReceivedTraffic = false;

// Throughput chart state with damped Y-axis ceiling
const tpValues = new Array(TP_WINDOW).fill(0);
let tpHasNonZero = false;
let smoothedMaxBps = 1000;

// ── Escaping & Formatting Helpers ────────────────────────────────────────────
function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function fmtBytes(b) {
  b = Number(b) || 0;
  if (b >= 1e9) return (b / 1e9).toFixed(2) + " GB";
  if (b >= 1e6) return (b / 1e6).toFixed(2) + " MB";
  if (b >= 1e3) return (b / 1e3).toFixed(1) + " KB";
  return Math.round(b) + " B";
}

function fmtBps(bps) {
  bps = Number(bps) || 0;
  if (bps >= 1e6) return (bps / 1e6).toFixed(2) + " Mbps";
  if (bps >= 1e3) return (bps / 1e3).toFixed(1) + " Kbps";
  return Math.round(bps) + " bps";
}

function fmtTime(ts) {
  if (!ts) return "--:--:--.---";
  const d = new Date(ts < 1e12 ? ts * 1000 : ts);
  const hh = String(d.getHours()).padStart(2, "0");
  const mm = String(d.getMinutes()).padStart(2, "0");
  const ss = String(d.getSeconds()).padStart(2, "0");
  const ms = String(d.getMilliseconds()).padStart(3, "0");
  return `${hh}:${mm}:${ss}.${ms}`;
}

function niceCeil(val) {
  const v = Math.max(100, val);
  const exp = Math.floor(Math.log10(v));
  const base = Math.pow(10, exp);
  const frac = v / base;
  if (frac <= 1) return 1 * base;
  if (frac <= 2) return 2 * base;
  if (frac <= 5) return 5 * base;
  return 10 * base;
}

// ── Tooltip Helper ───────────────────────────────────────────────────────────
const tooltipEl = document.getElementById("chart-tooltip");
function showTooltip(evt, text) {
  if (!tooltipEl) return;
  tooltipEl.textContent = text;
  tooltipEl.style.display = "block";
  const x = Math.min(window.innerWidth - 220, evt.clientX + 12);
  const y = Math.max(8, evt.clientY - 28);
  tooltipEl.style.left = `${x}px`;
  tooltipEl.style.top = `${y}px`;
}
function hideTooltip() {
  if (tooltipEl) tooltipEl.style.display = "none";
}

// ── Normalize Connection / Event from Backend Contract ───────────────────────
function normalizeConn(c) {
  const ft = c.five_tuple || {};
  const detailObj = c.detail && typeof c.detail === "object" ? c.detail : {};
  const src = ft.src_ip || c.src_ip || detailObj.src_ip || "-";
  const dst = ft.dst_ip || c.dst_ip || detailObj.target || "-";
  const rawProto = String(ft.proto || c.proto || "TCP").toUpperCase();
  const dstPort = Number(ft.dst_port || c.dst_port || 0);
  const srcPort = Number(ft.src_port || c.src_port || 0);
  const app = String(c.app || c.app_or_domain || "Unknown");
  const size = Number(c.bytes ?? c.length ?? c.packet_len ?? 512) || 0;
  const blocked = !!c.blocked;
  const isAnomaly = c.event === "anomaly" || c.event === "security_alert";
  const reason = c.reason || (isAnomaly ? (c.alert_type || c.type) : null);

  let proto = rawProto;
  if (app === "DNS" || dstPort === 53) proto = "DNS";
  else if (dstPort === 443) proto = "TLS";
  else if (dstPort === 80) proto = "HTTP";

  const knownProtos = ["TCP", "UDP", "TLS", "DNS", "HTTP", "HTTPS", "ICMP"];
  const badgeProto = knownProtos.includes(proto) ? proto : "OTHER";

  let info = "";
  if (c.info) {
    info = String(c.info);
  } else if (c.event === "security_alert") {
    const label = c.alert_type || reason || "SECURITY_ALERT";
    const det = typeof c.detail === "string" && c.detail ? c.detail : app;
    info = `${blocked ? "BLOCKED" : "FLAGGED"}: ${label} — ${det}`;
  } else if (c.event === "anomaly") {
    info = `ALERT: ${c.type || "Anomaly"} from ${src}`;
  } else if (blocked) {
    info = `BLOCKED: ${reason || "POLICY"} (${app})`;
  } else if (proto === "DNS") {
    info = `DNS → ${app} query [Port 53]`;
  } else if (proto === "TLS") {
    info = `${app} → TLS Application Data [Port 443]`;
  } else if (proto === "HTTP") {
    info = `${app} → HTTP Request/Response [Port 80]`;
  } else {
    info = `${app} → ${srcPort} → ${dstPort} (${size} B)`;
  }

  return {
    raw: c,
    id: c.id || ("pkt_" + Math.random().toString(36).slice(2, 11)),
    timestamp: c.ts || Date.now() / 1000,
    src_ip: src,
    src_port: srcPort,
    dst_ip: dst,
    dst_port: dstPort,
    protocol: proto,
    transportProto: rawProto,
    badgeProto: badgeProto,
    app: app,
    size: size,
    info: info,
    blocked: blocked,
    reason: reason,
    alert: isAnomaly || blocked,
    status: blocked ? "Dropped" : (isAnomaly ? "Warning" : "Captured"),
  };
}

// ── Packet Stream Table ──────────────────────────────────────────────────────
function updateBufferBar() {
  const pct = Math.min(100, Math.round((connStore.length / MAX_CONN_ROWS) * 100));
  const bar = document.getElementById("footer-buffer-bar");
  if (bar) bar.style.width = `${pct}%`;
}

function renderPacketEmptyState(isFilteredZero = false) {
  const tbody = document.getElementById("pkt-tbody");
  if (!tbody) return;
  let emptyRow = document.getElementById("pkt-empty-row");
  if (!emptyRow) {
    emptyRow = document.createElement("tr");
    emptyRow.id = "pkt-empty-row";
    tbody.appendChild(emptyRow);
  }
  if (isFilteredZero) {
    emptyRow.innerHTML = `
      <td colspan="7">
        <div class="empty-state-box">
          <strong>No packets match "${escapeHtml(activeFilterText)}"</strong>
          Try clearing or broadening your stream filter.
          <div><button type="button" class="btn-inline" onclick="clearStreamFilter()">Clear filter</button></div>
        </div>
      </td>`;
  } else {
    emptyRow.innerHTML = `
      <td colspan="7">
        <div class="empty-state-box">
          <strong>No packets captured yet</strong>
          Waiting for live engine IPC events on port 9000 or simulator traffic.
        </div>
      </td>`;
  }
  emptyRow.style.display = "";
}

function removePacketEmptyState() {
  const emptyRow = document.getElementById("pkt-empty-row");
  if (emptyRow) emptyRow.remove();
}

function rowMatchesFilter(searchStr, filterStr) {
  if (!filterStr) return true;
  const terms = filterStr.split(/\s+/).filter(Boolean);
  return terms.every(t => searchStr.includes(t));
}

function addPacketRow(p, isPrepend = false) {
  const tbody = document.getElementById("pkt-tbody");
  if (!tbody) return;
  removePacketEmptyState();

  const tr = document.createElement("tr");
  tr.dataset.id = p.id;
  tr.dataset.proto = p.protocol.toLowerCase();
  tr.dataset.search = `${p.src_ip} ${p.dst_ip} ${p.src_port} ${p.dst_port} ${p.protocol} ${p.app} ${p.info} ${p.status} ${p.reason || ""}`.toLowerCase();
  tr.tabIndex = 0;
  tr.setAttribute("aria-selected", "false");

  if (p.blocked) tr.className = "row-dropped";
  else if (p.alert) tr.className = "row-warning";
  else tr.className = "row-captured";

  const statusClass = p.blocked ? "status-dropped" : (p.alert ? "status-warning" : "status-captured");

  tr.innerHTML = `
    <td style="color:var(--text-dim)">${escapeHtml(fmtTime(p.timestamp))}</td>
    <td style="color:#f0f6fc;font-weight:600">${escapeHtml(p.src_ip)}</td>
    <td style="color:var(--text-dim)"><span aria-hidden="true" style="opacity:0.6">→</span> ${escapeHtml(p.dst_ip)}</td>
    <td><span class="proto-badge proto-${escapeHtml(p.badgeProto)}">${escapeHtml(p.protocol)}</span></td>
    <td class="r" style="color:var(--text-dim)">${escapeHtml(p.size)}</td>
    <td style="color:inherit;max-width:250px;overflow:hidden;text-overflow:ellipsis" title="${escapeHtml(p.info)}">${escapeHtml(p.info)}</td>
    <td><span class="status-pill ${statusClass}">${escapeHtml(p.status)}</span></td>
  `;

  tr.addEventListener("click", () => selectPacket(tr, p));
  tr.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      selectPacket(tr, p);
    }
  });

  if (isPrepend) {
    tbody.insertBefore(tr, tbody.firstChild);
  } else {
    tbody.appendChild(tr);
  }

  // Enforce DOM ring buffer limit
  while (tbody.querySelectorAll("tr[data-id]").length > MAX_CONN_ROWS) {
    const rows = tbody.querySelectorAll("tr[data-id]");
    const last = rows[rows.length - 1];
    if (last === selectedRow) selectedRow = null;
    last.remove();
  }

  if (activeFilterText && !rowMatchesFilter(tr.dataset.search, activeFilterText)) {
    tr.style.display = "none";
  }

  updateBufferBar();
  updateFilterMatchCount();

  // Keep newest row visible at top when prepending & Auto-scroll is enabled
  const autoScroll = document.getElementById("autoscroll-chk")?.checked;
  if (!isStreamPaused && autoScroll) {
    const wrap = document.getElementById("pkt-table-wrap");
    if (wrap) wrap.scrollTop = isPrepend ? 0 : wrap.scrollHeight;
  }
}

function jumpToTop() {
  const wrap = document.getElementById("pkt-table-wrap");
  if (wrap) wrap.scrollTop = 0;
}
function jumpToBottom() {
  const wrap = document.getElementById("pkt-table-wrap");
  if (wrap) wrap.scrollTop = wrap.scrollHeight;
}

function updateFilterMatchCount() {
  const tbody = document.getElementById("pkt-tbody");
  const countEl = document.getElementById("filter-match-count");
  if (!tbody || !countEl) return;

  const dataRows = Array.from(tbody.querySelectorAll("tr[data-id]"));
  if (!activeFilterText) {
    countEl.textContent = `${dataRows.length} buffered`;
    if (dataRows.length === 0) renderPacketEmptyState(false);
    return;
  }

  const visibleCount = dataRows.filter(tr => tr.style.display !== "none").length;
  countEl.textContent = `${visibleCount} of ${dataRows.length} matching`;
  if (dataRows.length > 0 && visibleCount === 0) {
    renderPacketEmptyState(true);
  } else if (dataRows.length === 0) {
    renderPacketEmptyState(false);
  } else {
    removePacketEmptyState();
  }
}

function applyFilter() {
  const input = document.getElementById("bpf-filter");
  activeFilterText = (input ? input.value : "").trim().toLowerCase();
  const tbody = document.getElementById("pkt-tbody");
  if (!tbody) return;

  removePacketEmptyState();
  const rows = tbody.querySelectorAll("tr[data-id]");
  rows.forEach(tr => {
    if (!activeFilterText || rowMatchesFilter(tr.dataset.search || "", activeFilterText)) {
      tr.style.display = "";
    } else {
      tr.style.display = "none";
    }
  });
  updateFilterMatchCount();
}

function clearStreamFilter() {
  const input = document.getElementById("bpf-filter");
  if (input) {
    input.value = "";
    input.focus();
  }
  applyFilter();
}

// ── Active Security Alert Feed (Color-coded & Filterable) ────────────────────
function normalizeAlert(event) {
  const rawType = String(event.alert_type || event.type || event.reason || "OTHER").toUpperCase();
  let filterType = rawType;
  const knownTypes = ["MALICIOUS", "VPN_DETECTED", "PORT_SCAN", "SYN_FLOOD", "DNS_TUNNEL"];
  if (!knownTypes.includes(filterType)) {
    filterType = "OTHER";
  }

  let badgeClass = filterType;
  let badgeLabel = rawType;
  let actionLabel = "ALERT";
  let actionClass = "alert";

  if (filterType === "VPN_DETECTED") {
    if (event.blocked) {
      badgeClass = "VPN_BLOCKED";
      badgeLabel = "VPN BLOCKED";
      actionLabel = "BLOCKED";
      actionClass = "blocked";
    } else {
      badgeClass = "VPN_DETECTED";
      badgeLabel = "VPN FLAGGED";
      actionLabel = "FLAGGED";
      actionClass = "flagged";
    }
  } else if (event.blocked || filterType === "MALICIOUS") {
    actionLabel = "BLOCKED";
    actionClass = "blocked";
  }

  const ft = event.five_tuple || {};
  const detailObj = event.detail && typeof event.detail === "object" ? event.detail : null;
  let detailStr = "";
  if (typeof event.detail === "string" && event.detail) {
    detailStr = event.detail;
  } else if (detailObj) {
    detailStr = Object.entries(detailObj).map(([k, v]) => `${k}=${v}`).join(" ");
  } else if (event.app_or_domain) {
    detailStr = String(event.app_or_domain);
  }
  const srcIp = ft.src_ip || (detailObj && detailObj.src_ip) || "";
  if (srcIp && !detailStr.includes(srcIp)) {
    detailStr = `${srcIp} · ${detailStr}`;
  }

  const key = event.id != null
    ? `id_${event.id}`
    : `${event.ts || ""}_${rawType}_${detailStr}`;

  const filterTarget = event.app_or_domain || srcIp || (detailObj && detailObj.domain) || "";

  return {
    key,
    ts: event.ts || Date.now() / 1000,
    filterType,
    badgeClass,
    badgeLabel,
    actionLabel,
    actionClass,
    detail: detailStr || rawType,
    filterTarget: String(filterTarget || ""),
  };
}

function addSecurityAlert(event) {
  if (!event || (event.event !== "anomaly" && event.event !== "security_alert")) return;
  const item = normalizeAlert(event);
  if (seenAlertKeys.has(item.key)) return;
  seenAlertKeys.add(item.key);
  if (seenAlertKeys.size > 1000) {
    const first = seenAlertKeys.values().next().value;
    seenAlertKeys.delete(first);
  }

  alertStore.unshift(item);
  if (alertStore.length > MAX_ALERT_ITEMS) alertStore.pop();
  renderAlertFeed();
}

function renderAlertFeed() {
  const list = document.getElementById("alert-feed-list");
  const countBadge = document.getElementById("alert-feed-count");
  if (!list) return;

  const filtered = activeAlertFilter === "ALL"
    ? alertStore
    : alertStore.filter(a => a.filterType === activeAlertFilter);

  if (countBadge) {
    countBadge.textContent = activeAlertFilter === "ALL"
      ? `${alertStore.length} alert${alertStore.length === 1 ? "" : "s"}`
      : `${filtered.length} / ${alertStore.length} shown`;
    countBadge.className = alertStore.length > 0 ? "alert-count-badge active" : "alert-count-badge";
  }

  if (filtered.length === 0) {
    const emptyMsg = alertStore.length === 0
      ? "<strong>No active security alerts</strong>Traffic is nominal across all 5 detectors (Malicious, VPN, Port Scan, SYN Flood, DNS Tunnel)."
      : `<strong>No alerts for ${escapeHtml(activeAlertFilter)}</strong>Switch back to ALL to view ${alertStore.length} recorded alert(s).`;
    list.innerHTML = `<li id="alert-empty-state"><div class="empty-state-box">${emptyMsg}</div></li>`;
    return;
  }

  list.innerHTML = "";
  for (const a of filtered) {
    const li = document.createElement("li");
    li.className = `alert-item type-${a.filterType}`;
    li.tabIndex = 0;
    li.title = a.filterTarget ? `Click to filter stream by ${a.filterTarget}` : a.detail;
    li.innerHTML = `
      <span class="alert-ts">${escapeHtml(fmtTime(a.ts))}</span>
      <span class="alert-badge ${escapeHtml(a.badgeClass)}">${escapeHtml(a.badgeLabel)}</span>
      <span class="alert-action-pill ${escapeHtml(a.actionClass)}">${escapeHtml(a.actionLabel)}</span>
      <span class="alert-detail-text">${escapeHtml(a.detail)}</span>
    `;
    const activateAlert = () => {
      if (!a.filterTarget) return;
      const input = document.getElementById("bpf-filter");
      if (input) {
        input.value = a.filterTarget;
        applyFilter();
      }
    };
    li.addEventListener("click", activateAlert);
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        activateAlert();
      }
    });
    list.appendChild(li);
  }

  const autoScroll = document.getElementById("alert-autoscroll-chk")?.checked;
  if (autoScroll) {
    list.scrollTop = 0;
  }
}

function setAlertFilter(type) {
  activeAlertFilter = type || "ALL";
  document.querySelectorAll(".alert-filter-btn").forEach(btn => {
    const isMatch = btn.dataset.type === activeAlertFilter;
    btn.classList.toggle("active", isMatch);
    btn.setAttribute("aria-pressed", isMatch ? "true" : "false");
  });
  renderAlertFeed();
}

// ── Deep Packet Inspector ────────────────────────────────────────────────────
function selectPacket(tr, p) {
  if (selectedRow) {
    selectedRow.classList.remove("selected");
    selectedRow.setAttribute("aria-selected", "false");
  }
  selectedRow = tr;
  tr.classList.add("selected");
  tr.setAttribute("aria-selected", "true");

  const infoEl = document.getElementById("inspector-pkt-info");
  if (infoEl) {
    infoEl.textContent = `${p.protocol} · ${p.src_ip}:${p.src_port} → ${p.dst_ip}:${p.dst_port} · ${p.size} Bytes`;
  }

  renderProtocolDissection(p);
  renderHexDump(p);
}

function renderProtocolDissection(p) {
  const tree = document.getElementById("proto-tree");
  if (!tree) return;
  const transport = String(p.transportProto || (p.protocol === "DNS" ? "UDP" : p.protocol) || "TCP").toUpperCase();
  const isUdp = transport === "UDP";
  const protoNum = isUdp ? 17 : (transport === "ICMP" ? 1 : 6);

  const layers = [
    {
      title: "Ethernet II, Src: Network Interface, Dst: Local Gateway",
      fields: [
        ["Frame Length", `${p.size} bytes (${p.size * 8} bits)`],
        ["EtherType", "IPv4 (0x0800)"],
      ],
    },
    {
      title: `Internet Protocol Version 4, Src: ${p.src_ip}, Dst: ${p.dst_ip}`,
      fields: [
        ["Version", "4"],
        ["Header Length", "20 bytes (5)"],
        ["Total Length", `${p.size} bytes`],
        ["Protocol", `${transport} (${protoNum})`],
        ["Source Address", p.src_ip],
        ["Destination Address", p.dst_ip],
      ],
    },
    {
      title: `${isUdp ? "User Datagram Protocol" : "Transmission Control Protocol"}, Src Port: ${p.src_port}, Dst Port: ${p.dst_port}`,
      fields: [
        ["Source Port", `${p.src_port}`],
        ["Destination Port", `${p.dst_port}`],
        ["Length", `${Math.max(0, p.size - 20)} bytes`],
      ],
    },
    {
      title: `Application Layer: ${p.app} (${p.status})`,
      fields: [
        ["Classified Application", p.app],
        ["Inspection Result", p.blocked ? `BLOCKED [${p.reason || "POLICY"}]` : "ALLOWED"],
        ["Reason Code", p.reason || "None"],
        ["Flow Info", p.info],
      ],
    },
  ];

  tree.innerHTML = layers.map((layer, idx) => {
    const isOpen = idx >= 1;
    return `
      <div class="tree-layer ${isOpen ? "open" : ""}">
        <button type="button" class="tree-layer-header" aria-expanded="${isOpen ? "true" : "false"}">
          <span class="tree-arrow" aria-hidden="true">▶</span>
          <span>${escapeHtml(layer.title)}</span>
        </button>
        <div class="tree-layer-content">
          ${layer.fields.map(([k, v]) => `
            <div class="tree-row">
              <span class="tree-key">${escapeHtml(k)}:</span>
              <span class="tree-val">${escapeHtml(v)}</span>
            </div>
          `).join("")}
        </div>
      </div>`;
  }).join("");

  tree.querySelectorAll(".tree-layer-header").forEach(btn => {
    btn.addEventListener("click", () => {
      const parent = btn.parentElement;
      const nowOpen = parent.classList.toggle("open");
      btn.setAttribute("aria-expanded", nowOpen ? "true" : "false");
    });
  });
}

function renderHexDump(p) {
  const hex = document.getElementById("hex-dump");
  if (!hex) return;
  const srcParts = (p.src_ip || "127.0.0.1").split(".").map(x => parseInt(x, 10) || 0);
  const dstParts = (p.dst_ip || "127.0.0.1").split(".").map(x => parseInt(x, 10) || 0);
  const totalLen = Math.min(Math.max(p.size || 64, 48), 128);
  const transport = String(p.transportProto || (p.protocol === "DNS" ? "UDP" : p.protocol) || "TCP").toUpperCase();
  const isUdp = transport === "UDP";
  const protoNum = isUdp ? 17 : (transport === "ICMP" ? 1 : 6);

  const bytes = [];
  bytes.push(0x45, 0x00, (p.size >> 8) & 0xff, p.size & 0xff);
  bytes.push(0x1a, 0x2b, 0x40, 0x00, 0x40, protoNum, 0x7a, 0xb1);
  bytes.push(...(srcParts.length === 4 ? srcParts : [127, 0, 0, 1]));
  bytes.push(...(dstParts.length === 4 ? dstParts : [127, 0, 0, 1]));

  bytes.push((p.src_port >> 8) & 0xff, p.src_port & 0xff, (p.dst_port >> 8) & 0xff, p.dst_port & 0xff);
  if (!isUdp) {
    bytes.push(0x00, 0x1f, 0x3c, 0x80, 0x00, 0x00, 0x00, 0x00, 0x50, 0x18, 0x01, 0xf5, 0x6f, 0x29, 0x00, 0x00);
  } else {
    const udpLen = Math.max(8, p.size - 20);
    bytes.push((udpLen >> 8) & 0xff, udpLen & 0xff, 0x00, 0x00);
  }

  const appPayload = `${p.app} ${p.blocked ? "[BLOCKED: " + (p.reason || "") + "]" : "[ALLOWED]"}`;
  for (let i = 0; i < appPayload.length; i++) {
    bytes.push(appPayload.charCodeAt(i) & 0xff);
  }

  let seed = ((p.src_port || 1) + (p.dst_port || 1)) % 256;
  while (bytes.length < totalLen) {
    seed = (seed * 37 + 13) % 256;
    bytes.push(seed);
  }

  let html = "";
  for (let i = 0; i < bytes.length; i += 16) {
    const chunk = bytes.slice(i, i + 16);
    const offset = i.toString(16).padStart(4, "0");
    const hexPart = chunk.map(b => b.toString(16).padStart(2, "0")).join(" ");
    const asciiPart = chunk.map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");

    html += `
      <div class="hex-row">
        <span class="hex-offset">${offset}</span>
        <span class="hex-bytes">${escapeHtml(hexPart.padEnd(48, " "))}</span>
        <span class="hex-ascii">${escapeHtml(asciiPart)}</span>
      </div>`;
  }
  hex.innerHTML = html;
}

function toggleInspector() {
  const insp = document.getElementById("inspector");
  const sbBtn = document.getElementById("btn-toggle-inspector");
  const closeBtn = document.getElementById("inspector-close-btn");
  if (!insp) return;

  const isCollapsed = insp.classList.toggle("collapsed");
  const expandedStr = isCollapsed ? "false" : "true";
  if (sbBtn) {
    sbBtn.textContent = isCollapsed ? "Show Inspector" : "Hide Inspector";
    sbBtn.setAttribute("aria-expanded", expandedStr);
  }
  if (closeBtn) {
    closeBtn.setAttribute("aria-expanded", expandedStr);
  }
}

// ── Charts: Throughput (Sane Y-axis), App Breakdown, Blocked Reasons ─────────
function updateThroughputChart(bps) {
  const val = Math.max(0, Number(bps) || 0);
  if (val > 0) tpHasNonZero = true;
  tpValues.push(val);
  if (tpValues.length > TP_WINDOW) tpValues.shift();

  const emptyEl = document.getElementById("tp-empty-state");
  const svgEl = document.getElementById("throughput-svg");
  const scaleLabel = document.getElementById("tp-scale-label");
  if (!svgEl || !emptyEl) return;

  if (!tpHasNonZero && !hasReceivedTraffic) {
    emptyEl.style.display = "";
    svgEl.style.display = "none";
    return;
  }

  emptyEl.style.display = "none";
  svgEl.style.display = "block";

  // Sane damped Y-axis scaling so bursts don't cause erratic vertical jumps
  const windowPeak = Math.max(...tpValues, 100);
  smoothedMaxBps = Math.max(windowPeak * 1.15, smoothedMaxBps * 0.88, 1000);
  const yMax = niceCeil(smoothedMaxBps);
  if (scaleLabel) scaleLabel.textContent = `Scale: 0–${fmtBps(yMax)}`;

  const W = 420, H = 128;
  const padL = 54, padR = 12, padT = 10, padB = 24;
  const plotW = W - padL - padR;
  const plotH = H - padT - padB;

  const points = tpValues.map((v, i) => {
    const x = padL + (i / (TP_WINDOW - 1)) * plotW;
    const y = padT + plotH - (Math.min(v, yMax) / yMax) * plotH;
    return { x, y, v, secAgo: (TP_WINDOW - 1) - i };
  });

  const linePath = points.map((p, i) => `${i === 0 ? "M" : "L"}${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(" ");
  const areaPath = `${linePath} L${(padL + plotW).toFixed(1)},${(padT + plotH).toFixed(1)} L${padL},${(padT + plotH).toFixed(1)} Z`;

  const yTicks = [0, 0.5, 1].map(frac => ({
    y: padT + plotH - frac * plotH,
    label: fmtBps(yMax * frac),
  }));

  svgEl.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svgEl.innerHTML = `
    <defs>
      <linearGradient id="tp-grad" x1="0" y1="0" x2="0" y2="1">
        <stop offset="0%" stop-color="#58a6ff" stop-opacity="0.34"/>
        <stop offset="100%" stop-color="#58a6ff" stop-opacity="0.02"/>
      </linearGradient>
    </defs>
    ${yTicks.map(t => `
      <line x1="${padL}" y1="${t.y.toFixed(1)}" x2="${W - padR}" y2="${t.y.toFixed(1)}" stroke="#223045" stroke-dasharray="3,3" stroke-width="1"/>
      <text x="${padL - 6}" y="${(t.y + 3).toFixed(1)}" text-anchor="end" fill="#8b99ab" font-size="9" font-family="JetBrains Mono, monospace">${escapeHtml(t.label)}</text>
    `).join("")}
    <path d="${areaPath}" fill="url(#tp-grad)"/>
    <path d="${linePath}" fill="none" stroke="#58a6ff" stroke-width="2" stroke-linejoin="round"/>
    <text x="${padL}" y="${H - 5}" text-anchor="start" fill="#8b99ab" font-size="9" font-family="JetBrains Mono, monospace">-30s</text>
    <text x="${padL + plotW / 2}" y="${H - 5}" text-anchor="middle" fill="#8b99ab" font-size="9" font-family="JetBrains Mono, monospace">Time (seconds)</text>
    <text x="${W - padR}" y="${H - 5}" text-anchor="end" fill="#8b99ab" font-size="9" font-family="JetBrains Mono, monospace">now</text>
    ${points.map((p, idx) => `
      <circle class="tp-pt" cx="${p.x.toFixed(1)}" cy="${p.y.toFixed(1)}" r="3.5" fill="#58a6ff" fill-opacity="0" data-idx="${idx}" style="cursor:crosshair"/>
    `).join("")}
  `;

  svgEl.querySelectorAll(".tp-pt").forEach(dot => {
    const idx = Number(dot.dataset.idx);
    const pt = points[idx];
    dot.addEventListener("mouseenter", (evt) => {
      dot.setAttribute("fill-opacity", "1");
      const ago = pt.secAgo === 0 ? "now" : `-${pt.secAgo}s`;
      showTooltip(evt, `Throughput (${ago}): ${fmtBps(pt.v)}`);
    });
    dot.addEventListener("mousemove", (evt) => {
      const ago = pt.secAgo === 0 ? "now" : `-${pt.secAgo}s`;
      showTooltip(evt, `Throughput (${ago}): ${fmtBps(pt.v)}`);
    });
    dot.addEventListener("mouseleave", () => {
      dot.setAttribute("fill-opacity", "0");
      hideTooltip();
    });
  });
}

const APP_COLORS = ["#58a6ff", "#3fb950", "#f2cc60", "#76e3ea", "#d2a8ff", "#ffa657", "#ff7b72", "#93c5fd"];

function updateBarBreakdown(listId, emptyId, totalId, entries, colorFn, unitLabel) {
  const listEl = document.getElementById(listId);
  const emptyEl = document.getElementById(emptyId);
  const totalEl = document.getElementById(totalId);
  if (!listEl || !emptyEl) return;

  const total = entries.reduce((sum, [, c]) => sum + c, 0);
  if (totalEl) totalEl.textContent = `${total.toLocaleString()} ${unitLabel}`;

  if (!entries.length || total === 0) {
    emptyEl.style.display = "";
    listEl.style.display = "none";
    listEl.innerHTML = "";
    return;
  }

  emptyEl.style.display = "none";
  listEl.style.display = "flex";
  listEl.innerHTML = "";

  entries.forEach(([label, count], i) => {
    const pct = ((count / total) * 100).toFixed(1);
    const color = colorFn(label, i);
    const li = document.createElement("li");
    li.className = "bar-row";
    li.innerHTML = `
      <span class="bar-row-name" title="${escapeHtml(label)}">${escapeHtml(label)}</span>
      <div class="bar-row-track">
        <div class="bar-row-fill" style="width:${pct}%;background:${color}"></div>
      </div>
      <span class="bar-row-val">${count.toLocaleString()} (${pct}%)</span>
    `;
    li.addEventListener("mouseenter", (evt) => {
      showTooltip(evt, `${label}: ${count.toLocaleString()} ${unitLabel} (${pct}%)`);
    });
    li.addEventListener("mousemove", (evt) => {
      showTooltip(evt, `${label}: ${count.toLocaleString()} ${unitLabel} (${pct}%)`);
    });
    li.addEventListener("mouseleave", hideTooltip);
    listEl.appendChild(li);
  });
}

// ── D3.js Real-Time Network Map ──────────────────────────────────────────────
let simulation, svg, linkGroup, nodeGroup, particleGroup;
const networkNodes = {};
const networkLinks = [];

function initGraph() {
  if (typeof d3 === "undefined") {
    const overlay = document.getElementById("map-empty-overlay");
    if (overlay) {
      overlay.innerHTML = "<strong>Network Map unavailable offline</strong><span>D3.js CDN could not be reached. Traffic Charts remain fully operational.</span>";
    }
    return;
  }

  const container = document.getElementById("network-map");
  if (!container) return;
  const width = container.clientWidth || 560;
  const height = container.clientHeight || 280;

  svg = d3.select("#map-svg")
    .attr("viewBox", `0 0 ${width} ${height}`)
    .attr("preserveAspectRatio", "xMidYMid meet");

  const bg = svg.append("g").attr("class", "radar-bg");
  const cx = width / 2, cy = height / 2;
  [65, 130, 195, 260].forEach(r => {
    bg.append("circle")
      .attr("cx", cx).attr("cy", cy).attr("r", r)
      .attr("fill", "none")
      .attr("stroke", "rgba(88, 166, 255, 0.08)")
      .attr("stroke-width", 1)
      .attr("stroke-dasharray", "3,3");
  });

  const defs = svg.append("defs");
  defs.append("marker")
    .attr("id", "arrow-cyan")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 22)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", "#58a6ff")
    .attr("opacity", 0.65);

  defs.append("marker")
    .attr("id", "arrow-orange")
    .attr("viewBox", "0 -5 10 10")
    .attr("refX", 22)
    .attr("refY", 0)
    .attr("markerWidth", 6)
    .attr("markerHeight", 6)
    .attr("orient", "auto")
    .append("path")
    .attr("d", "M0,-5L10,0L0,5")
    .attr("fill", "#f2cc60")
    .attr("opacity", 0.75);

  linkGroup = svg.append("g").attr("class", "links");
  particleGroup = svg.append("g").attr("class", "particles");
  nodeGroup = svg.append("g").attr("class", "nodes");

  simulation = d3.forceSimulation()
    .force("link", d3.forceLink().id(d => d.id).distance(80))
    .force("charge", d3.forceManyBody().strength(-180))
    .force("center", d3.forceCenter(width / 2, height / 2))
    .force("collision", d3.forceCollide().radius(24));

  svg.call(d3.zoom().scaleExtent([0.4, 3]).on("zoom", e => {
    linkGroup.attr("transform", e.transform);
    particleGroup.attr("transform", e.transform);
    nodeGroup.attr("transform", e.transform);
    bg.attr("transform", e.transform);
  }));

  networkNodes["Gateway"] = {
    id: "Gateway",
    label: "Gateway",
    icon: "✛",
    type: "gateway",
    color: "#3fb950",
    radius: 14,
    fx: width / 2,
    fy: height / 2,
  };
}

function getNodeMeta(id) {
  if (id === "Gateway" || id === "192.168.1.1" || id === "10.0.0.1") {
    return { label: "Gateway", icon: "✛", type: "gateway", color: "#3fb950", radius: 14 };
  }
  if (id.startsWith("192.168.") || id.startsWith("10.0.") || id.startsWith("127.")) {
    return { label: id, icon: "●", type: "client", color: "#58a6ff", radius: 10 };
  }
  return { label: id, icon: "◆", type: "wan", color: "#f2cc60", radius: 10 };
}

function addNetworkConnection(srcIp, dstIp) {
  if (!simulation || !srcIp || !dstIp || srcIp === "-" || dstIp === "-") return;

  const overlay = document.getElementById("map-empty-overlay");
  if (overlay) overlay.style.display = "none";

  if (!networkNodes[srcIp]) {
    networkNodes[srcIp] = { id: srcIp, ...getNodeMeta(srcIp) };
  }
  if (!networkNodes[dstIp]) {
    networkNodes[dstIp] = { id: dstIp, ...getNodeMeta(dstIp) };
  }

  const isWan = !dstIp.startsWith("192.168.") && !dstIp.startsWith("10.0.") && !dstIp.startsWith("127.");
  const existing = networkLinks.find(
    l => (l.source === srcIp || l.source?.id === srcIp) &&
         (l.target === dstIp || l.target?.id === dstIp)
  );

  if (existing) {
    existing.count = (existing.count || 1) + 1;
    existing.wan = isWan;
  } else {
    if (networkLinks.length >= 35) {
      const evicted = networkLinks.shift();
      if (evicted) {
        const evictedIds = [evicted.source?.id || evicted.source, evicted.target?.id || evicted.target];
        for (const id of evictedIds) {
          if (!id || id === "Gateway") continue;
          const stillReferenced = networkLinks.some(
            l => (l.source?.id || l.source) === id || (l.target?.id || l.target) === id
          );
          if (!stillReferenced) delete networkNodes[id];
        }
      }
    }
    networkLinks.push({ source: srcIp, target: dstIp, count: 1, wan: isWan });
  }

  updateGraphUI();
  pulseParticle(srcIp, dstIp, isWan);
}

function updateGraphUI() {
  if (!simulation) return;
  const nodes = Object.values(networkNodes);
  const links = networkLinks.map(l => ({ ...l }));

  const countEl = document.getElementById("map-node-count");
  if (countEl) countEl.textContent = `${nodes.length} nodes · ${links.length} active links`;

  simulation.nodes(nodes);
  simulation.force("link").links(links);

  const linkSelection = linkGroup.selectAll("line").data(
    links,
    d => `${d.source.id || d.source}->${d.target.id || d.target}`
  );
  linkSelection.exit().remove();
  const linkEnter = linkSelection.enter().append("line");
  const allLinks = linkEnter.merge(linkSelection)
    .attr("class", d => "link" + (d.wan ? " wan" : ""))
    .attr("stroke-width", d => Math.min(1 + Math.log2(d.count || 1), 2.5))
    .attr("marker-end", d => d.wan ? "url(#arrow-orange)" : "url(#arrow-cyan)");

  const nodeSelection = nodeGroup.selectAll("g.node").data(nodes, d => d.id);
  nodeSelection.exit().remove();

  const nodeEnter = nodeSelection.enter().append("g")
    .attr("class", "node")
    .call(d3.drag()
      .on("start", (e, d) => {
        if (!e.active) simulation.alphaTarget(0.3).restart();
        d.fx = d.x; d.fy = d.y;
      })
      .on("drag", (e, d) => { d.fx = e.x; d.fy = e.y; })
      .on("end", (e, d) => {
        if (!e.active) simulation.alphaTarget(0);
        if (d.type !== "gateway") { d.fx = null; d.fy = null; }
      })
    );

  nodeEnter.append("circle")
    .attr("class", "node-circle")
    .attr("r", d => d.radius || 10)
    .attr("fill", "#131b27")
    .attr("stroke", d => d.color);

  nodeEnter.append("text")
    .attr("class", "node-icon")
    .attr("text-anchor", "middle")
    .attr("dy", 4)
    .attr("fill", d => d.color)
    .text(d => d.icon || "●");

  nodeEnter.append("text")
    .attr("class", "node-label")
    .attr("dy", d => (d.radius || 10) + 12)
    .attr("text-anchor", "middle")
    .text(d => d.label || d.id);

  function filterByNode(d) {
    const input = document.getElementById("bpf-filter");
    if (input) {
      input.value = d.id;
      applyFilter();
    }
  }

  nodeEnter
    .attr("tabindex", "0")
    .attr("role", "button")
    .attr("aria-label", d => `Filter stream by ${d.label || d.id}`)
    .on("click", (e, d) => filterByNode(d))
    .on("keydown", (e, d) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        filterByNode(d);
      }
    });

  const allNodes = nodeEnter.merge(nodeSelection);
  simulation.on("tick", () => {
    allLinks
      .attr("x1", d => d.source.x)
      .attr("y1", d => d.source.y)
      .attr("x2", d => d.target.x)
      .attr("y2", d => d.target.y);
    allNodes.attr("transform", d => `translate(${d.x},${d.y})`);
  });

  simulation.alpha(0.2).restart();
}

function pulseParticle(srcId, dstId, isWan) {
  if (!particleGroup) return;
  const srcNode = networkNodes[srcId];
  const dstNode = networkNodes[dstId];
  if (!srcNode || !dstNode || !srcNode.x || !dstNode.x) return;

  const dot = particleGroup.append("circle")
    .attr("r", isWan ? 3 : 2.5)
    .attr("fill", isWan ? "#f2cc60" : "#58a6ff")
    .attr("cx", srcNode.x)
    .attr("cy", srcNode.y);

  dot.transition()
    .duration(750)
    .ease(d3.easeLinear)
    .attr("cx", dstNode.x)
    .attr("cy", dstNode.y)
    .remove();
}

// ── Tabs (Charts vs Network Map) ─────────────────────────────────────────────
function switchTelemetryTab(tabId) {
  const tabs = document.querySelectorAll('.tab-btn[role="tab"]');
  tabs.forEach(t => {
    const isActive = t.id === tabId;
    t.setAttribute("aria-selected", isActive ? "true" : "false");
    t.tabIndex = isActive ? 0 : -1;
    const panelId = t.getAttribute("aria-controls");
    const panel = document.getElementById(panelId);
    if (panel) panel.classList.toggle("active", isActive);
  });

  if (tabId === "tab-map" && simulation) {
    const container = document.getElementById("network-map");
    if (container) {
      const w = container.clientWidth || 560;
      const h = container.clientHeight || 280;
      svg.attr("viewBox", `0 0 ${w} ${h}`);
      if (networkNodes["Gateway"]) {
        networkNodes["Gateway"].fx = w / 2;
        networkNodes["Gateway"].fy = h / 2;
      }
      simulation.force("center", d3.forceCenter(w / 2, h / 2)).alpha(0.25).restart();
    }
  }
}

// ── WebSocket & Live Stats Updates ───────────────────────────────────────────
function connectWebSocket() {
  const wsProto = location.protocol === "https:" ? "wss:" : "ws:";
  const wsUrl = `${wsProto}//${location.host}/ws`;

  try {
    ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      const wsEl = document.getElementById("sb-ws");
      const dotEl = document.getElementById("sb-dot-ws");
      if (wsEl) {
        wsEl.textContent = "Connected [Live]";
        wsEl.style.color = "#7ee787";
      }
      if (dotEl) dotEl.className = "sb-dot green";
      // Catch up on any alerts emitted before connect / during a dropped socket
      fetchInitialEvents();
    };

    ws.onmessage = (e) => {
      if (isStreamPaused) return;
      try {
        const data = JSON.parse(e.data);
        if (data.total_packets !== undefined) {
          updateStatsUI(data);
          return;
        }
        if (data.event === "anomaly" || data.event === "security_alert") {
          addSecurityAlert(data);
        }
        if (data.event === "app_classified") {
          hasReceivedTraffic = true;
          const norm = normalizeConn(data);
          connStore.unshift(norm);
          if (connStore.length > MAX_CONN_ROWS) connStore.pop();
          addPacketRow(norm, true);
          addNetworkConnection(norm.src_ip, norm.dst_ip);
        }
      } catch (err) {}
    };

    ws.onclose = () => {
      const wsEl = document.getElementById("sb-ws");
      const dotEl = document.getElementById("sb-dot-ws");
      if (wsEl) {
        wsEl.textContent = "Polling fallback";
        wsEl.style.color = "#ffdf85";
      }
      if (dotEl) dotEl.className = "sb-dot orange";
      setTimeout(connectWebSocket, 4000);
    };

    ws.onerror = () => {
      try { ws.close(); } catch (err) {}
    };
  } catch (err) {}
}

async function fetchStats() {
  if (isStreamPaused) return;
  try {
    const res = await fetch("/api/stats");
    if (!res.ok) return;
    const data = await res.json();
    updateStatsUI(data);
  } catch (err) {}
}

function updateStatsUI(d) {
  const now = Date.now();
  const dt = (now - lastTime) / 1000;
  const curr = d.total_packets || 0;
  const pps = dt > 0 && lastPacketCount > 0 ? Math.max(0, Math.round((curr - lastPacketCount) / dt)) : 0;
  lastPacketCount = curr;
  lastTime = now;

  if (curr > 0) hasReceivedTraffic = true;

  const tputBps = d.throughput_bps || 0;
  const tput = fmtBps(tputBps);
  const buf = fmtBytes(d.total_bytes || 0);
  const pkts = curr.toLocaleString();
  const blocked = (d.blocked_total || 0).toLocaleString();

  // Toolbar stats
  document.getElementById("tb-pps").textContent = pps.toLocaleString();
  document.getElementById("tb-tput").textContent = tput;
  document.getElementById("tb-buf").textContent = buf;
  document.getElementById("tb-dropped").textContent = blocked;

  const idlePill = document.getElementById("tb-idle-pill");
  if (idlePill) {
    idlePill.textContent = curr === 0 ? "Awaiting traffic" : `${pps} pps live`;
  }

  // Stage 01-04 Pipeline Summary Cards
  const appsEntries = Object.entries(d.app_breakdown || {}).sort((a, b) => b[1] - a[1]);
  const blockedEntries = Object.entries(d.blocked_reasons || {}).sort((a, b) => b[1] - a[1]);
  const scans = d.scan_alerts || 0;
  const floods = d.syn_flood_alerts || 0;
  const tunnels = d.dns_tunnel_alerts || 0;
  const malicious = d.malicious_domain_blocks || 0;
  const vpnDet = d.vpn_detections || 0;
  const vpnBlk = d.vpn_blocks || 0;
  const totalAlerts = scans + floods + tunnels + malicious + vpnDet;

  document.getElementById("st1-packets").textContent = pkts;
  document.getElementById("st1-bytes").textContent = `${buf} · ${curr === 0 ? "idle" : "active"}`;
  document.getElementById("st2-tput").textContent = tput;
  document.getElementById("st2-apps").textContent = `${appsEntries.length} app${appsEntries.length === 1 ? "" : "s"}`;
  document.getElementById("st3-alerts").textContent = totalAlerts.toLocaleString();
  document.getElementById("st3-blocked").textContent = `${blocked} blocked`;
  document.getElementById("st3-alert-summary").textContent =
    totalAlerts > 0 ? `${totalAlerts} threat signal(s) active` : "No active threats";

  const alertsCard = document.getElementById("stage-alerts-card");
  if (alertsCard) alertsCard.classList.toggle("has-alerts", totalAlerts > 0);

  const policyEl = document.getElementById("st4-policy");
  if (policyEl) policyEl.textContent = String(d.vpn_action || "flag-only").toUpperCase();
  const vpnBlkEl = document.getElementById("st4-vpn-blocks");
  if (vpnBlkEl) vpnBlkEl.textContent = `${vpnBlk} VPN blocked`;

  // Header Security Pills (All 5 Detectors)
  const setPill = (id, label, count, dangerWhenPositive = false) => {
    const el = document.getElementById(id);
    if (!el) return;
    el.textContent = `${label}: ${count}`;
    el.className = count > 0 ? (dangerWhenPositive ? "sec-pill danger" : "sec-pill warn") : "sec-pill";
  };
  setPill("pill-malicious", "Malicious", malicious, true);
  setPill("pill-vpn", "VPN", vpnDet, vpnBlk > 0);
  setPill("pill-scans", "Scans", scans, false);
  setPill("pill-floods", "Floods", floods, true);
  setPill("pill-tunnels", "Tunnels", tunnels, false);

  // Footer & Charts
  document.getElementById("sb-packets").textContent = pkts;
  document.getElementById("sb-buffer").textContent = `${connStore.length} / ${MAX_CONN_ROWS} flows (${buf})`;
  document.getElementById("footer-packet-rate").textContent = `${pps} pkts/s`;

  updateThroughputChart(tputBps);
  updateBarBreakdown(
    "app-bar-list",
    "app-empty-state",
    "app-chart-total",
    appsEntries.slice(0, 6),
    (_, i) => APP_COLORS[i % APP_COLORS.length],
    "pkts"
  );
  const reasonColorMap = {
    MALICIOUS: "#ff7b72",
    VPN_DETECTED: "#f2cc60",
    DOMAIN: "#58a6ff",
    IP: "#ffa657",
    APP: "#d2a8ff",
    PORT: "#76e3ea",
  };
  updateBarBreakdown(
    "blocked-bar-list",
    "blocked-empty-state",
    "blocked-chart-total",
    blockedEntries.filter(([, c]) => c > 0).slice(0, 6),
    (label) => reasonColorMap[label] || "#ff7b72",
    "blocked"
  );
}

async function fetchInitialConnections() {
  try {
    const res = await fetch("/api/connections");
    if (!res.ok) return;
    const data = await res.json();
    const rawList = Array.isArray(data) ? data : (data.connections || []);
    if (!rawList.length) return;

    hasReceivedTraffic = true;
    const sample = rawList.slice(0, 40);
    sample.forEach(c => {
      const norm = normalizeConn(c);
      connStore.push(norm);
      addPacketRow(norm);
      addNetworkConnection(norm.src_ip, norm.dst_ip);
    });

    const firstRow = document.querySelector("#pkt-tbody tr[data-id]");
    if (firstRow && connStore[0]) {
      selectPacket(firstRow, connStore[0]);
    }
  } catch (err) {}
}

async function fetchInitialEvents() {
  try {
    const res = await fetch("/api/events");
    if (!res.ok) return;
    const events = await res.json();
    if (!Array.isArray(events)) return;

    // Preserve newest-first order in alertStore (flows come from /api/connections & app_classified)
    events.slice(0, 30).reverse().forEach(ev => {
      addSecurityAlert(ev);
    });
  } catch (err) {}
}

// ── Capture Feed Controls ────────────────────────────────────────────────────
function setCaptureBadgeState(mode) {
  const badge = document.getElementById("hdr-capture-badge");
  const text = document.getElementById("hdr-capture-text");
  const sbStatus = document.getElementById("sb-status");
  const sbDot = document.getElementById("sb-dot-status");
  const pauseBtn = document.getElementById("btn-pause");
  const footerPauseBtn = document.getElementById("footer-pause-btn");

  if (mode === "active") {
    if (badge) badge.className = "capture-badge";
    if (text) text.textContent = "Active Capture";
    if (sbStatus) { sbStatus.textContent = "Active"; sbStatus.style.color = "#7ee787"; }
    if (sbDot) sbDot.className = "sb-dot green";
    if (pauseBtn) { pauseBtn.textContent = "⏸ Pause"; pauseBtn.setAttribute("aria-pressed", "false"); }
    if (footerPauseBtn) {
      footerPauseBtn.textContent = "⏸";
      footerPauseBtn.setAttribute("aria-pressed", "false");
      footerPauseBtn.setAttribute("aria-label", "Pause live feed");
    }
  } else if (mode === "paused") {
    if (badge) badge.className = "capture-badge paused";
    if (text) text.textContent = "Feed Paused";
    if (sbStatus) { sbStatus.textContent = "Paused"; sbStatus.style.color = "#ffdf85"; }
    if (sbDot) sbDot.className = "sb-dot orange";
    if (pauseBtn) { pauseBtn.textContent = "▶ Resume"; pauseBtn.setAttribute("aria-pressed", "true"); }
    if (footerPauseBtn) {
      footerPauseBtn.textContent = "▶";
      footerPauseBtn.setAttribute("aria-pressed", "true");
      footerPauseBtn.setAttribute("aria-label", "Resume live feed");
    }
  } else {
    if (badge) badge.className = "capture-badge stopped";
    if (text) text.textContent = "Stopped";
    if (sbStatus) { sbStatus.textContent = "Stopped"; sbStatus.style.color = "#ffb4ae"; }
    if (sbDot) sbDot.className = "sb-dot red";
    if (pauseBtn) { pauseBtn.textContent = "▶ Resume"; pauseBtn.setAttribute("aria-pressed", "true"); }
    if (footerPauseBtn) {
      footerPauseBtn.textContent = "▶";
      footerPauseBtn.setAttribute("aria-pressed", "true");
      footerPauseBtn.setAttribute("aria-label", "Resume live feed");
    }
  }
}

function startCapture() {
  const wasPaused = isStreamPaused;
  isStreamPaused = false;
  setCaptureBadgeState("active");
  if (wasPaused) {
    fetchInitialEvents();
    fetchStats();
  }
}

function togglePause() {
  isStreamPaused = !isStreamPaused;
  setCaptureBadgeState(isStreamPaused ? "paused" : "active");
  if (!isStreamPaused) {
    fetchInitialEvents();
    fetchStats();
  }
}

function stopCapture() {
  isStreamPaused = true;
  setCaptureBadgeState("stopped");
}

function exportReport(format) {
  window.open(`/api/report?format=${encodeURIComponent(format)}`, "_blank");
}

// ── Resizable Split Handle (Mouse + Keyboard) ────────────────────────────────
function initResizeHandle() {
  const handle = document.getElementById("resize-handle");
  const left = document.getElementById("pkt-panel");
  if (!handle || !left) return;

  let dragging = false, startX = 0, startW = 0;

  handle.addEventListener("mousedown", e => {
    dragging = true;
    startX = e.clientX;
    startW = left.offsetWidth;
    handle.classList.add("active");
    document.body.style.cursor = "ew-resize";
  });

  window.addEventListener("mousemove", e => {
    if (!dragging) return;
    const dx = e.clientX - startX;
    const newW = Math.max(340, Math.min(startW + dx, window.innerWidth - 360));
    left.style.width = newW + "px";
    left.style.flex = "none";
  });

  window.addEventListener("mouseup", () => {
    if (dragging) {
      dragging = false;
      handle.classList.remove("active");
      document.body.style.cursor = "";
    }
  });

  handle.addEventListener("keydown", e => {
    if (e.key === "ArrowLeft" || e.key === "ArrowRight") {
      e.preventDefault();
      const delta = e.key === "ArrowLeft" ? -28 : 28;
      const newW = Math.max(340, Math.min(left.offsetWidth + delta, window.innerWidth - 360));
      left.style.width = newW + "px";
      left.style.flex = "none";
    }
  });
}

// ── Wire UI Controls & Startup ───────────────────────────────────────────────
window.addEventListener("load", () => {
  initGraph();
  initResizeHandle();

  // Alert filter buttons
  document.querySelectorAll(".alert-filter-btn").forEach(btn => {
    btn.addEventListener("click", () => setAlertFilter(btn.dataset.type));
  });

  // Header threat pills also filter alert feed
  document.querySelectorAll(".sec-pill[data-alert-filter]").forEach(btn => {
    btn.addEventListener("click", () => {
      const target = btn.dataset.alertFilter;
      setAlertFilter(activeAlertFilter === target ? "ALL" : target);
    });
  });

  // Telemetry tabs with keyboard navigation
  const tabBtns = Array.from(document.querySelectorAll('.tab-btn[role="tab"]'));
  tabBtns.forEach((btn, idx) => {
    btn.addEventListener("click", () => switchTelemetryTab(btn.id));
    btn.addEventListener("keydown", e => {
      if (e.key === "ArrowRight" || e.key === "ArrowLeft") {
        e.preventDefault();
        const nextIdx = e.key === "ArrowRight"
          ? (idx + 1) % tabBtns.length
          : (idx - 1 + tabBtns.length) % tabBtns.length;
        tabBtns[nextIdx].focus();
        switchTelemetryTab(tabBtns[nextIdx].id);
      }
    });
  });

  fetchInitialConnections();
  fetchInitialEvents();
  fetchStats();
  connectWebSocket();
  // Poll /api/stats and /api/events only when WebSocket is not open
  setInterval(() => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      fetchStats();
    }
  }, 1500);
  setInterval(() => {
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      fetchInitialEvents();
    }
  }, 8000);
});

window.addEventListener("resize", () => {
  if (!simulation) return;
  const container = document.getElementById("network-map");
  if (!container) return;
  const w = container.clientWidth || 560;
  const h = container.clientHeight || 280;
  svg.attr("viewBox", `0 0 ${w} ${h}`);
  if (networkNodes["Gateway"]) {
    networkNodes["Gateway"].fx = w / 2;
    networkNodes["Gateway"].fy = h / 2;
  }
  simulation.force("center", d3.forceCenter(w / 2, h / 2)).alpha(0.2).restart();
});
