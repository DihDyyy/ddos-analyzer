// ============================================================================
// DDoS PCAP Analyzer - Frontend JavaScript
// ============================================================================

document.addEventListener("DOMContentLoaded", () => {
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("pcap-file");
    const fileSelected = document.getElementById("file-selected");
    const fileName = document.getElementById("file-name");
    const fileSize = document.getElementById("file-size");
    const fileRemove = document.getElementById("file-remove");
    const form = document.getElementById("upload-form");
    const btnAnalyze = document.getElementById("btn-analyze");
    const uploadSection = document.getElementById("upload-section");
    const loadingSection = document.getElementById("loading-section");
    const resultsSection = document.getElementById("results-section");
    const configToggle = document.getElementById("config-toggle");
    const configBody = document.getElementById("config-body");
    const configArrow = document.getElementById("config-arrow");
    const btnNewAnalysis = document.getElementById("btn-new-analysis");

    let selectedFile = null;
    let protocolChart = null;
    let timelineChart = null;
    let httpChart = null;

    // ── Drop Zone ──
    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("dragover", (e) => { e.preventDefault(); dropZone.classList.add("drag-over"); });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
    dropZone.addEventListener("drop", (e) => {
        e.preventDefault();
        dropZone.classList.remove("drag-over");
        if (e.dataTransfer.files.length > 0) handleFileSelect(e.dataTransfer.files[0]);
    });
    fileInput.addEventListener("change", () => { if (fileInput.files.length > 0) handleFileSelect(fileInput.files[0]); });
    fileRemove.addEventListener("click", (e) => {
        e.stopPropagation();
        selectedFile = null; fileInput.value = "";
        fileSelected.style.display = "none";
        dropZone.querySelector(".drop-zone-content").style.display = "";
    });

    function handleFileSelect(file) {
        selectedFile = file;
        fileName.textContent = file.name;
        fileSize.textContent = formatSize(file.size);
        fileSelected.style.display = "flex";
        dropZone.querySelector(".drop-zone-content").style.display = "none";
    }

    // ── Config Toggle ──
    configToggle.addEventListener("click", () => {
        configBody.classList.toggle("open");
        configArrow.classList.toggle("open");
    });

    // ── Form Submit ──
    form.addEventListener("submit", async (e) => {
        e.preventDefault();
        if (!selectedFile) { alert("Vui lòng chọn file .pcap trước!"); return; }

        const formData = new FormData();
        formData.append("pcap_file", selectedFile);
        formData.append("syn_threshold", document.getElementById("syn_threshold").value);
        formData.append("udp_threshold", document.getElementById("udp_threshold").value);
        formData.append("icmp_threshold", document.getElementById("icmp_threshold").value);
        formData.append("http_threshold", document.getElementById("http_threshold").value);

        uploadSection.style.display = "none";
        loadingSection.style.display = "";
        resultsSection.style.display = "none";

        try {
            const resp = await fetch("/api/analyze", { method: "POST", body: formData });
            const data = await resp.json();
            if (!resp.ok || data.error) {
                alert("Lỗi: " + (data.error || "Có lỗi xảy ra"));
                uploadSection.style.display = "";
                loadingSection.style.display = "none";
                return;
            }
            loadingSection.style.display = "none";
            renderResults(data);
        } catch (err) {
            alert("Lỗi kết nối: " + err.message);
            uploadSection.style.display = "";
            loadingSection.style.display = "none";
        }
    });

    // ── New Analysis ──
    btnNewAnalysis.addEventListener("click", () => {
        resultsSection.style.display = "none";
        uploadSection.style.display = "";
        selectedFile = null; fileInput.value = "";
        fileSelected.style.display = "none";
        dropZone.querySelector(".drop-zone-content").style.display = "";
    });

    // ══════════════════════════════════════
    // RENDER RESULTS
    // ══════════════════════════════════════
    function renderResults(data) {
        resultsSection.style.display = "";
        renderRiskBanner(data);
        renderOverviewCards(data);
        renderProtocolChart(data);
        renderTimelineChart(data);
        renderAlerts(data);
        renderAttackSummary(data);
        renderTopIPs(data);
        renderHTTPStats(data);
        renderDownloads(data);
        resultsSection.scrollIntoView({ behavior: "smooth" });
    }

    // ── Risk Banner ──
    function renderRiskBanner(data) {
        const banner = document.getElementById("risk-banner");
        const risk = (data.risk_level || "SAFE").toLowerCase();
        banner.className = "section risk-banner " + risk;

        const colors = { critical:"#fca5a5", high:"#fdba74", medium:"#fde047", low:"#93c5fd", safe:"#86efac" };
        const icons = { critical:"🔴", high:"🟠", medium:"🟡", low:"🔵", safe:"🟢" };
        const msgs = {
            critical: "NGUY HIỂM - Phát hiện nhiều dấu hiệu tấn công DDoS nghiêm trọng!",
            high: "CAO - Phát hiện dấu hiệu tấn công DDoS đáng lo ngại!",
            medium: "TRUNG BÌNH - Phát hiện traffic bất thường, có thể là tấn công DDoS.",
            low: "THẤP - Có một số traffic bất thường nhưng chưa nghiêm trọng.",
            safe: "AN TOÀN - Không phát hiện dấu hiệu tấn công DDoS."
        };

        document.getElementById("risk-icon").textContent = icons[risk] || "🛡️";
        const rl = document.getElementById("risk-level");
        rl.textContent = data.risk_level;
        rl.style.color = colors[risk] || "#fff";
        document.getElementById("risk-desc").textContent = msgs[risk] || "";

        document.getElementById("stat-packets").textContent = (data.capture_info.total_packets || 0).toLocaleString();
        document.getElementById("stat-alerts").textContent = data.total_alerts || 0;

        let attackerCount = 0;
        if (data.attack_summary) {
            const ips = new Set();
            Object.values(data.attack_summary).forEach(s => (s.source_ips || []).forEach(ip => ips.add(ip)));
            attackerCount = ips.size;
        }
        document.getElementById("stat-attackers").textContent = attackerCount;
    }

    // ── Overview Cards ──
    function renderOverviewCards(data) {
        const ci = data.capture_info || {};
        const pr = data.packet_rate || {};
        document.getElementById("card-total-packets").textContent = (ci.total_packets || 0).toLocaleString();
        document.getElementById("card-total-data").textContent = ci.total_bytes_formatted || "0 B";
        document.getElementById("card-avg-pps").textContent = (pr.avg_pps || 0).toLocaleString(undefined,{maximumFractionDigits:1});
        document.getElementById("card-max-pps").textContent = (pr.max_pps || 0).toLocaleString();
        document.getElementById("card-src-ips").textContent = ci.unique_src_ips || 0;
        document.getElementById("card-duration").textContent = (ci.capture_duration_seconds || 0) + "s";
    }

    // ── Protocol Chart ──
    function renderProtocolChart(data) {
        const dist = data.protocol_distribution || {};
        const labels = Object.keys(dist);
        const values = labels.map(l => dist[l].count);
        const colorMap = { TCP:"#06b6d4", UDP:"#a855f7", ICMP:"#f59e0b", HTTP:"#10b981", OTHER:"#64748b" };
        const colors = labels.map(l => colorMap[l] || "#64748b");

        if (protocolChart) protocolChart.destroy();
        protocolChart = new Chart(document.getElementById("protocol-chart"), {
            type: "doughnut",
            data: { labels, datasets: [{ data: values, backgroundColor: colors, borderWidth: 0, hoverOffset: 8 }] },
            options: {
                responsive: true, maintainAspectRatio: false,
                cutout: "65%",
                plugins: {
                    legend: { display: false },
                    tooltip: { callbacks: { label: (ctx) => ` ${ctx.label}: ${ctx.parsed.toLocaleString()} (${dist[ctx.label].percentage}%)` } }
                }
            }
        });

        const legend = document.getElementById("protocol-legend");
        legend.innerHTML = labels.map((l,i) =>
            `<div class="legend-item"><span class="legend-dot" style="background:${colors[i]}"></span>${l}: ${values[i].toLocaleString()} (${dist[l].percentage}%)</div>`
        ).join("");
    }

    // ── Timeline Chart ──
    function renderTimelineChart(data) {
        const timeline = (data.packet_rate || {}).timeline || [];
        if (timelineChart) timelineChart.destroy();
        const labels = timeline.map((_,i) => i + "s");

        timelineChart = new Chart(document.getElementById("timeline-chart"), {
            type: "line",
            data: {
                labels,
                datasets: [{
                    label: "Packets/s",
                    data: timeline,
                    borderColor: "#06b6d4",
                    backgroundColor: "rgba(6,182,212,0.1)",
                    fill: true, tension: 0.3, pointRadius: timeline.length > 60 ? 0 : 2,
                    borderWidth: 2,
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false,
                scales: {
                    x: { grid: { color: "rgba(42,49,85,0.4)" }, ticks: { color: "#64748b", font: { size: 10 }, maxTicksLimit: 20 } },
                    y: { grid: { color: "rgba(42,49,85,0.4)" }, ticks: { color: "#64748b" }, beginAtZero: true }
                },
                plugins: { legend: { display: false } }
            }
        });
    }

    // ── Alerts ──
    function renderAlerts(data) {
        const container = document.getElementById("alerts-container");
        const badge = document.getElementById("alert-count-badge");
        const alerts = data.alerts || [];
        badge.textContent = alerts.length;

        if (alerts.length === 0) {
            badge.style.background = "rgba(22,163,74,0.15)";
            badge.style.color = "#10b981";
            container.innerHTML = `<div class="no-alerts-msg"><div class="msg-icon">✅</div><div class="msg-title">KHÔNG PHÁT HIỆN TẤN CÔNG DDoS</div><div class="msg-desc">Traffic trong ngưỡng bình thường. File pcap này có vẻ an toàn.</div></div>`;
            return;
        }

        const attackNames = { SYN_FLOOD:"SYN Flood (L4)", UDP_FLOOD:"UDP Flood (L4)", ICMP_FLOOD:"ICMP Flood (L3)", HTTP_FLOOD:"HTTP Flood (L7)" };
        const sevIcons = { CRITICAL:"🔴", HIGH:"🟠", MEDIUM:"🟡", LOW:"🔵" };

        let html = `<div class="alerts-table-wrap"><table class="data-table"><thead><tr>
            <th>Severity</th><th>Attack Type</th><th>Source IP</th><th>Time</th><th>Pkts/s</th><th>Threshold</th><th>Ratio</th>
        </tr></thead><tbody>`;

        alerts.slice(0, 50).forEach(a => {
            const sev = (a.severity || "LOW").toLowerCase();
            html += `<tr class="alert-row-${sev}">
                <td><span class="risk-badge ${sev}">${sevIcons[a.severity]||"⚪"} ${a.severity}</span></td>
                <td>${attackNames[a.attack_type]||a.attack_type}</td>
                <td style="color:var(--accent-cyan)">${a.source_ip}</td>
                <td>t=${a.time_slot_second}s</td>
                <td style="font-weight:700">${a.packet_count.toLocaleString()}</td>
                <td>${a.threshold}</td>
                <td><span class="risk-badge ${sev}">${a.ratio}x</span></td>
            </tr>`;
        });
        html += "</tbody></table></div>";
        if (alerts.length > 50) html += `<p style="text-align:center;color:var(--text-dim);margin-top:12px">... và ${alerts.length-50} cảnh báo khác (xem trong report)</p>`;
        container.innerHTML = html;
    }

    // ── Attack Summary ──
    function renderAttackSummary(data) {
        const summary = data.attack_summary || {};
        const section = document.getElementById("attack-summary-section");
        const container = document.getElementById("attack-cards");
        const keys = Object.keys(summary);
        if (keys.length === 0) { section.style.display = "none"; return; }
        section.style.display = "";

        const layers = { SYN_FLOOD:"L4", UDP_FLOOD:"L4", ICMP_FLOOD:"L3", HTTP_FLOOD:"L7" };
        const colors = { SYN_FLOOD:"#ef4444", UDP_FLOOD:"#f97316", ICMP_FLOOD:"#eab308", HTTP_FLOOD:"#a855f7" };
        const icons = { SYN_FLOOD:"🔴", UDP_FLOOD:"🟠", ICMP_FLOOD:"🟡", HTTP_FLOOD:"🟣" };

        container.innerHTML = keys.map(k => {
            const s = summary[k];
            return `<div class="attack-card" style="border-top-color:${colors[k]||'var(--accent-red)'}">
                <div class="attack-card-header">
                    <span style="font-size:1.3rem">${icons[k]||"⚪"}</span>
                    <span class="attack-card-name">${s.display_name||k}</span>
                    <span class="attack-card-layer">${layers[k]||"?"}</span>
                </div>
                <div class="attack-card-stats">
                    <div class="attack-stat"><div class="attack-stat-val">${s.total_alerts}</div><div class="attack-stat-lbl">Alerts</div></div>
                    <div class="attack-stat"><div class="attack-stat-val">${s.unique_source_ips}</div><div class="attack-stat-lbl">IPs</div></div>
                    <div class="attack-stat"><div class="attack-stat-val">${(s.max_packets_per_second||0).toLocaleString()}</div><div class="attack-stat-lbl">Max PPS</div></div>
                    <div class="attack-stat"><div class="attack-stat-val"><span class="risk-badge ${(s.max_severity||'low').toLowerCase()}">${s.max_severity}</span></div><div class="attack-stat-lbl">Severity</div></div>
                </div>
            </div>`;
        }).join("");
    }

    // ── Top IPs ──
    function renderTopIPs(data) {
        const body = document.getElementById("top-ips-body");
        const ips = data.top_source_ips || [];
        body.innerHTML = ips.map((ip,i) => {
            const protoHTML = Object.entries(ip.protocols || {}).map(([p,c]) =>
                `<span class="proto-tag ${p.toLowerCase()}">${p}:${c}</span>`
            ).join("");
            let riskClass = "low", riskText = "LOW";
            if (ip.percentage > 50) { riskClass="critical"; riskText="CRITICAL"; }
            else if (ip.percentage > 25) { riskClass="high"; riskText="HIGH"; }
            else if (ip.percentage > 10) { riskClass="medium"; riskText="MEDIUM"; }
            return `<tr>
                <td style="color:${i<3?'#fbbf24':'var(--text-dim)'};font-weight:${i<3?700:400}">${i+1}</td>
                <td style="color:var(--accent-cyan);font-weight:600">${ip.ip}</td>
                <td>${ip.count.toLocaleString()}</td>
                <td>${ip.percentage}%</td>
                <td>${protoHTML}</td>
                <td><span class="risk-badge ${riskClass}">${riskText}</span></td>
            </tr>`;
        }).join("");
    }

    // ── HTTP Stats ──
    function renderHTTPStats(data) {
        const hs = data.http_stats || {};
        const section = document.getElementById("http-section");
        if (!hs.total_requests || hs.total_requests === 0) { section.style.display = "none"; return; }
        section.style.display = "";

        // Methods chart
        const methods = hs.methods || {};
        const mLabels = Object.keys(methods);
        const mValues = mLabels.map(l => methods[l]);
        const mColors = ["#10b981","#3b82f6","#f59e0b","#ef4444","#a855f7","#ec4899","#06b6d4","#64748b"];
        if (httpChart) httpChart.destroy();
        httpChart = new Chart(document.getElementById("http-methods-chart"), {
            type: "doughnut",
            data: { labels: mLabels, datasets: [{ data: mValues, backgroundColor: mColors.slice(0,mLabels.length), borderWidth: 0 }] },
            options: { responsive:true, maintainAspectRatio:false, cutout:"60%", plugins:{ legend:{ position:"bottom", labels:{ color:"#94a3b8", font:{size:11} } } } }
        });

        // URIs
        const uris = hs.top_uris || [];
        document.getElementById("http-uris-body").innerHTML = uris.map(u =>
            `<tr><td style="color:var(--accent-cyan)">${escapeHtml(u.uri)}</td><td>${u.count.toLocaleString()}</td></tr>`
        ).join("");
    }

    // ── Downloads ──
    function renderDownloads(data) {
        const grid = document.getElementById("download-grid");
        const rf = data.report_files || {};
        let html = "";
        if (rf.json) {
            html += `<a class="download-btn" href="/api/download/${rf.json}" download><span class="dl-icon">📄</span>Full Report<span class="dl-ext">.json</span></a>`;
        }
        (rf.csv || []).forEach(f => {
            let label = "Report";
            if (f.includes("alerts")) label = "Alerts";
            else if (f.includes("top_ips")) label = "Top IPs";
            else if (f.includes("statistics")) label = "Statistics";
            html += `<a class="download-btn" href="/api/download/${f}" download><span class="dl-icon">📊</span>${label}<span class="dl-ext">.csv</span></a>`;
        });
        grid.innerHTML = html;
    }

    // ── Helpers ──
    function formatSize(bytes) {
        const units = ["B","KB","MB","GB"];
        let i = 0;
        while (bytes >= 1024 && i < units.length - 1) { bytes /= 1024; i++; }
        return bytes.toFixed(1) + " " + units[i];
    }
    function escapeHtml(s) {
        const d = document.createElement("div"); d.textContent = s; return d.innerHTML;
    }
});
