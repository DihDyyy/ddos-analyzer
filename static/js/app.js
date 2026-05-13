// ============================================================================
// DDoS Analyzer - Frontend (PCAP + Live Monitor)
// ============================================================================
document.addEventListener("DOMContentLoaded", () => {
    // ── Mode Tabs ──
    const tabs = document.querySelectorAll(".mode-tab");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            tab.classList.add("active");
            document.querySelectorAll(".mode-content").forEach(m => m.classList.remove("active"));
            document.getElementById(tab.dataset.mode + "-mode").classList.add("active");
        });
    });

    // ══════════════════════════════════════
    // PCAP MODE (giữ nguyên logic cũ)
    // ══════════════════════════════════════
    const dropZone = document.getElementById("drop-zone");
    const fileInput = document.getElementById("pcap-file");
    const fileSelected = document.getElementById("file-selected");
    const fileName = document.getElementById("file-name");
    const fileSize = document.getElementById("file-size");
    const fileRemove = document.getElementById("file-remove");
    const form = document.getElementById("upload-form");
    const uploadSection = document.getElementById("upload-section");
    const loadingSection = document.getElementById("loading-section");
    const resultsSection = document.getElementById("results-section");
    const configToggle = document.getElementById("config-toggle");
    const configBody = document.getElementById("config-body");
    const configArrow = document.getElementById("config-arrow");
    const btnNewAnalysis = document.getElementById("btn-new-analysis");
    let selectedFile = null, protocolChart = null, timelineChart = null, httpChart = null;

    dropZone.addEventListener("click", () => fileInput.click());
    dropZone.addEventListener("dragover", e => { e.preventDefault(); dropZone.classList.add("drag-over"); });
    dropZone.addEventListener("dragleave", () => dropZone.classList.remove("drag-over"));
    dropZone.addEventListener("drop", e => { e.preventDefault(); dropZone.classList.remove("drag-over"); if(e.dataTransfer.files.length) handleFileSelect(e.dataTransfer.files[0]); });
    fileInput.addEventListener("change", () => { if(fileInput.files.length) handleFileSelect(fileInput.files[0]); });
    fileRemove.addEventListener("click", e => { e.stopPropagation(); selectedFile=null; fileInput.value=""; fileSelected.style.display="none"; dropZone.querySelector(".drop-zone-content").style.display=""; });
    function handleFileSelect(f) { selectedFile=f; fileName.textContent=f.name; fileSize.textContent=formatSize(f.size); fileSelected.style.display="flex"; dropZone.querySelector(".drop-zone-content").style.display="none"; }
    configToggle.addEventListener("click", () => { configBody.classList.toggle("open"); configArrow.classList.toggle("open"); });

    form.addEventListener("submit", async e => {
        e.preventDefault();
        if(!selectedFile){ alert("Vui lòng chọn file .pcap trước!"); return; }
        const fd = new FormData();
        fd.append("pcap_file", selectedFile);
        ["syn_threshold","udp_threshold","icmp_threshold","http_threshold"].forEach(id => fd.append(id, document.getElementById(id).value));
        uploadSection.style.display="none"; loadingSection.style.display=""; resultsSection.style.display="none";
        try {
            const r = await fetch("/api/analyze", {method:"POST", body:fd});
            const d = await r.json();
            if(!r.ok||d.error){ alert("Lỗi: "+(d.error||"Có lỗi")); uploadSection.style.display=""; loadingSection.style.display="none"; return; }
            loadingSection.style.display="none"; renderResults(d);
        } catch(err){ alert("Lỗi: "+err.message); uploadSection.style.display=""; loadingSection.style.display="none"; }
    });
    btnNewAnalysis.addEventListener("click", () => { resultsSection.style.display="none"; uploadSection.style.display=""; selectedFile=null; fileInput.value=""; fileSelected.style.display="none"; dropZone.querySelector(".drop-zone-content").style.display=""; });

    function renderResults(d) {
        resultsSection.style.display="";
        renderRiskBanner(d); renderOverviewCards(d); renderProtocolChart(d); renderTimelineChart(d);
        renderAlerts(d); renderAttackSummary(d); renderTopIPs(d); renderHTTPStats(d); renderDownloads(d);
        resultsSection.scrollIntoView({behavior:"smooth"});
    }
    function renderRiskBanner(d) {
        const b=document.getElementById("risk-banner"), r=(d.risk_level||"SAFE").toLowerCase();
        b.className="section risk-banner "+r;
        const icons={critical:"🔴",high:"🟠",medium:"🟡",low:"🔵",safe:"🟢"};
        const msgs={critical:"NGUY HIỂM - Phát hiện tấn công DDoS nghiêm trọng!",high:"CAO - Phát hiện tấn công đáng lo ngại!",medium:"TRUNG BÌNH - Traffic bất thường.",low:"THẤP - Một số bất thường nhẹ.",safe:"AN TOÀN - Không phát hiện tấn công."};
        document.getElementById("risk-icon").textContent=icons[r]||"🛡️";
        const rl=document.getElementById("risk-level"); rl.textContent=d.risk_level;
        document.getElementById("risk-desc").textContent=msgs[r]||"";
        document.getElementById("stat-packets").textContent=(d.capture_info.total_packets||0).toLocaleString();
        document.getElementById("stat-alerts").textContent=d.total_alerts||0;
        let ac=0; if(d.attack_summary){const s=new Set(); Object.values(d.attack_summary).forEach(x=>(x.source_ips||[]).forEach(ip=>s.add(ip))); ac=s.size;} document.getElementById("stat-attackers").textContent=ac;
    }
    function renderOverviewCards(d) {
        const ci=d.capture_info||{}, pr=d.packet_rate||{};
        document.getElementById("card-total-packets").textContent=(ci.total_packets||0).toLocaleString();
        document.getElementById("card-total-data").textContent=ci.total_bytes_formatted||"0 B";
        document.getElementById("card-avg-pps").textContent=(pr.avg_pps||0).toLocaleString(undefined,{maximumFractionDigits:1});
        document.getElementById("card-max-pps").textContent=(pr.max_pps||0).toLocaleString();
        document.getElementById("card-src-ips").textContent=ci.unique_src_ips||0;
        document.getElementById("card-duration").textContent=(ci.capture_duration_seconds||0)+"s";
    }
    function renderProtocolChart(d) {
        const dist=d.protocol_distribution||{}, labels=Object.keys(dist), values=labels.map(l=>dist[l].count);
        const cm={TCP:"#06b6d4",UDP:"#a855f7",ICMP:"#f59e0b",HTTP:"#10b981",OTHER:"#64748b"}, colors=labels.map(l=>cm[l]||"#64748b");
        if(protocolChart) protocolChart.destroy();
        protocolChart=new Chart(document.getElementById("protocol-chart"),{type:"doughnut",data:{labels,datasets:[{data:values,backgroundColor:colors,borderWidth:0,hoverOffset:8}]},options:{responsive:true,maintainAspectRatio:false,cutout:"65%",plugins:{legend:{display:false}}}});
        document.getElementById("protocol-legend").innerHTML=labels.map((l,i)=>`<div class="legend-item"><span class="legend-dot" style="background:${colors[i]}"></span>${l}: ${values[i].toLocaleString()} (${dist[l].percentage}%)</div>`).join("");
    }
    function renderTimelineChart(d) {
        const tl=(d.packet_rate||{}).timeline||[]; if(timelineChart) timelineChart.destroy();
        timelineChart=new Chart(document.getElementById("timeline-chart"),{type:"line",data:{labels:tl.map((_,i)=>i+"s"),datasets:[{label:"Packets/s",data:tl,borderColor:"#06b6d4",backgroundColor:"rgba(6,182,212,0.1)",fill:true,tension:0.3,pointRadius:tl.length>60?0:2,borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,scales:{x:{grid:{color:"rgba(42,49,85,0.4)"},ticks:{color:"#64748b",font:{size:10},maxTicksLimit:20}},y:{grid:{color:"rgba(42,49,85,0.4)"},ticks:{color:"#64748b"},beginAtZero:true}},plugins:{legend:{display:false}}}});
    }
    function renderAlerts(d) {
        const c=document.getElementById("alerts-container"), badge=document.getElementById("alert-count-badge"), alerts=d.alerts||[];
        badge.textContent=alerts.length;
        if(!alerts.length){ badge.style.background="rgba(22,163,74,0.15)"; badge.style.color="#10b981"; c.innerHTML=`<div class="no-alerts-msg"><div class="msg-icon">✅</div><div class="msg-title">KHÔNG PHÁT HIỆN TẤN CÔNG</div><div class="msg-desc">Traffic bình thường.</div></div>`; return; }
        const an={SYN_FLOOD:"SYN Flood (L4)",UDP_FLOOD:"UDP Flood (L4)",ICMP_FLOOD:"ICMP Flood (L3)",HTTP_FLOOD:"HTTP Flood (L7)"};
        const si={CRITICAL:"🔴",HIGH:"🟠",MEDIUM:"🟡",LOW:"🔵"};
        let h=`<div class="alerts-table-wrap"><table class="data-table"><thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Time</th><th>Pkts/s</th><th>Threshold</th><th>Ratio</th></tr></thead><tbody>`;
        alerts.slice(0,50).forEach(a=>{const s=(a.severity||"LOW").toLowerCase(); h+=`<tr class="alert-row-${s}"><td><span class="risk-badge ${s}">${si[a.severity]||"⚪"} ${a.severity}</span></td><td>${an[a.attack_type]||a.attack_type}</td><td style="color:var(--accent-cyan)">${a.source_ip}</td><td>t=${a.time_slot_second}s</td><td style="font-weight:700">${a.packet_count.toLocaleString()}</td><td>${a.threshold}</td><td><span class="risk-badge ${s}">${a.ratio}x</span></td></tr>`;});
        h+="</tbody></table></div>"; c.innerHTML=h;
    }
    function renderAttackSummary(d) {
        const sum=d.attack_summary||{}, sec=document.getElementById("attack-summary-section"), con=document.getElementById("attack-cards"), keys=Object.keys(sum);
        if(!keys.length){sec.style.display="none";return;} sec.style.display="";
        const colors={SYN_FLOOD:"#ef4444",UDP_FLOOD:"#f97316",ICMP_FLOOD:"#eab308",HTTP_FLOOD:"#a855f7"}, icons={SYN_FLOOD:"🔴",UDP_FLOOD:"🟠",ICMP_FLOOD:"🟡",HTTP_FLOOD:"🟣"}, layers={SYN_FLOOD:"L4",UDP_FLOOD:"L4",ICMP_FLOOD:"L3",HTTP_FLOOD:"L7"};
        con.innerHTML=keys.map(k=>{const s=sum[k]; return `<div class="attack-card" style="border-top-color:${colors[k]}"><div class="attack-card-header"><span style="font-size:1.3rem">${icons[k]||"⚪"}</span><span class="attack-card-name">${s.display_name||k}</span><span class="attack-card-layer">${layers[k]}</span></div><div class="attack-card-stats"><div class="attack-stat"><div class="attack-stat-val">${s.total_alerts}</div><div class="attack-stat-lbl">Alerts</div></div><div class="attack-stat"><div class="attack-stat-val">${s.unique_source_ips}</div><div class="attack-stat-lbl">IPs</div></div><div class="attack-stat"><div class="attack-stat-val">${(s.max_packets_per_second||0).toLocaleString()}</div><div class="attack-stat-lbl">Max PPS</div></div><div class="attack-stat"><div class="attack-stat-val"><span class="risk-badge ${(s.max_severity||'low').toLowerCase()}">${s.max_severity}</span></div><div class="attack-stat-lbl">Severity</div></div></div></div>`;}).join("");
    }
    function renderTopIPs(d) {
        const body=document.getElementById("top-ips-body"), ips=d.top_source_ips||[];
        body.innerHTML=ips.map((ip,i)=>{const ph=Object.entries(ip.protocols||{}).map(([p,c])=>`<span class="proto-tag ${p.toLowerCase()}">${p}:${c}</span>`).join(""); let rc="low",rt="LOW"; if(ip.percentage>50){rc="critical";rt="CRITICAL";}else if(ip.percentage>25){rc="high";rt="HIGH";}else if(ip.percentage>10){rc="medium";rt="MEDIUM";} return `<tr><td style="color:${i<3?'#fbbf24':'var(--text-dim)'}">${i+1}</td><td style="color:var(--accent-cyan);font-weight:600">${ip.ip}</td><td>${ip.count.toLocaleString()}</td><td>${ip.percentage}%</td><td>${ph}</td><td><span class="risk-badge ${rc}">${rt}</span></td></tr>`;}).join("");
    }
    function renderHTTPStats(d) {
        const hs=d.http_stats||{}, sec=document.getElementById("http-section");
        if(!hs.total_requests){sec.style.display="none";return;} sec.style.display="";
        const m=hs.methods||{}, ml=Object.keys(m), mv=ml.map(l=>m[l]), mc=["#10b981","#3b82f6","#f59e0b","#ef4444","#a855f7","#ec4899"];
        if(httpChart) httpChart.destroy();
        httpChart=new Chart(document.getElementById("http-methods-chart"),{type:"doughnut",data:{labels:ml,datasets:[{data:mv,backgroundColor:mc.slice(0,ml.length),borderWidth:0}]},options:{responsive:true,maintainAspectRatio:false,cutout:"60%",plugins:{legend:{position:"bottom",labels:{color:"#94a3b8"}}}}});
        document.getElementById("http-uris-body").innerHTML=(hs.top_uris||[]).map(u=>`<tr><td style="color:var(--accent-cyan)">${escapeHtml(u.uri)}</td><td>${u.count.toLocaleString()}</td></tr>`).join("");
    }
    function renderDownloads(d) {
        const g=document.getElementById("download-grid"), rf=d.report_files||{}; let h="";
        if(rf.json) h+=`<a class="download-btn" href="/api/download/${rf.json}" download><span class="dl-icon">📄</span>Full Report<span class="dl-ext">.json</span></a>`;
        (rf.csv||[]).forEach(f=>{let l="Report"; if(f.includes("alerts"))l="Alerts"; else if(f.includes("top_ips"))l="Top IPs"; else if(f.includes("statistics"))l="Statistics"; h+=`<a class="download-btn" href="/api/download/${f}" download><span class="dl-icon">📊</span>${l}<span class="dl-ext">.csv</span></a>`;});
        g.innerHTML=h;
    }

    // ══════════════════════════════════════
    // LIVE MONITOR MODE
    // ══════════════════════════════════════
    let liveInterval = null;
    let liveProtoChart = null, liveTimeChart = null;
    const btnStart = document.getElementById("btn-live-start");
    const btnStop = document.getElementById("btn-live-stop");

    // Load interfaces
    async function loadInterfaces() {
        try {
            const r = await fetch("/api/live/interfaces");
            const d = await r.json();
            const sel = document.getElementById("live-interface");
            sel.innerHTML = '<option value="">Tự động (mặc định)</option>';
            (d.interfaces || []).forEach(iface => {
                sel.innerHTML += `<option value="${iface}">${iface}</option>`;
            });
        } catch(e) { console.error("Load interfaces:", e); }
    }
    loadInterfaces();
    document.getElementById("btn-refresh-iface").addEventListener("click", loadInterfaces);

    btnStart.addEventListener("click", async () => {
        const iface = document.getElementById("live-interface").value;
        const body = { interface: iface || null,
            syn_threshold: parseInt(document.getElementById("live-syn").value),
            udp_threshold: parseInt(document.getElementById("live-udp").value),
            icmp_threshold: parseInt(document.getElementById("live-icmp").value),
            http_threshold: parseInt(document.getElementById("live-http").value),
        };
        try {
            const r = await fetch("/api/live/start", { method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify(body) });
            const d = await r.json();
            if (d.error) { alert("Lỗi: " + d.error); return; }
            btnStart.style.display = "none"; btnStop.style.display = "";
            document.getElementById("live-placeholder").style.display = "none";
            ["live-status-section","live-risk-banner","live-cards-section","live-charts-section","live-alerts-section","live-packets-section","live-top-ips-section"].forEach(id => document.getElementById(id).style.display = "");
            document.getElementById("live-iface-name").textContent = d.interface || "default";
            document.getElementById("tab-live-badge").style.display = "";
            document.getElementById("header-status-text").textContent = "Live Monitoring";
            document.getElementById("header-status-dot").style.background = "#ef4444";
            liveInterval = setInterval(fetchLiveData, 1500);
            fetchLiveData();
        } catch(e) { alert("Lỗi kết nối: " + e.message); }
    });

    btnStop.addEventListener("click", async () => {
        try { await fetch("/api/live/stop", {method:"POST"}); } catch(e) {}
        clearInterval(liveInterval); liveInterval = null;
        btnStart.style.display = ""; btnStop.style.display = "none";
        document.getElementById("tab-live-badge").style.display = "none";
        document.getElementById("header-status-text").textContent = "System Online";
        document.getElementById("header-status-dot").style.background = "var(--accent-green)";
    });

    async function fetchLiveData() {
        try {
            const r = await fetch("/api/live/data");
            const d = await r.json();
            if (!d.is_running && !d.total_packets) return;
            updateLiveDashboard(d);
        } catch(e) { console.error("Live data error:", e); }
    }

    function updateLiveDashboard(d) {
        // Elapsed
        const el = Math.round(d.elapsed_seconds || 0);
        const mm = Math.floor(el/60), ss = el%60;
        const elStr = mm > 0 ? `${mm}m ${ss}s` : `${ss}s`;
        document.getElementById("live-elapsed").textContent = elStr;
        document.getElementById("live-card-elapsed").textContent = elStr;

        // Cards
        document.getElementById("live-card-packets").textContent = (d.total_packets||0).toLocaleString();
        document.getElementById("live-card-data").textContent = d.total_bytes_formatted || "0 B";
        document.getElementById("live-card-avg-pps").textContent = d.avg_pps || 0;
        document.getElementById("live-card-max-pps").textContent = d.max_pps || 0;
        document.getElementById("live-card-ips").textContent = d.unique_src_ips || 0;

        // Risk banner
        const risk = (d.risk_level||"SAFE").toLowerCase();
        const rb = document.getElementById("live-risk-banner");
        rb.className = "section risk-banner " + risk;
        const icons = {critical:"🔴",high:"🟠",medium:"🟡",low:"🔵",safe:"🟢"};
        const msgs = {critical:"NGUY HIỂM - Đang bị tấn công DDoS!",high:"CAO - Phát hiện tấn công!",medium:"TRUNG BÌNH - Traffic bất thường.",low:"THẤP - Bất thường nhẹ.",safe:"AN TOÀN - Mạng bình thường."};
        document.getElementById("live-risk-icon").textContent = icons[risk]||"🟢";
        document.getElementById("live-risk-level").textContent = d.risk_level;
        document.getElementById("live-risk-desc").textContent = msgs[risk]||"";
        document.getElementById("live-stat-packets").textContent = (d.total_packets||0).toLocaleString();
        document.getElementById("live-stat-pps").textContent = d.current_pps || 0;
        document.getElementById("live-stat-alerts").textContent = d.total_alerts || 0;
        document.getElementById("live-stat-ips").textContent = d.unique_src_ips || 0;

        // Protocol chart
        updateLiveProtocolChart(d.protocol_distribution || {});

        // Timeline chart
        updateLiveTimelineChart(d.pps_timeline || []);

        // Alerts
        updateLiveAlerts(d.alerts || [], d.total_alerts || 0);

        // Recent packets
        updateLivePackets(d.recent_packets || []);

        // Top IPs
        updateLiveTopIPs(d.top_source_ips || []);
    }

    function updateLiveProtocolChart(dist) {
        const labels = Object.keys(dist), values = labels.map(l => dist[l].count);
        const cm = {TCP:"#06b6d4",UDP:"#a855f7",ICMP:"#f59e0b",HTTP:"#10b981",OTHER:"#64748b"};
        const colors = labels.map(l => cm[l]||"#64748b");
        if (liveProtoChart) {
            liveProtoChart.data.labels = labels;
            liveProtoChart.data.datasets[0].data = values;
            liveProtoChart.data.datasets[0].backgroundColor = colors;
            liveProtoChart.update("none");
        } else if (labels.length) {
            liveProtoChart = new Chart(document.getElementById("live-protocol-chart"), {
                type:"doughnut", data:{labels,datasets:[{data:values,backgroundColor:colors,borderWidth:0}]},
                options:{responsive:true,maintainAspectRatio:false,cutout:"65%",plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>` ${ctx.label}: ${ctx.parsed.toLocaleString()}`}}},animation:{duration:0}}
            });
        }
        const leg = document.getElementById("live-protocol-legend");
        leg.innerHTML = labels.map((l,i) => `<div class="legend-item"><span class="legend-dot" style="background:${colors[i]}"></span>${l}: ${values[i].toLocaleString()} (${dist[l].percentage}%)</div>`).join("");
    }

    function updateLiveTimelineChart(tl) {
        const labels = tl.map((_,i) => (tl.length - i) + "");
        labels.reverse();
        if (liveTimeChart) {
            liveTimeChart.data.labels = labels;
            liveTimeChart.data.datasets[0].data = tl;
            liveTimeChart.update("none");
        } else if (tl.length) {
            liveTimeChart = new Chart(document.getElementById("live-timeline-chart"), {
                type:"line", data:{labels,datasets:[{label:"PPS",data:tl,borderColor:"#ef4444",backgroundColor:"rgba(239,68,68,0.1)",fill:true,tension:0.3,pointRadius:0,borderWidth:2}]},
                options:{responsive:true,maintainAspectRatio:false,animation:{duration:0},scales:{x:{grid:{color:"rgba(42,49,85,0.4)"},ticks:{color:"#64748b",font:{size:10},maxTicksLimit:15},title:{display:true,text:"giây trước",color:"#64748b"}},y:{grid:{color:"rgba(42,49,85,0.4)"},ticks:{color:"#64748b"},beginAtZero:true}},plugins:{legend:{display:false}}}
            });
        }
    }

    function updateLiveAlerts(alerts, total) {
        const badge = document.getElementById("live-alert-count");
        badge.textContent = total;
        const c = document.getElementById("live-alerts-container");
        if (!alerts.length) {
            badge.style.background="rgba(22,163,74,0.15)"; badge.style.color="#10b981";
            c.innerHTML = `<div class="no-alerts-msg"><div class="msg-icon">✅</div><div class="msg-title">CHƯA PHÁT HIỆN TẤN CÔNG</div><div class="msg-desc">Đang giám sát...</div></div>`;
            return;
        }
        badge.style.background="rgba(239,68,68,0.15)"; badge.style.color="#ef4444";
        const an={SYN_FLOOD:"SYN Flood",UDP_FLOOD:"UDP Flood",ICMP_FLOOD:"ICMP Flood",HTTP_FLOOD:"HTTP Flood"};
        const si={CRITICAL:"🔴",HIGH:"🟠",MEDIUM:"🟡",LOW:"🔵"};
        let h = `<div class="alerts-table-wrap"><table class="data-table"><thead><tr><th>Time</th><th>Severity</th><th>Type</th><th>Source IP</th><th>Pkts/s</th><th>Ratio</th></tr></thead><tbody>`;
        [...alerts].reverse().forEach(a => {
            const s = (a.severity||"LOW").toLowerCase();
            h += `<tr class="alert-row-${s}"><td>${a.time}</td><td><span class="risk-badge ${s}">${si[a.severity]||"⚪"} ${a.severity}</span></td><td>${an[a.attack_type]||a.attack_type}</td><td style="color:var(--accent-cyan)">${a.source_ip}</td><td style="font-weight:700">${a.packet_count}</td><td><span class="risk-badge ${s}">${a.ratio}x</span></td></tr>`;
        });
        h += "</tbody></table></div>"; c.innerHTML = h;
    }

    function updateLivePackets(pkts) {
        const body = document.getElementById("live-packets-body");
        body.innerHTML = [...pkts].reverse().map(p => {
            const pc = {TCP:"var(--accent-cyan)",UDP:"var(--accent-purple)",ICMP:"var(--accent-yellow)"}[p.proto] || "var(--text-dim)";
            return `<tr><td>${p.time}</td><td style="color:var(--accent-cyan)">${p.src}</td><td>${p.dst}</td><td><span class="proto-tag ${p.proto.toLowerCase()}">${p.proto}</span></td><td>${p.size}</td><td>${p.dport||"-"}</td><td style="color:var(--accent-yellow)">${p.info||""}</td></tr>`;
        }).join("");
    }

    function updateLiveTopIPs(ips) {
        const body = document.getElementById("live-top-ips-body");
        body.innerHTML = ips.map((ip,i) => {
            const ph = Object.entries(ip.protocols||{}).map(([p,c])=>`<span class="proto-tag ${p.toLowerCase()}">${p}:${c}</span>`).join("");
            return `<tr><td style="color:${i<3?'#fbbf24':'var(--text-dim)'}">${i+1}</td><td style="color:var(--accent-cyan);font-weight:600">${ip.ip}</td><td>${ip.count.toLocaleString()}</td><td>${ip.percentage}%</td><td>${ph}</td></tr>`;
        }).join("");
    }

    // ── Helpers ──
    function formatSize(b) { const u=["B","KB","MB","GB"]; let i=0; while(b>=1024&&i<u.length-1){b/=1024;i++;} return b.toFixed(1)+" "+u[i]; }
    function escapeHtml(s) { const d=document.createElement("div"); d.textContent=s; return d.innerHTML; }
});
