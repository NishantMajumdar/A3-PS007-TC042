/**
 * app.js - PS-007 2016-Era Light Web Dashboard Controller
 *
 * Design Constraints:
 *   - Light utilitarian design (2016 enterprise aesthetic).
 *   - No gradients, no rounded corners, no mouse animations.
 *   - Background: Pure White (#ffffff), Accent: #2d2f4d.
 *   - 5 dedicated views driven strictly by sidebar navigation:
 *       1- list clients
 *       2- network map
 *       3- attack logs
 *       4- live logs
 *       5- ip rotation history
 */

document.addEventListener("DOMContentLoaded", () => {
    // ==========================================================================
    // 1. STATE & REFERENCES
    // ==========================================================================
    const topology = new NetworkTopologyVisualizer("topologyCanvas");

    let ws = null;
    let sseSource = null;
    let wsConnected = false;
    let currentSessions = [];
    let liveLogCount = 0;
    const MAX_LIVE_LOGS = 300;

    // View Mapping: sidebar data-view -> DOM element id
    const VALID_VIEWS = [
        "view-clients",
        "view-map",
        "view-attacks",
        "view-logs",
        "view-rotations"
    ];

    // ==========================================================================
    // 2. SIDEBAR TAB NAVIGATION (5 DEDICATED PAGES)
    // ==========================================================================
    function switchView(viewId) {
        if (!VALID_VIEWS.includes(viewId)) {
            viewId = "view-clients";
        }

        // 1. Update sidebar active state
        const navItems = document.querySelectorAll(".sidebar-nav li");
        navItems.forEach((li) => {
            if (li.getAttribute("data-view") === viewId) {
                li.classList.add("active");
            } else {
                li.classList.remove("active");
            }
        });

        // 2. Update page view visibility
        const pageViews = document.querySelectorAll(".page-view");
        pageViews.forEach((page) => {
            if (page.id === viewId) {
                page.classList.add("active");
            } else {
                page.classList.remove("active");
            }
        });

        // 3. Update URL hash without scroll jump
        if (window.location.hash !== `#${viewId}`) {
            history.replaceState(null, "", `#${viewId}`);
        }

        // 4. Special handling for Network Map canvas
        if (viewId === "view-map") {
            // Give browser 20ms to apply display: block layout before recalculating canvas size
            setTimeout(() => {
                if (topology && typeof topology._initCanvas === "function") {
                    topology._initCanvas();
                }
            }, 30);
        }
    }

    // Attach click listeners to sidebar links
    const sidebarLinks = document.querySelectorAll(".sidebar-nav li a");
    sidebarLinks.forEach((link) => {
        link.addEventListener("click", (e) => {
            e.preventDefault();
            const parentLi = link.closest("li");
            const targetView = parentLi ? parentLi.getAttribute("data-view") : null;
            if (targetView) {
                switchView(targetView);
            }
        });
    });

    // Handle back/forward navigation or initial URL hash
    window.addEventListener("hashchange", () => {
        const hash = window.location.hash.replace("#", "");
        if (hash) {
            switchView(hash);
        }
    });

    // Initialize initial view from hash or default to view-clients
    const initialHash = window.location.hash.replace("#", "");
    if (VALID_VIEWS.includes(initialHash)) {
        switchView(initialHash);
    } else {
        switchView("view-clients");
    }

    // ==========================================================================
    // 3. WEBSOCKET & SSE LIVE STREAM
    // ==========================================================================
    function connectLiveStream() {
        const wsHost = window.location.hostname || "localhost";
        const wsUrl = `ws://${wsHost}:8765`;

        try {
            ws = new WebSocket(wsUrl);

            ws.onopen = () => {
                wsConnected = true;
                updateWsStatus(true, "WS: LIVE (:8765)");
            };

            ws.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleLiveEvent(data);
                } catch (err) {
                    console.error("Failed to parse WS payload:", err);
                }
            };

            ws.onerror = () => {
                if (!wsConnected) fallbackToSSE();
            };

            ws.onclose = () => {
                if (wsConnected) {
                    wsConnected = false;
                    updateWsStatus(false, "RECONNECTING...");
                    setTimeout(connectLiveStream, 3000);
                } else {
                    fallbackToSSE();
                }
            };
        } catch (e) {
            fallbackToSSE();
        }
    }

    function fallbackToSSE() {
        if (sseSource) return;

        try {
            sseSource = new EventSource("/api/stream");
            sseSource.onopen = () => {
                updateWsStatus(true, "STREAM: LIVE");
            };
            sseSource.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    if (data.type !== "heartbeat" && data.type !== "connected") {
                        handleLiveEvent(data);
                    }
                } catch (err) {}
            };
            sseSource.onerror = () => {
                updateWsStatus(false, "RECONNECTING...");
            };
        } catch (err) {
            updateWsStatus(false, "STREAM: OFFLINE");
        }
    }

    function updateWsStatus(connected, label) {
        const dot = document.getElementById("wsStatusDot");
        const txt = document.getElementById("wsStatusText");
        if (dot && txt) {
            dot.className = connected ? "status-dot" : "status-dot offline";
            txt.textContent = label || (connected ? "STREAM: LIVE" : "OFFLINE");
            txt.style.color = connected ? "#a5d6a7" : "#ef9a9a";
        }
    }

    // ==========================================================================
    // 4. LIVE EVENT HANDLER (WebSocket / SSE Push)
    // ==========================================================================
    function handleLiveEvent(evt) {
        const now = new Date();
        const timeStr = now.toTimeString().split(" ")[0];
        const type = (evt.type || "EVENT").toUpperCase();

        if (type === "BIND_DAD" || type === "BIND") {
            const sid = evt.session_id || "UNKNOWN";
            const pseudo = evt.pseudonym || "NEW_CLIENT";
            const addr = evt.addr || evt.target || "N/A";
            topology.triggerPacketFlow(sid, "s1", "#2e7d32");
            appendConsoleLog(timeStr, "BIND_DAD", `DAD Bind: Anchor ${sid} -> ${pseudo} (${addr})`, "badge-green");
        } else if (type === "ROTATION") {
            const sid = evt.session_id || "UNKNOWN";
            const pseudo = evt.pseudonym || sid;
            const newIp = evt.new_ip || evt.addr || "N/A";
            topology.triggerPacketFlow(sid, "s1", "#6a1b9a");
            appendConsoleLog(timeStr, "ROTATION", `RFC 8981 Rotation: P=${pseudo} -> ${newIp}`, "badge-purple");
        } else if (type === "ALERT") {
            const sid = (evt.evidence && evt.evidence.session_id) || evt.pseudonym || "UNKNOWN";
            topology.markDeviceAsRogue(sid, evt.pseudonym);
            topology.triggerPacketFlow(sid, "s1", "#c62828");
            const alertType = evt.alert_type || "SECURITY_ALERT";
            const desc = evt.description || "Violation detected";
            appendConsoleLog(timeStr, "ALERT", `[${evt.severity || 'CRITICAL'}] ${alertType}: ${desc}`, "badge-red");
        } else if (type === "EXPIRY") {
            appendConsoleLog(timeStr, "EXPIRY", `Session expired: ${evt.session_id} (P=${evt.pseudonym})`, "badge-amber");
        } else {
            appendConsoleLog(timeStr, type, JSON.stringify(evt), "badge-accent");
        }

        // Trigger immediate state sync to update counters and tables
        fetchState();
    }

    // ==========================================================================
    // 5. PERIODIC SNAPSHOT SYNCHRONIZATION (GET /api/state)
    // ==========================================================================
    function fetchState() {
        fetch("/api/state")
            .then((res) => res.json())
            .then((json) => {
                if (json.status === "ok" && json.data) {
                    renderDashboard(json.data);
                }
            })
            .catch((err) => {
                console.error("Error synchronizing state snapshot:", err);
            });
    }

    function renderDashboard(data) {
        // ----------------------------------------------------------------------
        // A. Sidebar Footer Telemetry
        // ----------------------------------------------------------------------
        const uptimeEl = document.getElementById("uptimeVal");
        const totalPktsEl = document.getElementById("totalPktsVal");
        const totalRotEl = document.getElementById("totalRotVal");
        const deviceCountsEl = document.getElementById("deviceCounts");
        const epochProgressBar = document.getElementById("epochProgressBar");
        const epochTimerText = document.getElementById("epochTimerText");

        if (uptimeEl) uptimeEl.textContent = data.uptime || "00:00:00";
        if (totalPktsEl) totalPktsEl.textContent = (data.total_sniffed_raw || 0).toLocaleString();
        if (totalRotEl) totalRotEl.textContent = `${data.total_rotations || 0}x`;

        // Filter client sessions: exclude gateway / Port 1
        currentSessions = (data.sessions || []).filter(
            (s) => s.session_id && s.session_id !== "SES-PORT01" && s.session_id !== "GATEWAY" && s.session_id !== "r1"
        );

        const clientCount = currentSessions.length;
        const totalMonitored = (data.router ? 1 : 0) + clientCount + (data.unauthenticated ? data.unauthenticated.length : 0);
        if (deviceCountsEl) {
            deviceCountsEl.textContent = `${totalMonitored} Nodes (${data.auth_count || clientCount} Auth)`;
        }

        // Epoch timer bar
        const epochLen = data.epoch_length || 300;
        const epochRem = Math.max(0, data.epoch_remaining !== undefined ? data.epoch_remaining : 300);
        const epochPct = Math.max(0, Math.min(100, (epochRem / epochLen) * 100));
        if (epochProgressBar) epochProgressBar.style.width = `${epochPct}%`;
        if (epochTimerText) epochTimerText.textContent = `${Math.floor(epochRem)}s rem`;

        // Sidebar Badges
        const sidebarClientCount = document.getElementById("sidebarClientCount");
        if (sidebarClientCount) sidebarClientCount.textContent = clientCount;

        const sidebarRotCount = document.getElementById("sidebarRotCount");
        if (sidebarRotCount) sidebarRotCount.textContent = `${data.total_rotations || 0}x`;

        const alerts = data.alerts || [];
        const sidebarAttackCount = document.getElementById("sidebarAttackCount");
        if (sidebarAttackCount) {
            sidebarAttackCount.textContent = alerts.length;
            if (alerts.length > 0) {
                sidebarAttackCount.classList.add("badge-alert");
            } else {
                sidebarAttackCount.classList.remove("badge-alert");
            }
        }

        // ----------------------------------------------------------------------
        // B. Page 1: List Monitored Clients (#view-clients)
        // ----------------------------------------------------------------------
        renderClientsView(data, currentSessions);

        // ----------------------------------------------------------------------
        // C. Page 2: Network Topology Map (#view-map)
        // ----------------------------------------------------------------------
        topology.syncDiscoveredSessions(currentSessions);
        // Ensure all alerted offenders stay flagged as red rogue nodes
        for (const a of alerts) {
            const sid = (a.evidence && a.evidence.session_id) || a.pseudonym;
            if (sid) {
                topology.markDeviceAsRogue(sid, a.pseudonym);
            }
        }

        // ----------------------------------------------------------------------
        // D. Page 3: Security Attack Logs (#view-attacks)
        // ----------------------------------------------------------------------
        renderAttacksView(alerts);

        // ----------------------------------------------------------------------
        // E. Page 5: IP Rotation History (#view-rotations)
        // ----------------------------------------------------------------------
        renderRotationsView(currentSessions);
    }

    // ==========================================================================
    // 6. VIEW 1: LIST CLIENTS RENDERING
    // ==========================================================================
    function renderClientsView(data, sessions) {
        // Stats bar
        const statTotalNodes = document.getElementById("statTotalNodes");
        const statAuthNodes = document.getElementById("statAuthNodes");
        const statRogueNodes = document.getElementById("statRogueNodes");
        const statTotalRots = document.getElementById("statTotalRots");

        const unauths = data.unauthenticated || [];
        const totalNodes = (data.router ? 1 : 0) + sessions.length + unauths.length;
        const rogueCount = sessions.filter((s) => s.is_rogue || (s.status && s.status.includes("ROGUE"))).length +
            unauths.filter((u) => u.is_rogue || (u.status && u.status.includes("ROGUE"))).length;
        const authCount = sessions.filter((s) => !s.is_rogue && (!s.status || !s.status.includes("ROGUE"))).length;

        if (statTotalNodes) statTotalNodes.textContent = totalNodes;
        if (statAuthNodes) statAuthNodes.textContent = authCount;
        if (statRogueNodes) statRogueNodes.textContent = rogueCount;
        if (statTotalRots) statTotalRots.textContent = `${data.total_rotations || 0}x`;

        // Table
        const tbody = document.getElementById("devicesTableBody");
        if (!tbody) return;
        tbody.innerHTML = "";

        // Row 1: Fixed Infrastructure Gateway (Port 1)
        if (data.router) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td><span class="badge badge-accent">Gateway</span></td>
                <td><span class="badge badge-green">ROUTER</span></td>
                <td><code>INFRASTRUCTURE</code></td>
                <td><code style="font-weight: 700; color: #1565c0;">${data.router.active_ip || "fd00:abcd::1"}</code></td>
                <td><span class="badge">0x</span></td>
                <td>${data.router.pkts || 0}</td>
                <td>Port 1 (wire: 5)</td>
            `;
            tbody.appendChild(tr);
        }

        // Empty state for IoT devices
        if (sessions.length === 0 && unauths.length === 0) {
            const tr = document.createElement("tr");
            tr.innerHTML = `
                <td colspan="7" style="text-align: center; color: var(--text-dim); padding: 25px;">
                    Waiting for IoT client devices (identifying dynamically via RFC 4862 DAD)...
                </td>
            `;
            tbody.appendChild(tr);
            return;
        }

        // Discovered IoT Sessions
        for (const s of sessions) {
            const tr = document.createElement("tr");
            const isRogue = s.is_rogue || (s.status && s.status.includes("ROGUE"));
            const pseudo = s.pseudonym || s.session_id;

            let statusBadge = '<span class="badge badge-green">ACTIVE</span>';
            let roleBadge = '<span class="badge badge-accent">IoT Device</span>';
            let pseudoColor = "var(--text-main)";

            if (isRogue) {
                tr.className = "row-danger";
                statusBadge = '<span class="badge badge-red">ROGUE ATTACKER</span>';
                roleBadge = '<span class="badge badge-red">Rogue Attacker</span>';
                pseudoColor = "#c62828";
            } else if (s.status === "IDLE") {
                statusBadge = '<span class="badge badge-amber">IDLE</span>';
            }

            tr.innerHTML = `
                <td>${roleBadge}</td>
                <td>${statusBadge}</td>
                <td><code style="font-weight: 700; color: ${pseudoColor};">${pseudo}</code></td>
                <td><code style="color: ${isRogue ? '#c62828' : '#2e7d32'}; font-weight: 600;">${s.active_ip || "Tentative"}</code></td>
                <td><span class="badge badge-purple">${s.rotations || 0}x</span></td>
                <td>${s.pkts || 0}</td>
                <td><code>${s.session_id}</code></td>
            `;
            tbody.appendChild(tr);
        }

        // Unauthenticated records (if any)
        for (const u of unauths) {
            const tr = document.createElement("tr");
            const isRogue = u.is_rogue || (u.status && (u.status.includes("ROGUE") || u.status.includes("FAIL")));
            if (isRogue) tr.className = "row-danger";

            tr.innerHTML = `
                <td><span class="badge ${isRogue ? 'badge-red' : 'badge-amber'}">Unauthenticated</span></td>
                <td><span class="badge ${isRogue ? 'badge-red' : 'badge-amber'}">${u.status || "UNAUTH"}</span></td>
                <td><code style="color: var(--text-dim);">---</code></td>
                <td><code style="color: #e65100;">${u.active_ip || "N/A"}</code></td>
                <td><span class="badge">0x</span></td>
                <td>${u.pkts || 0}</td>
                <td><code>${u.session_id || "---"}</code></td>
            `;
            tbody.appendChild(tr);
        }
    }

    // ==========================================================================
    // 7. VIEW 3: ATTACK LOGS RENDERING
    // ==========================================================================
    function renderAttacksView(alerts) {
        const critAlertCount = document.getElementById("critAlertCount");
        const highAlertCount = document.getElementById("highAlertCount");
        const tbody = document.getElementById("attacksTableBody");
        if (!tbody) return;

        let critCount = 0;
        let highCount = 0;

        for (const a of alerts) {
            const sev = (a.severity || "CRITICAL").toUpperCase();
            if (sev === "CRITICAL") critCount++;
            else if (sev === "HIGH") highCount++;
        }

        if (critAlertCount) critAlertCount.textContent = critCount;
        if (highAlertCount) highAlertCount.textContent = highCount;

        tbody.innerHTML = "";

        if (alerts.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="7" style="text-align: center; color: var(--color-green); padding: 25px; font-weight: 600;">
                        [✓] Zero security attacks detected. RFC 6105 RA-Guard & RFC 4861 NDP nominal.
                    </td>
                </tr>
            `;
            return;
        }

        // Render newest alerts first
        const sortedAlerts = [...alerts].reverse();
        for (const a of sortedAlerts) {
            const tr = document.createElement("tr");
            const sev = (a.severity || "CRITICAL").toUpperCase();
            const isCritical = sev === "CRITICAL";

            if (isCritical) {
                tr.className = "row-danger";
            }

            const sevBadge = isCritical
                ? '<span class="badge badge-red">CRITICAL</span>'
                : (sev === "HIGH" ? '<span class="badge badge-amber">HIGH</span>' : '<span class="badge badge-accent">INFO</span>');

            const timeStr = a.timestamp
                ? new Date(a.timestamp * 1000).toTimeString().split(" ")[0]
                : "N/A";

            const pseudo = a.pseudonym || "N/A";
            const srcIp = a.src || (a.evidence && a.evidence.source_ip) || "N/A";
            const linkAnchor = (a.evidence && a.evidence.session_id) ||
                (a.evidence && a.evidence.ingress_port ? `Port ${a.evidence.ingress_port}` : "---");

            tr.innerHTML = `
                <td><code>${timeStr}</code></td>
                <td>${sevBadge}</td>
                <td><strong style="font-family: var(--font-mono);">${a.alert_type}</strong></td>
                <td><code>${pseudo}</code></td>
                <td><code>${srcIp}</code></td>
                <td><code>${linkAnchor}</code></td>
                <td>${a.description || "Protocol violation detected and mitigated."}</td>
            `;
            tbody.appendChild(tr);
        }
    }

    // ==========================================================================
    // 8. VIEW 4: LIVE LOGS CONSOLE RENDERING
    // ==========================================================================
    function appendConsoleLog(timeStr, typeStr, message, badgeClass) {
        const consoleEl = document.getElementById("liveLogsConsole");
        if (!consoleEl) return;

        const entry = document.createElement("div");
        entry.className = "log-entry";
        entry.innerHTML = `
            <span class="log-time">[${timeStr}]</span>
            <span class="log-type"><span class="badge ${badgeClass || 'badge-accent'}">${typeStr}</span></span>
            <span class="log-msg">${message}</span>
        `;

        consoleEl.appendChild(entry);
        liveLogCount++;

        // Prune old entries if exceeding limit
        while (consoleEl.children.length > MAX_LIVE_LOGS) {
            consoleEl.removeChild(consoleEl.firstChild);
        }

        // Update counter
        const counterEl = document.getElementById("logCounterText");
        if (counterEl) {
            counterEl.textContent = `Entries: ${consoleEl.children.length}`;
        }

        // Auto scroll to bottom
        const chkAutoScroll = document.getElementById("chkAutoScroll");
        if (chkAutoScroll && chkAutoScroll.checked) {
            consoleEl.scrollTop = consoleEl.scrollHeight;
        }
    }

    // Button: Clear Logs
    const btnClearLogs = document.getElementById("btnClearLogs");
    if (btnClearLogs) {
        btnClearLogs.addEventListener("click", () => {
            const consoleEl = document.getElementById("liveLogsConsole");
            if (consoleEl) {
                consoleEl.innerHTML = "";
                liveLogCount = 0;
            }
            const counterEl = document.getElementById("logCounterText");
            if (counterEl) counterEl.textContent = "Entries: 0";
        });
    }

    // ==========================================================================
    // 9. VIEW 5: IP ROTATION HISTORY RENDERING
    // ==========================================================================
    function renderRotationsView(sessions) {
        const container = document.getElementById("chainsContainer");
        if (!container) return;

        if (sessions.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; color: var(--text-dim); padding: 35px;">
                    Awaiting RFC 8981 address rotation events (addresses rotate automatically every 60s)...
                </div>
            `;
            return;
        }

        container.innerHTML = "";

        for (const s of sessions) {
            const history = s.ip_history || [];
            const pseudo = s.pseudonym || s.session_id;
            const rotCount = s.rotations || 0;

            const card = document.createElement("div");
            card.className = "rotation-card";

            let stepsHtml = "";
            if (history.length > 1) {
                // Latest Active Address
                const activeIp = history[history.length - 1];
                stepsHtml += `
                    <div class="chain-step">
                        <span class="badge badge-green">ACTIVE</span>
                        <code style="font-weight: 700; color: #2e7d32;">${activeIp}</code>
                        <span style="color: var(--text-dim); font-size: 11px;">(Current RFC 8981 SLAAC Address)</span>
                    </div>
                `;

                // Previous Expired Addresses
                for (let i = history.length - 2; i >= 0; i--) {
                    const prevTag = `PREV ${history.length - 1 - i}`;
                    stepsHtml += `
                        <div class="chain-arrow">↑ Rotated from previous temporary address:</div>
                        <div class="chain-step">
                            <span class="badge">${prevTag}</span>
                            <code style="color: var(--text-muted);">${history[i]}</code>
                            <span style="color: var(--text-dim); font-size: 11px;">(Deprecated / Expired)</span>
                        </div>
                    `;
                }
            } else {
                const singleIp = s.active_ip || history[0] || "Awaiting initial SLAAC DAD";
                stepsHtml = `
                    <div class="chain-step">
                        <span class="badge badge-green">ACTIVE</span>
                        <code style="font-weight: 700; color: #2e7d32;">${singleIp}</code>
                        <span style="color: var(--text-dim); font-size: 11px;">(Initial SLAAC Address - 0 rotations observed)</span>
                    </div>
                `;
            }

            card.innerHTML = `
                <div class="rotation-card-header">
                    <div>
                        <strong style="color: var(--accent); font-family: var(--font-mono); font-size: 13px;">${pseudo}</strong>
                        <span style="font-size: 11px; color: var(--text-dim); margin-left: 8px;">[Session Anchor: ${s.session_id}]</span>
                    </div>
                    <div>
                        <span class="badge badge-purple">${rotCount} Rotations Total</span>
                    </div>
                </div>
                <div class="rotation-card-body">
                    ${stepsHtml}
                </div>
            `;

            container.appendChild(card);
        }
    }

    // ==========================================================================
    // 10. CONTROLS & POLLING INITIALIZATION
    // ==========================================================================
    const btnRefreshClients = document.getElementById("btnRefreshClients");
    if (btnRefreshClients) {
        btnRefreshClients.addEventListener("click", () => {
            fetchState();
        });
    }

    const btnRecenterMap = document.getElementById("btnRecenterMap");
    if (btnRecenterMap) {
        btnRecenterMap.addEventListener("click", () => {
            if (topology && typeof topology._initCanvas === "function") {
                topology._initCanvas();
            }
        });
    }

    // Initial load
    connectLiveStream();
    fetchState();

    // Regular state synchronization every 1.5 seconds
    setInterval(fetchState, 1500);
});
