/**
 * topology.js - PS-007 2016-Era Light Network Topology Visualizer
 *
 * Constraints:
 *   - Light background (#ffffff), no gradients, no mouse animations.
 *   - Strict 0px border-radius, clean enterprise styling.
 *   - Displays Ephemeral Pseudonyms (P), never static hardware names.
 *   - Highlights rogue attacker devices in solid red (#c62828).
 */

class NetworkTopologyVisualizer {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        
        // Static Infrastructure Nodes
        this.infraNodes = {};
        // Dynamic Discovered Device Nodes: keyed by session_id
        this.clientNodes = {};
        
        this.particles = [];
        this.hoveredNode = null;
        
        this._initCanvas();
        this._setupListeners();
        this._startAnimationLoop();
    }

    _initCanvas() {
        if (!this.canvas) return;
        const rect = this.canvas.getBoundingClientRect();
        this.width = rect.width || 800;
        this.height = rect.height || 520;
        this.canvas.width = this.width * (window.devicePixelRatio || 1);
        this.canvas.height = this.height * (window.devicePixelRatio || 1);
        this.ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);

        const w = this.width;
        const h = this.height;

        // Infrastructure nodes (Router r1, Switch s1, Monitor m1)
        this.infraNodes = {
            'r1': {
                id: 'r1',
                shortCode: 'GW',
                label: 'Gateway (r1)',
                subLabel: 'Port 1 (wire: 5)',
                ip: 'fd00:abcd::1',
                role: 'Infrastructure Gateway',
                x: w * 0.5,
                y: h * 0.18,
                color: '#2d2f4d',
                borderColor: '#1a1b2d',
                radius: 18
            },
            's1': {
                id: 's1',
                shortCode: 'SW',
                label: 'OVS Switch (s1)',
                subLabel: 'OpenFlow 1.3 Mirror',
                role: 'Switch Interconnect',
                x: w * 0.5,
                y: h * 0.46,
                color: '#555963',
                borderColor: '#333333',
                radius: 19
            },
            'm1': {
                id: 'm1',
                shortCode: 'MON',
                label: 'Monitor (m1)',
                subLabel: 'Mirror Sniffer (Port 2)',
                ip: 'fd00:abcd::2',
                role: 'Promiscuous Monitor',
                x: w * 0.82,
                y: h * 0.46,
                color: '#0b7285',
                borderColor: '#065463',
                radius: 18
            }
        };

        this._recalculateClientPositions();
    }

    _setupListeners() {
        window.addEventListener('resize', () => {
            this._initCanvas();
        });

        const btnRecenter = document.getElementById("btnRecenterMap");
        if (btnRecenter) {
            btnRecenter.addEventListener("click", () => {
                this._initCanvas();
            });
        }

        this.canvas.addEventListener('mousemove', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const mouseX = e.clientX - rect.left;
            const mouseY = e.clientY - rect.top;

            this.hoveredNode = null;
            const allNodes = { ...this.infraNodes, ...this.clientNodes };
            for (const key in allNodes) {
                const node = allNodes[key];
                const dist = Math.hypot(node.x - mouseX, node.y - mouseY);
                if (dist <= (node.radius || 18) + 4) {
                    this.hoveredNode = node;
                    break;
                }
            }
        });

        this.canvas.addEventListener('mouseleave', () => {
            this.hoveredNode = null;
        });
    }

    /**
     * Dynamically synchronizes client nodes from the monitor's session list.
     * Port 1 / Router is strictly ignored.
     */
    syncDiscoveredSessions(sessions) {
        const activeIds = new Set();

        for (const s of sessions) {
            const sid = s.session_id;
            // The Gateway / Port 1 is fixed infrastructure, never a dynamic client
            if (!sid || sid === "SES-PORT01" || sid === "GATEWAY" || sid === "r1") {
                continue;
            }
            activeIds.add(sid);

            const isRogue = s.is_rogue || (s.status && s.status.includes("ROGUE"));
            const isQuarantined = Boolean(s.quarantined);
            const pseudo = s.pseudonym || sid;

            let nodeColor = "#2e7d32";
            let borderColor = "#1b5e20";
            let nodeLabel = `P: ${pseudo}`;

            if (isQuarantined) {
                nodeColor = "#b91c1c";
                borderColor = "#450a0a";
                nodeLabel = `CUT OFF: ${pseudo}`;
            } else if (isRogue) {
                nodeColor = "#c62828";
                borderColor = "#7f1d1d";
            } else if (s.status === "IDLE") {
                nodeColor = "#d97706";
                borderColor = "#b45309";
            }

            if (!this.clientNodes[sid]) {
                // New device discovered via DAD
                this.clientNodes[sid] = {
                    id: sid,
                    sessionId: sid,
                    pseudonym: pseudo,
                    shortCode: pseudo.substring(0, 4),
                    label: nodeLabel,
                    ip: s.active_ip || "Tentative",
                    status: isQuarantined ? "QUARANTINED" : (s.status || "ACTIVE"),
                    rotations: s.rotations || 0,
                    pkts: s.pkts || 0,
                    role: isQuarantined ? "Attacker (Cut Off)" : (s.role || "IoT Device"),
                    isRogue: isRogue,
                    quarantined: isQuarantined,
                    color: nodeColor,
                    borderColor: borderColor,
                    radius: 17
                };
            } else {
                // Update existing discovered node
                const node = this.clientNodes[sid];
                node.pseudonym = pseudo;
                node.shortCode = pseudo.substring(0, 4);
                node.label = nodeLabel;
                node.ip = s.active_ip || node.ip;
                node.status = isQuarantined ? "QUARANTINED" : (s.status || node.status);
                node.rotations = s.rotations !== undefined ? s.rotations : node.rotations;
                node.pkts = s.pkts !== undefined ? s.pkts : node.pkts;
                node.isRogue = isRogue;
                node.quarantined = isQuarantined;
                node.color = nodeColor;
                node.borderColor = borderColor;
            }
        }

        // Clean up any rogue SES-PORT01 if previously present
        delete this.clientNodes["SES-PORT01"];

        // Remove any node no longer in active session list
        for (const sid in this.clientNodes) {
            if (!activeIds.has(sid)) {
                delete this.clientNodes[sid];
            }
        }

        this._recalculateClientPositions();
    }

    /**
     * Marks a specific session/device as ROGUE ATTACKER in red on the map.
     */
    markDeviceAsRogue(sessionId, pseudonym) {
        if (!sessionId || sessionId === "SES-PORT01" || sessionId === "GATEWAY" || sessionId === "r1") {
            return;
        }

        for (const sid in this.clientNodes) {
            const node = this.clientNodes[sid];
            if (node.sessionId === sessionId || node.pseudonym === pseudonym) {
                node.isRogue = true;
                node.status = "ROGUE ATTACKER";
                node.color = "#c62828";
                node.borderColor = "#7f1d1d";
                return;
            }
        }

        // If the attacker hasn't been DAD-bound yet, create a dynamic rogue node immediately
        this.clientNodes[sessionId] = {
            id: sessionId,
            sessionId: sessionId,
            pseudonym: pseudonym || `ROGUE-${sessionId}`,
            shortCode: (pseudonym || sessionId).substring(0, 4),
            label: `ROGUE: ${pseudonym || sessionId}`,
            ip: "Attacker (Rogue RA)",
            status: "ROGUE ATTACKER",
            rotations: 0,
            pkts: 1,
            role: "Rogue Attacker",
            isRogue: true,
            color: "#c62828",
            borderColor: "#7f1d1d",
            radius: 18
        };
        this._recalculateClientPositions();
    }

    /**
     * Arranges discovered client nodes dynamically along a bottom arc.
     */
    _recalculateClientPositions() {
        const keys = Object.keys(this.clientNodes);
        const count = keys.length;
        if (count === 0) return;

        const w = this.width;
        const h = this.height;
        const s1 = this.infraNodes['s1'];
        if (!s1) return;

        const radiusY = Math.min(w * 0.35, h * 0.40);
        const radiusX = Math.min(w * 0.40, 420);

        if (count === 1) {
            const node = this.clientNodes[keys[0]];
            node.x = s1.x;
            node.y = s1.y + radiusY;
            return;
        }

        const startAngle = Math.PI * 0.15;
        const endAngle = Math.PI * 0.85;
        const step = (endAngle - startAngle) / (count - 1);

        keys.forEach((key, i) => {
            const node = this.clientNodes[key];
            const angle = startAngle + (i * step);
            node.x = s1.x + radiusX * Math.cos(angle);
            node.y = s1.y + radiusY * Math.sin(angle);
        });
    }

    triggerPacketFlow(fromId, toId = 's1', color = '#2d2f4d', speed = 0.025) {
        const allNodes = { ...this.infraNodes, ...this.clientNodes };
        const fromNode = allNodes[fromId];
        const toNode = allNodes[toId];
        if (!fromNode || !toNode) return;

        this.particles.push({
            fromX: fromNode.x,
            fromY: fromNode.y,
            toX: toNode.x,
            toY: toNode.y,
            progress: 0,
            speed: speed,
            color: color
        });

        // Mirror flow to monitor m1
        if (toId === 's1' && fromId !== 'm1') {
            const m1 = this.infraNodes['m1'];
            if (m1) {
                setTimeout(() => {
                    this.particles.push({
                        fromX: toNode.x,
                        fromY: toNode.y,
                        toX: m1.x,
                        toY: m1.y,
                        progress: 0,
                        speed: speed * 1.2,
                        color: '#0b7285'
                    });
                }, 80);
            }
        }
    }

    _startAnimationLoop() {
        const render = () => {
            this._render();
            requestAnimationFrame(render);
        };
        requestAnimationFrame(render);
    }

    _render() {
        const w = this.width;
        const h = this.height;
        this.ctx.clearRect(0, 0, w, h);

        // White Background Fill
        this.ctx.fillStyle = '#ffffff';
        this.ctx.fillRect(0, 0, w, h);

        const r1 = this.infraNodes['r1'];
        const s1 = this.infraNodes['s1'];
        const m1 = this.infraNodes['m1'];

        // 1. Draw Static Infrastructure Links (2016 Crisp Lines)
        if (r1 && s1) {
            this._drawLink(r1, s1, '#4a5568', 2, [3, 3]);
        }
        if (s1 && m1) {
            this._drawLink(s1, m1, '#0b7285', 2, [4, 4]);
        }

        // 2. Draw Dynamic Client Links
        for (const sid in this.clientNodes) {
            const cNode = this.clientNodes[sid];
            if (s1 && cNode) {
                const linkColor = cNode.isRogue ? '#c62828' : '#94a3b8';
                const linkWidth = cNode.isRogue ? 2.5 : 1.5;
                this._drawLink(cNode, s1, linkColor, linkWidth, []);
            }
        }

        // 3. Draw Simple Particles (Zero Blur, Clean 2016 dots)
        for (let i = this.particles.length - 1; i >= 0; i--) {
            const p = this.particles[i];
            p.progress += p.speed;

            const currX = p.fromX + (p.toX - p.fromX) * p.progress;
            const currY = p.fromY + (p.toY - p.fromY) * p.progress;

            this.ctx.beginPath();
            this.ctx.arc(currX, currY, 3, 0, Math.PI * 2);
            this.ctx.fillStyle = p.color;
            this.ctx.shadowBlur = 0;
            this.ctx.fill();

            if (p.progress >= 1.0) {
                this.particles.splice(i, 1);
            }
        }

        // 4. Draw Infrastructure Nodes
        for (const key in this.infraNodes) {
            this._drawNode(this.infraNodes[key]);
        }

        // 5. Draw Discovered Client Nodes
        const clientCount = Object.keys(this.clientNodes).length;
        if (clientCount === 0) {
            this.ctx.font = '12px Consolas, monospace';
            this.ctx.fillStyle = '#6b7280';
            this.ctx.textAlign = 'center';
            this.ctx.fillText("No IoT clients identified yet.", s1.x, s1.y + 70);
            this.ctx.font = '11px -apple-system, sans-serif';
            this.ctx.fillStyle = '#9ca3af';
            this.ctx.fillText("Nodes appear dynamically upon SLAAC DAD binding.", s1.x, s1.y + 90);
        } else {
            for (const sid in this.clientNodes) {
                this._drawNode(this.clientNodes[sid]);
            }
        }

        // 6. Draw Tooltip (Sharp 2016 rectangle, 0px radius)
        if (this.hoveredNode) {
            this._drawTooltip(this.hoveredNode);
        }
    }

    _drawLink(n1, n2, strokeStyle, lineWidth, dash) {
        this.ctx.beginPath();
        this.ctx.moveTo(n1.x, n1.y);
        this.ctx.lineTo(n2.x, n2.y);
        this.ctx.strokeStyle = strokeStyle;
        this.ctx.lineWidth = lineWidth || 1.5;
        this.ctx.setLineDash(dash || []);
        this.ctx.stroke();
        this.ctx.setLineDash([]);
    }

    _drawNode(node) {
        const radius = node.radius || 18;

        // If Rogue Attacker: draw solid red rectangular warning frame (Zero Animation)
        if (node.isRogue) {
            this.ctx.strokeStyle = '#c62828';
            this.ctx.lineWidth = 2;
            this.ctx.strokeRect(node.x - radius - 5, node.y - radius - 5, (radius * 2) + 10, (radius * 2) + 10);
        }

        // Core Circle
        this.ctx.beginPath();
        this.ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
        this.ctx.fillStyle = node.color;
        this.ctx.shadowBlur = 0;
        this.ctx.fill();

        this.ctx.lineWidth = 2;
        this.ctx.strokeStyle = node.borderColor || '#1a1b2d';
        this.ctx.stroke();

        // Node Short Label Inside Circle (White Text)
        this.ctx.font = 'bold 9px Consolas, monospace';
        this.ctx.fillStyle = '#ffffff';
        this.ctx.textAlign = 'center';
        this.ctx.textBaseline = 'middle';
        this.ctx.fillText(node.shortCode || 'DEV', node.x, node.y);
        this.ctx.textBaseline = 'alphabetic';

        // Label Below Node (Dark Text for 2016 Light Theme)
        this.ctx.font = 'bold 11px Consolas, monospace';
        this.ctx.fillStyle = node.isRogue ? '#c62828' : '#2d2f4d';
        this.ctx.textAlign = 'center';
        this.ctx.fillText(node.label, node.x, node.y + radius + 15);

        // Sublabel Below Node (Session ID / Port)
        const sub = node.subLabel || node.sessionId;
        if (sub) {
            this.ctx.font = '10px -apple-system, sans-serif';
            this.ctx.fillStyle = node.isRogue ? '#c62828' : '#57606a';
            this.ctx.fillText(sub, node.x, node.y + radius + 28);
        }
    }

    _drawTooltip(node) {
        const pad = 10;
        const tipW = 240;
        const tipH = 96;
        let tipX = node.x + 22;
        let tipY = node.y - 45;

        if (tipX + tipW > this.width) tipX = node.x - tipW - 22;
        if (tipY < 10) tipY = 10;

        // Strict 2016 Rectangular Tooltip (Zero Radius)
        this.ctx.fillStyle = '#ffffff';
        this.ctx.strokeStyle = node.isRogue ? '#c62828' : '#2d2f4d';
        this.ctx.lineWidth = 2;
        this.ctx.fillRect(tipX, tipY, tipW, tipH);
        this.ctx.strokeRect(tipX, tipY, tipW, tipH);

        this.ctx.textAlign = 'left';
        this.ctx.font = 'bold 11px -apple-system, sans-serif';
        this.ctx.fillStyle = node.isRogue ? '#c62828' : '#2d2f4d';
        this.ctx.fillText(`${node.label} [${node.status || 'NOMINAL'}]`, tipX + pad, tipY + 18);

        this.ctx.font = '10px Consolas, monospace';
        this.ctx.fillStyle = '#555555';
        this.ctx.fillText(`Anchor: ${node.sessionId || node.subLabel || 'Static'}`, tipX + pad, tipY + 34);

        this.ctx.fillStyle = '#1f2328';
        this.ctx.fillText(`Pseudonym: ${node.pseudonym || 'N/A'}`, tipX + pad, tipY + 50);

        const ipTrunc = (node.ip && node.ip.length > 25) ? (node.ip.substring(0, 24) + '...') : (node.ip || 'None');
        this.ctx.fillStyle = '#2e7d32';
        this.ctx.fillText(`IP: ${ipTrunc}`, tipX + pad, tipY + 66);

        this.ctx.fillStyle = node.isRogue ? '#c62828' : '#666666';
        this.ctx.fillText(`Rotations: ${node.rotations || 0}x | Packets: ${node.pkts || 0}`, tipX + pad, tipY + 82);
    }
}

window.NetworkTopologyVisualizer = NetworkTopologyVisualizer;
