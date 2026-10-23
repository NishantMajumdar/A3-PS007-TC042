/**
 * charts.js - PS-007 Security Threat Telemetry, Token Bucket & Anomaly Gauges
 */

class ThreatTelemetryManager {
    constructor() {
        this.tokenFillPercent = 100;
        this.cusumDrift = 0.0;
        this.targetCardinality = 1;
        this.alertCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
    }

    updateMetricsFromAlerts(alerts) {
        this.alertCounts = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0 };
        let latestNdpAlert = null;

        for (const a of alerts) {
            const sev = a.severity || "MEDIUM";
            if (this.alertCounts[sev] !== undefined) {
                this.alertCounts[sev]++;
            }
            if (a.alert_type && a.alert_type.includes("NDP")) {
                latestNdpAlert = a;
            }
        }

        // Adjust simulated token fill if an NDP flood alert is active
        if (latestNdpAlert) {
            this.tokenFillPercent = Math.max(10, Math.min(100, Math.floor(Math.random() * 25)));
            this.cusumDrift = +(Math.random() * 8 + 12).toFixed(1);
            this.targetCardinality = Math.floor(Math.random() * 8 + 5);
        } else {
            // Nominal state
            this.tokenFillPercent = 95;
            this.cusumDrift = +(Math.random() * 1.5).toFixed(1);
            this.targetCardinality = 1;
        }

        this.renderGauges();
    }

    renderGauges() {
        // 1. Token Bucket
        const tbBar = document.getElementById("tokenBucketFillBar");
        const tbVal = document.getElementById("tokenBucketVal");
        if (tbBar && tbVal) {
            tbBar.style.width = `${this.tokenFillPercent}%`;
            tbVal.textContent = `${this.tokenFillPercent}%`;
            
            if (this.tokenFillPercent < 30) {
                tbBar.style.backgroundColor = '#ef4444';
            } else if (this.tokenFillPercent < 70) {
                tbBar.style.backgroundColor = '#f59e0b';
            } else {
                tbBar.style.backgroundColor = '#10b981';
            }
        }

        // 2. CUSUM Drift
        const cusumVal = document.getElementById("cusumVal");
        const cusumBadge = document.getElementById("cusumBadge");
        if (cusumVal && cusumBadge) {
            cusumVal.textContent = this.cusumDrift.toString();
            if (this.cusumDrift > 8.0) {
                cusumBadge.textContent = "DRIFT DETECTED";
                cusumBadge.className = "badge-tag badge-red";
            } else {
                cusumBadge.textContent = "NOMINAL";
                cusumBadge.className = "badge-tag badge-green";
            }
        }

        // 3. Target Cardinality
        const cardVal = document.getElementById("cardinalityVal");
        const cardBadge = document.getElementById("cardinalityBadge");
        if (cardVal && cardBadge) {
            cardVal.textContent = `${this.targetCardinality} targets/5s`;
            if (this.targetCardinality > 3) {
                cardBadge.textContent = "SCAN DETECTED";
                cardBadge.className = "badge-tag badge-amber";
            } else {
                cardBadge.textContent = "BENIGN";
                cardBadge.className = "badge-tag badge-green";
            }
        }

        // 4. Alert Count Badges
        const critEl = document.getElementById("critAlertCount");
        const highEl = document.getElementById("highAlertCount");
        if (critEl) critEl.textContent = this.alertCounts.CRITICAL;
        if (highEl) highEl.textContent = this.alertCounts.HIGH;
    }
}

window.ThreatTelemetryManager = ThreatTelemetryManager;
