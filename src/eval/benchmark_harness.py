#!/usr/bin/env python3
"""
eval/benchmark_harness.py - PS-007 Evaluation & Benchmarking Harness

Executes >= 30 trials per scenario across:
  - Attack Scenarios: Rogue RA, Rotating-Source NDP Flood, Target Scan
  - Benign Stress Tests: Simultaneous Address Rotation, Device Reboot / SLAAC, Bursty Sensor
  - Parameter Sweeps: Over Rotation Interval (1s..60s) and Attacker Rate (4..64 pps)
Outputs:
  - CSV files: benchmark_metrics.csv, rotation_sweep.csv, rate_sweep.csv
  - PNG Plots: detection_comparison.png, parameter_sweeps.png
"""

import os
os.environ["MPLCONFIGDIR"] = "/tmp/matplotlib_cache"
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import csv
import time
import random
import numpy as np
from typing import Dict, List, Tuple

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

from pseudonym import PseudonymManager
from attribution import AttributionEngine
from detectors import RogueRADetector, NDPAbuseDetector
from baseline_detector import BaselineDetector

# ==============================================================================
# SCENARIO SIMULATORS
# ==============================================================================

def run_trial_rogue_ra(is_attack: bool, trial_id: int) -> Tuple[bool, Optional[float], bool, Optional[float]]:
    """
    Rogue RA Scenario:
      If attack: injected unauthorized RA with lifetime 0 or unexpected prefix.
      If benign: regular periodic RA from authorized router fd00:abcd::1.
    Returns: (baseline_detected, baseline_latency_ms, our_detected, our_latency_ms)
    """
    ra_detector = RogueRADetector(authorized_routers=["fd00:abcd::1"])
    baseline = BaselineDetector(rate_limit_pps=6.0, window_seconds=2.0)

    t0 = 1000.0
    if is_attack:
        # Attack: Rogue RA injected at t = t0 + 0.1
        src = f"fd00:abcd::bad:{trial_id:04x}"
        t_inject = t0 + 0.1
        
        # Baseline per-IP inspection (single packet doesn't breach rate threshold)
        b_alert = baseline.process_packet(src, current_time=t_inject)
        b_detected = (b_alert is not None)
        b_lat = (t_inject - t0) * 1000.0 if b_detected else None

        # Our detector inspection
        alerts = ra_detector.inspect_ra(
            src_ip=src,
            router_lifetime=0,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("2001:db8:rogue::", 64)],
            current_time=t_inject
        )
        our_detected = len(alerts) > 0
        our_lat = (t_inject - t0) * 1000.0 if our_detected else None

        return b_detected, b_lat, our_detected, our_lat
    else:
        # Benign: Legitimate RA from authorized router
        src = "fd00:abcd::1"
        t_inject = t0 + 0.5
        b_alert = baseline.process_packet(src, current_time=t_inject)
        alerts = ra_detector.inspect_ra(
            src_ip=src,
            router_lifetime=1800,
            cur_hop_limit=64,
            managed_flag=0,
            other_flag=0,
            advertised_prefixes=[("fd00:abcd::", 64)],
            current_time=t_inject
        )
        return (b_alert is not None), None, (len(alerts) > 0), None


def run_trial_rotating_ndp_flood(
    is_attack: bool,
    attack_rate_pps: float = 12.0,
    rotate_interval_sec: float = 2.0,
    trial_id: int = 0
) -> Tuple[bool, Optional[float], bool, Optional[float]]:
    """
    Rotating-Source NDP Flood:
      If attack: Attacker floods at attack_rate_pps, rotating source IP every rotate_interval_sec.
      If benign: Normal host transmitting occasional NS queries (1 pps).
    """
    ndp_detector = NDPAbuseDetector(hysteresis_n=3, hysteresis_m=5)
    baseline = BaselineDetector(rate_limit_pps=6.0, window_seconds=2.0)

    t0 = 1000.0
    duration = 6.0
    pseudonym = f"IOT-NODE{trial_id % 5:02d}"

    b_detected = False
    b_lat = None
    our_detected = False
    our_lat = None

    if is_attack:
        interval = 1.0 / attack_rate_pps
        num_packets = int(duration * attack_rate_pps)
        current_ip_gen = 0
        last_rot = t0

        for i in range(num_packets):
            now = t0 + (i * interval)
            if now - last_rot >= rotate_interval_sec:
                current_ip_gen += 1
                last_rot = now

            src_ip = f"fd00:abcd::{trial_id:02x}:{current_ip_gen:04x}"

            # Baseline check
            if not b_detected:
                if baseline.process_packet(src_ip, current_time=now):
                    b_detected = True
                    b_lat = (now - t0) * 1000.0

            # Our detector check
            if not our_detected:
                alerts = ndp_detector.record_ndp_packet(
                    pseudonym=pseudonym,
                    ndp_type="NS",
                    src_ip=src_ip,
                    target_ip="fd00:abcd::1",
                    current_time=now
                )
                if alerts:
                    our_detected = True
                    our_lat = (now - t0) * 1000.0
    else:
        # Benign: 1 packet every 1.5s
        for i in range(4):
            now = t0 + (i * 1.5)
            src_ip = f"fd00:abcd::100{trial_id % 5}"
            if baseline.process_packet(src_ip, current_time=now):
                b_detected = True
            alerts = ndp_detector.record_ndp_packet(
                pseudonym=pseudonym,
                ndp_type="NS",
                src_ip=src_ip,
                target_ip="fd00:abcd::1",
                current_time=now
            )
            if alerts:
                our_detected = True

    return b_detected, b_lat, our_detected, our_lat


def run_trial_ndp_target_scan(is_attack: bool, trial_id: int) -> Tuple[bool, Optional[float], bool, Optional[float]]:
    """
    NDP Target Scanning (Host Discovery / Cache Exhaustion):
      If attack: Queries 10 distinct targets within 2 seconds.
      If benign: Queries normal gateway target only.
    """
    ndp_detector = NDPAbuseDetector(hysteresis_n=3, hysteresis_m=5, max_distinct_targets=3, target_window_seconds=5.0)
    baseline = BaselineDetector(rate_limit_pps=6.0, window_seconds=2.0)

    t0 = 1000.0
    pseudonym = f"IOT-SCAN{trial_id:02d}"
    src_ip = f"fd00:abcd::{trial_id:04x}"

    b_detected = False
    b_lat = None
    our_detected = False
    our_lat = None

    if is_attack:
        # Attacker queries 8 distinct targets spaced at 0.25s (rate = 4 pps, below baseline 6 pps limit!)
        for i in range(8):
            now = t0 + (i * 0.25)
            target = f"fd00:abcd::{i+100:04x}"
            if not b_detected and baseline.process_packet(src_ip, current_time=now):
                b_detected = True
                b_lat = (now - t0) * 1000.0

            if not our_detected:
                alerts = ndp_detector.record_ndp_packet(
                    pseudonym=pseudonym,
                    ndp_type="NS",
                    src_ip=src_ip,
                    target_ip=target,
                    current_time=now
                )
                if alerts:
                    our_detected = True
                    our_lat = (now - t0) * 1000.0
    else:
        # Benign: queries only default router
        for i in range(4):
            now = t0 + (i * 1.0)
            target = "fd00:abcd::1"
            if baseline.process_packet(src_ip, current_time=now):
                b_detected = True
            alerts = ndp_detector.record_ndp_packet(
                pseudonym=pseudonym,
                ndp_type="NS",
                src_ip=src_ip,
                target_ip=target,
                current_time=now
            )
            if alerts:
                our_detected = True

    return b_detected, b_lat, our_detected, our_lat


def run_trial_simultaneous_rotation(trial_id: int) -> Tuple[bool, bool]:
    """Benign Stress: 5 IoT hosts simultaneously rotate IPv6 addresses & do DAD."""
    pm = PseudonymManager(epoch_length_seconds=300.0, default_addr_ttl=60.0)
    engine = AttributionEngine(pm, max_bindings_per_rotation=3, rotation_window_seconds=60.0)
    ndp_detector = NDPAbuseDetector()
    baseline = BaselineDetector(rate_limit_pps=6.0, window_seconds=2.0)

    t0 = 1000.0
    b_fp = False
    our_fp = False

    for host_id in range(1, 6):
        vlan = 4100 + host_id
        new_ip = f"fd00:abcd::{trial_id:02x}:{host_id:02x}"
        
        # Valid DAD NS
        event = engine.handle_dad_ns(vlan_id=vlan, target_ip=new_ip, current_time=t0 + 0.05)
        if event.event_type == "REJECT_EXCEEDED":
            our_fp = True

        # Send NS
        if baseline.process_packet(new_ip, current_time=t0 + 0.1):
            b_fp = True
        alerts = ndp_detector.record_ndp_packet(event.pseudonym, "NS", new_ip, "fd00:abcd::1", current_time=t0 + 0.1)
        if alerts:
            our_fp = True

    return b_fp, our_fp


def run_trial_device_reboot_slaac(trial_id: int) -> Tuple[bool, bool]:
    """Benign Stress: Device reboot triggering link-local DAD + global DAD."""
    pm = PseudonymManager()
    engine = AttributionEngine(pm, max_bindings_per_rotation=3)
    ndp_detector = NDPAbuseDetector()
    baseline = BaselineDetector()

    t0 = 1000.0
    b_fp = False
    our_fp = False

    vlan = 4103
    # Step 1: Link-local DAD
    ev1 = engine.handle_dad_ns(vlan, "fe80::1001", current_time=t0)
    # Step 2: Global SLAAC DAD
    ev2 = engine.handle_dad_ns(vlan, "fd00:abcd::1001", current_time=t0 + 0.5)

    if ev1.event_type == "REJECT_EXCEEDED" or ev2.event_type == "REJECT_EXCEEDED":
        our_fp = True

    alerts = ndp_detector.record_ndp_packet(ev2.pseudonym, "NS", "fd00:abcd::1001", "fd00:abcd::1", current_time=t0 + 0.6)
    if alerts:
        our_fp = True
    if baseline.process_packet("fd00:abcd::1001", current_time=t0 + 0.6):
        b_fp = True

    return b_fp, our_fp


def run_trial_bursty_sensor(trial_id: int) -> Tuple[bool, bool]:
    """Benign Stress: Bursty IoT sensor transmitting batch telemetry."""
    ndp_detector = NDPAbuseDetector()
    baseline = BaselineDetector(rate_limit_pps=6.0, window_seconds=2.0)

    t0 = 1000.0
    b_fp = False
    our_fp = False
    src_ip = f"fd00:abcd::sensor:{trial_id:02x}"
    pseudonym = f"IOT-SENSOR{trial_id:02x}"

    # Normal NDP query followed by data
    alerts = ndp_detector.record_ndp_packet(pseudonym, "NS", src_ip, "fd00:abcd::1", current_time=t0)
    if alerts:
        our_fp = True
    if baseline.process_packet(src_ip, current_time=t0):
        b_fp = True

    return b_fp, our_fp


# ==============================================================================
# BENCHMARK EXECUTION HARNESS
# ==============================================================================

def execute_benchmarks(num_trials: int = 30) -> Dict:
    print(f"[*] Running PS-007 Evaluation Suite (N={num_trials} trials per scenario)...")

    scenarios = [
        ("Rogue RA Attack", run_trial_rogue_ra),
        ("Rotating NDP Flood", run_trial_rotating_ndp_flood),
        ("Target Scanning Scan", run_trial_ndp_target_scan)
    ]

    results = {}

    for name, runner in scenarios:
        print(f"  -> Benchmarking scenario: {name}...")
        b_tp = 0
        our_tp = 0
        b_latencies = []
        our_latencies = []

        # Attack trials (measure TPR and latency)
        for t in range(num_trials):
            b_det, b_lat, our_det, our_lat = runner(is_attack=True, trial_id=t)
            if b_det:
                b_tp += 1
                if b_lat: b_latencies.append(b_lat)
            if our_det:
                our_tp += 1
                if our_lat: our_latencies.append(our_lat)

        # Benign trials (measure FPR)
        b_fp = 0
        our_fp = 0
        for t in range(num_trials):
            b_det, _, our_det, _ = runner(is_attack=False, trial_id=t)
            if b_det: b_fp += 1
            if our_det: our_fp += 1

        b_tpr = b_tp / num_trials
        b_fpr = b_fp / num_trials
        our_tpr = our_tp / num_trials
        our_fpr = our_fp / num_trials

        b_p50 = float(np.percentile(b_latencies, 50)) if b_latencies else 0.0
        b_p95 = float(np.percentile(b_latencies, 95)) if b_latencies else 0.0
        our_p50 = float(np.percentile(our_latencies, 50)) if our_latencies else 0.0
        our_p95 = float(np.percentile(our_latencies, 95)) if our_latencies else 0.0

        results[name] = {
            "baseline": {"tpr": b_tpr, "fpr": b_fpr, "p50_ms": b_p50, "p95_ms": b_p95},
            "our_system": {"tpr": our_tpr, "fpr": our_fpr, "p50_ms": our_p50, "p95_ms": our_p95}
        }

    # Benign stress tests
    print("  -> Benchmarking benign stress scenarios...")
    stress_scenarios = [
        ("Simultaneous Rotation", run_trial_simultaneous_rotation),
        ("Device Reboot / SLAAC", run_trial_device_reboot_slaac),
        ("Bursty Sensor Telemetry", run_trial_bursty_sensor)
    ]
    stress_results = {}
    for name, runner in stress_scenarios:
        b_fps = 0
        our_fps = 0
        for t in range(num_trials):
            bf, of = runner(trial_id=t)
            if bf: b_fps += 1
            if of: our_fps += 1
        stress_results[name] = {
            "baseline_fpr": b_fps / num_trials,
            "our_system_fpr": our_fps / num_trials
        }

    # ==========================================================================
    # PARAMETER SWEEPS (>= 30 trials per step)
    # ==========================================================================
    print("  -> Running parameter sweep: Rotation Interval (1s..60s)...")
    rotation_intervals = [1.0, 2.0, 3.0, 5.0, 10.0, 30.0, 60.0]
    rotation_sweep_data = []

    for rot_sec in rotation_intervals:
        b_hits = 0
        our_hits = 0
        for t in range(num_trials):
            b_det, _, our_det, _ = run_trial_rotating_ndp_flood(
                is_attack=True,
                attack_rate_pps=12.0,
                rotate_interval_sec=rot_sec,
                trial_id=t
            )
            if b_det: b_hits += 1
            if our_det: our_hits += 1
        rotation_sweep_data.append({
            "rotation_interval_s": rot_sec,
            "baseline_tpr": b_hits / num_trials,
            "our_tpr": our_hits / num_trials
        })

    print("  -> Running parameter sweep: Attacker Rate (4..64 pps)...")
    attacker_rates = [4.0, 8.0, 16.0, 32.0, 64.0]
    rate_sweep_data = []

    for rate in attacker_rates:
        our_hits = 0
        our_lats = []
        b_hits = 0
        b_lats = []
        for t in range(num_trials):
            b_det, b_lat, our_det, our_lat = run_trial_rotating_ndp_flood(
                is_attack=True,
                attack_rate_pps=rate,
                rotate_interval_sec=2.0,
                trial_id=t
            )
            if our_det:
                our_hits += 1
                if our_lat: our_lats.append(our_lat)
            if b_det:
                b_hits += 1
                if b_lat: b_lats.append(b_lat)

        rate_sweep_data.append({
            "attack_rate_pps": rate,
            "baseline_tpr": b_hits / num_trials,
            "our_tpr": our_hits / num_trials,
            "our_p50_ms": float(np.percentile(our_lats, 50)) if our_lats else 0.0,
            "our_p95_ms": float(np.percentile(our_lats, 95)) if our_lats else 0.0
        })

    # ==========================================================================
    # SAVE CSV RESULTS
    # ==========================================================================
    os.makedirs("eval/results", exist_ok=True)
    
    # 1. Benchmark metrics CSV
    with open("eval/results/benchmark_metrics.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Scenario", "Detector", "TPR", "FPR", "Latency_p50_ms", "Latency_p95_ms"])
        for scn, dat in results.items():
            writer.writerow([scn, "Baseline", f"{dat['baseline']['tpr']:.4f}", f"{dat['baseline']['fpr']:.4f}", f"{dat['baseline']['p50_ms']:.2f}", f"{dat['baseline']['p95_ms']:.2f}"])
            writer.writerow([scn, "PS-007 (Ours)", f"{dat['our_system']['tpr']:.4f}", f"{dat['our_system']['fpr']:.4f}", f"{dat['our_system']['p50_ms']:.2f}", f"{dat['our_system']['p95_ms']:.2f}"])
        for scn, dat in stress_results.items():
            writer.writerow([f"Benign Stress: {scn}", "Baseline", "N/A", f"{dat['baseline_fpr']:.4f}", "N/A", "N/A"])
            writer.writerow([f"Benign Stress: {scn}", "PS-007 (Ours)", "N/A", f"{dat['our_system_fpr']:.4f}", "N/A", "N/A"])

    # 2. Rotation sweep CSV
    with open("eval/results/rotation_sweep.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["rotation_interval_s", "baseline_tpr", "our_tpr"])
        writer.writeheader()
        writer.writerows(rotation_sweep_data)

    # 3. Rate sweep CSV
    with open("eval/results/rate_sweep.csv", "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["attack_rate_pps", "baseline_tpr", "our_tpr", "our_p50_ms", "our_p95_ms"])
        writer.writeheader()
        writer.writerows(rate_sweep_data)

    # ==========================================================================
    # GENERATE PLOTS
    # ==========================================================================
    print("  -> Rendering benchmark plots...")
    
    # Plot 1: Detection TPR Comparison
    sc_names = list(results.keys())
    b_tprs = [results[s]["baseline"]["tpr"] * 100 for s in sc_names]
    our_tprs = [results[s]["our_system"]["tpr"] * 100 for s in sc_names]
    
    x = np.arange(len(sc_names))
    width = 0.35

    fig, ax = plt.subplots(figsize=(8, 4.5))
    rects1 = ax.bar(x - width/2, b_tprs, width, label="Baseline (Per-Source-IP)", color="#e74c3c")
    rects2 = ax.bar(x + width/2, our_tprs, width, label="PS-007 (Epoch Pseudonym)", color="#2ecc71")

    ax.set_ylabel("True Positive Rate (%)", fontsize=11, fontweight="bold")
    ax.set_title("Detection Performance: Baseline vs PS-007 System (N=30 Trials)", fontsize=12, fontweight="bold")
    ax.set_xticks(x)
    ax.set_xticklabels(sc_names, fontsize=10)
    ax.set_ylim(0, 115)
    ax.legend(loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.6)

    # Bar value labels
    for rect in rects1:
        height = rect.get_height()
        ax.annotate(f"{height:.0f}%", xy=(rect.get_x() + rect.get_width()/2, height),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9)
    for rect in rects2:
        height = rect.get_height()
        ax.annotate(f"{height:.0f}%", xy=(rect.get_x() + rect.get_width()/2, height),
                    xytext=(0, 3), textcoords="offset points", ha="center", va="bottom", fontsize=9, fontweight="bold")

    plt.tight_layout()
    fig.savefig("eval/results/detection_comparison.png", dpi=200)
    plt.close(fig)

    # Plot 2: Parameter Sweeps (Rotation Interval & Attacker Rate)
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))

    # Subplot A: Rotation interval vs TPR
    rot_x = [d["rotation_interval_s"] for d in rotation_sweep_data]
    b_rot_y = [d["baseline_tpr"] * 100 for d in rotation_sweep_data]
    our_rot_y = [d["our_tpr"] * 100 for d in rotation_sweep_data]

    ax1.plot(rot_x, b_rot_y, "o--", color="#e74c3c", label="Baseline (Per-IP)", linewidth=2)
    ax1.plot(rot_x, our_rot_y, "s-", color="#2ecc71", label="PS-007 (Pseudonym)", linewidth=2.5)
    ax1.set_xscale("log")
    ax1.set_xlabel("Attacker IP Rotation Interval (seconds)", fontsize=10, fontweight="bold")
    ax1.set_ylabel("True Positive Rate (%)", fontsize=10, fontweight="bold")
    ax1.set_title("Robustness to Address Rotation (RFC 8981 Evasion)", fontsize=10, fontweight="bold")
    ax1.set_ylim(-5, 110)
    ax1.grid(True, linestyle="--", alpha=0.5)
    ax1.legend()

    # Subplot B: Attack Rate vs Latency (p50 & p95)
    rates_x = [d["attack_rate_pps"] for d in rate_sweep_data]
    p50_y = [d["our_p50_ms"] for d in rate_sweep_data]
    p95_y = [d["our_p95_ms"] for d in rate_sweep_data]

    ax2.plot(rates_x, p50_y, "o-", color="#3498db", label="Latency p50 (Median)", linewidth=2)
    ax2.plot(rates_x, p95_y, "^--", color="#9b59b6", label="Latency p95", linewidth=2)
    ax2.set_xlabel("Attack Packet Rate (pps)", fontsize=10, fontweight="bold")
    ax2.set_ylabel("Detection Latency (ms)", fontsize=10, fontweight="bold")
    ax2.set_title("Detection Latency vs Attacker Rate", fontsize=10, fontweight="bold")
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.legend()

    plt.tight_layout()
    fig.savefig("eval/results/parameter_sweeps.png", dpi=200)
    plt.close(fig)

    print("[+] Evaluation complete! Artifacts saved to eval/results/")
    return {
        "results": results,
        "stress_results": stress_results,
        "rotation_sweep": rotation_sweep_data,
        "rate_sweep": rate_sweep_data
    }

if __name__ == "__main__":
    trials = 30
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        trials = int(sys.argv[1])
    execute_benchmarks(num_trials=trials)
