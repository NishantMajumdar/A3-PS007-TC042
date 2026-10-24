# Optional Mode B: Active Client Agent & Cryptographic Ratchet

## Overview
vibe coded
**Mode A is the PRIMARY operational mode for PS-007.**
In Mode A, IoT devices are treated as **100% black-box endpoints** without any custom software or agents. All rotation tracking, pseudonym derivation, and anomaly detection occur passively via OpenFlow 1.3 switch port mirroring and RFC 4862 Duplicate Address Detection (DAD) Neighbor Solicitations.

**Mode B is STRICTLY OPTIONAL.**
It provides an active client-side agent for managed IoT environments where the operator has execution privileges on the endpoint and wishes to run an active cryptographic hash ratchet with replay protection.

---

## Contents of `optional_mode_b/`

1. **`ratchet.py`**:
   - Key Ratchet: $S_{i+1} = \text{SHA256}(S_i)$
   - Authentication Tag: `HMAC(S_i, new_addr || ctr)`
   - Replay Protection: Rejection of non-increasing counters (`ctr <= last_ctr`)

2. **`optional_client_agent.py`**:
   - Active Python agent for IoT nodes.
   - Negotiates seed $S_0$ via `AUTH_REQUEST`.
   - Watches kernel RFC 8981 rotations every 3 seconds.
   - Emits `UPDATE_RATCHET` from new addresses.

3. **`optional_mode_b_server.py`**:
   - Modular UDP server listening on port 9000 when Mode B is explicitly enabled via `--enable-mode-b`.

---

## Usage

### Enable Mode B on the Monitor
```bash
# By default, monitor.py runs Mode A (Pure Black-Box Passive Mode)
python3 monitor.py

# To explicitly activate optional Mode B UDP server:
python3 monitor.py --enable-mode-b
# Or via environment variable:
ENABLE_MODE_B=1 python3 monitor.py
```

### Launching Optional Mode B Agent on a Client
```bash
python3 optional_mode_b/optional_client_agent.py
# Or via launcher:
./launch_node.sh --mode-b h1
```
