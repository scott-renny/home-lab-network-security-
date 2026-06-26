#!/usr/bin/env bash
# =============================================================================
# suricata-nfqueue.sh
# Inserts iptables NFQUEUE rules to route inter-VLAN traffic through
# Suricata for IPS inspection.
#
# How it works:
#   iptables intercepts packets in the FORWARD chain and redirects them
#   to NFQUEUE queue 1. Suricata listens on queue 1 (--queue-num 1) and
#   either accepts or drops packets based on loaded rules.
#
# Usage: sudo bash suricata-nfqueue.sh [flush]
#   flush = remove all NFQUEUE rules (cleanup mode)
#
# Tested on: Ubuntu 22.04 LTS with Suricata 8.0.5
# =============================================================================
 
set -euo pipefail
 
PARENT_IFACE="wlp2s0"
QUEUE_NUM=1
 
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log()  { echo -e "${GREEN}[+]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err()  { echo -e "${RED}[✗]${NC} $1"; exit 1; }
 
[[ $EUID -ne 0 ]] && err "Run as root: sudo bash $0"
 
# ── Flush mode ────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "flush" ]]; then
  warn "Flushing all NFQUEUE rules from FORWARD chain..."
  iptables -F FORWARD 2>/dev/null || true
  warn "All FORWARD chain NFQUEUE rules removed."
  warn "NOTE: This also removes Docker and UFW forward rules if present."
  warn "Restart Docker and UFW if needed: sudo systemctl restart docker ufw"
  exit 0
fi
 
# ── Check Suricata is running ─────────────────────────────────────────────────
if ! pidof suricata > /dev/null 2>&1; then
  err "Suricata is not running. Start it first: sudo systemctl start suricata"
fi
log "Suricata is running (PID: $(pidof suricata)) ✓"
 
# ── Insert NFQUEUE rules ───────────────────────────────────────────────────────
# Rule 1: VLAN 20 (Smart Device Sandbox) → VLAN 15 (VIP Vault)
#         Primary lateral movement detection path
log "Adding NFQUEUE rule: VLAN 20 → VLAN 15 (lateral movement path)..."
iptables -I FORWARD \
  -i "${PARENT_IFACE}.20" \
  -o "${PARENT_IFACE}.15" \
  -j NFQUEUE --queue-num "$QUEUE_NUM"
 
# Rule 2: Telus base network → VLAN 10 (Secure Lab)
#         Prevents ISP subnet from probing lab
log "Adding NFQUEUE rule: Telus base → VLAN 10 (unauthorized probe path)..."
iptables -I FORWARD \
  -i "${PARENT_IFACE}" \
  -o "${PARENT_IFACE}.10" \
  -j NFQUEUE --queue-num "$QUEUE_NUM"
 
# Rule 3: Telus base network → VLAN 15 (VIP Vault)
#         Prevents ISP subnet from probing vault
log "Adding NFQUEUE rule: Telus base → VLAN 15 (unauthorized probe path)..."
iptables -I FORWARD \
  -i "${PARENT_IFACE}" \
  -o "${PARENT_IFACE}.15" \
  -j NFQUEUE --queue-num "$QUEUE_NUM"
 
# ── Verify ────────────────────────────────────────────────────────────────────
echo ""
log "=== FORWARD chain (NFQUEUE rules) ==="
iptables -L FORWARD -n -v | head -20
echo ""
log "NFQUEUE rules active. Suricata is now inspecting inter-VLAN traffic."
warn "These rules are not persistent. To persist: save with iptables-save"
warn "  sudo iptables-save > /etc/iptables/rules.v4"
