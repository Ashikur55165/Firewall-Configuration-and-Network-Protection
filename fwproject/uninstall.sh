#!/usr/bin/env bash
set -euo pipefail
if [[ "${EUID}" -ne 0 ]]; then echo "Run with sudo: sudo bash uninstall.sh"; exit 1; fi
systemctl disable --now fwproject-dashboard.service fwproject-demo.service fwproject-firewall.service 2>/dev/null || true
nft delete table inet fwproject 2>/dev/null || true
rm -f /etc/systemd/system/fwproject-firewall.service /etc/systemd/system/fwproject-dashboard.service /etc/systemd/system/fwproject-demo.service
rm -f /etc/sudoers.d/fwproject /usr/local/sbin/fwproject-firewall
rm -rf /etc/fwproject /opt/fwproject
systemctl daemon-reload
userdel fwproject 2>/dev/null || true
echo "Firewall Project removed. Other nftables tables were not intentionally deleted."
echo "Note: if you added external project rules elsewhere, review them separately."
