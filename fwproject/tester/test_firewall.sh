#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <UBUNTU_FIREWALL_IP>"
  echo "Example: $0 192.168.1.20"
  exit 2
fi
TARGET="$1"

if ! command -v nmap >/dev/null 2>&1; then
  echo "Nmap is required. Install it with: sudo apt install nmap"
  exit 1
fi

if ! [[ "$TARGET" =~ ^[0-9a-fA-F:.]+$ ]]; then
  echo "Enter an IPv4 or IPv6 address, not a hostname."
  exit 2
fi

echo "Target: $TARGET"
echo "TCP test of SSH, dashboard, and demo HTTP service:"
nmap -n -Pn -sT -sV --reason -p 22,5000,8080 "$TARGET"
echo
echo "UDP test of demo echo service (may take longer):"
nmap -n -Pn -sU --reason -p 9999 "$TARGET"
echo
echo "For a permitted TCP test, try: curl --max-time 3 http://$TARGET:8080/"
