# Firewall Configuration and Network Protection Project

A single-Ubuntu-host firewall lab based on the nftables. The Ubuntu computer runs `nftables`, a Python/Flask management dashboard, persistent firewall rules, kernel-drop logging, and two demo services. A second physical computer on the same reachable network performs authorized scans and connection tests. **No VMs are needed.**

## What is implemented

- `nftables` host INPUT firewall with default-drop policy in a dedicated `inet fwproject` table.
- Management-subnet access to TCP/22 (SSH) and the dashboard TCP port (default 5000).
- Rule creation, deletion, enable/disable, and immediate application from the dashboard.
- Source IPv4/IPv6 CIDR, TCP, UDP, ICMP, and any-protocol source rules; optional TCP/UDP destination port.
- Explicit block rules evaluated before connection tracking and custom allow rules.
- Basic ICMP rate limiting and a global TCP SYN rate-limit drop rule.
- Kernel log prefixes for dropped traffic and a dashboard log viewer.
- TCP HTTP demo on port 8080 and UDP echo demo on port 9999.
- A test script for a second computer using Nmap.

The project is a **host firewall**: its main chain filters inbound traffic to the Ubuntu machine. Outbound traffic is not restricted, and this setup does not turn Ubuntu into a router/firewall for other devices.

## Requirements

- Ubuntu 22.04/24.04 or a recent Ubuntu release with systemd.
- A normal Ubuntu user with `sudo` rights.
- Network connection between Ubuntu and the testing computer (same LAN is easiest).
- Nmap on the testing computer. Wireshark is optional for packet observation.

Do not run this on a production or remote-only server without console access. The policy intentionally blocks unmatched inbound traffic. Do not expose the dashboard or lab services to the public Internet.

## Install on Ubuntu

1. Extract the ZIP on Ubuntu.
2. Open a terminal in the extracted `fwproject` directory.
3. Run:

   ```bash
   chmod +x install.sh
   ./install.sh
   ```

4. When prompted for the management CIDR, enter the LAN subnet that contains the computer(s) you will use to administer/test the Ubuntu host, for example `192.168.1.0/24`. The installer suggests the subnet of the first active IPv4 interface; verify it before accepting.
5. Save the generated dashboard password shown at the end.

If UFW is already active, the installer stops instead of silently layering policies. Review the existing firewall; for this lab, you may choose to disable UFW manually with `sudo ufw disable`, then rerun the installer. Do not do this on a machine that depends on UFW protection without understanding the change.

Open `http://UBUNTU_LAN_IP:5000/` from a machine inside the configured management CIDR. The browser asks for Basic Authentication: username `admin`, password printed by the installer. The dashboard port can be changed during installation.

## Find the Ubuntu LAN address

```bash
ip -br address
hostname -I
```

Use the address on the interface connected to the testing computer, not `127.0.0.1`.

## Demonstrate the firewall from the second computer

Install Nmap on the second computer. On Kali/Debian/Ubuntu:

```bash
sudo apt update && sudo apt install -y nmap
```

On Windows, install Nmap from its official installer. Then run the included test script (or execute the equivalent command):

```bash
bash tester/test_firewall.sh UBUNTU_LAN_IP
```

The management subnet is allowed to access the dashboard and SSH ports. The demo TCP/UDP services are running, but the firewall initially blocks them from non-management traffic unless a rule is added.

### Test 1 — confirm the demo port is filtered

```bash
nmap -n -Pn -sT --reason -p 8080 UBUNTU_LAN_IP
```

### Test 2 — allow TCP/8080 from the tester

In the dashboard, create:

- Name: `Allow tester TCP demo`
- Action: `Allow`
- Source: the tester's IP, e.g. `192.168.1.50/32`
- Protocol: `TCP`
- Port: `8080`

The dashboard applies the rule immediately. Test:

```bash
curl --max-time 3 http://UBUNTU_LAN_IP:8080/
nmap -n -Pn -sT -sV --reason -p 8080 UBUNTU_LAN_IP
```

The HTTP demo should answer and Nmap should report the port open.

### Test 3 — block it again

Create a second rule with the same source/protocol/port but Action `Block`. Explicit block rules take precedence over custom allow rules. Test again:

```bash
curl --max-time 3 http://UBUNTU_LAN_IP:8080/
nmap -n -Pn -sT --reason -p 8080 UBUNTU_LAN_IP
```

The connection should time out and Nmap should normally report `filtered`. Delete/disable the block rule to restore access.

### Test 4 — UDP/9999

Create an `Allow` rule for the tester IP, protocol `UDP`, destination port `9999`, then test:

```bash
nmap -n -Pn -sU --reason -p 9999 UBUNTU_LAN_IP
```

The UDP demo echoes received datagrams. UDP scan results can be `open|filtered` depending on the probe and response; verify with a small UDP client or packet capture if needed. Use a block rule to compare behavior.

## Packet observation with Wireshark

On Ubuntu, start Wireshark or run:

```bash
sudo tcpdump -ni any 'host TESTER_IP and (tcp port 8080 or udp port 9999)'
```

Run the Nmap/curl tests again. A host firewall drop may be visible in packet capture on the host, depending on capture point and interface. Kernel drop messages are available with:

```bash
sudo journalctl -k -g FWPROJECT_ --since '30 minutes ago' --no-pager
```

Dashboard logs are available at **Firewall activity logs**. Add the service user to the `adm`/`systemd-journal` groups during installation; if log access is unavailable, use the `journalctl` command with `sudo`.

## Useful administration commands

```bash
sudo systemctl status fwproject-firewall fwproject-dashboard fwproject-demo
sudo systemctl restart fwproject-dashboard fwproject-demo
sudo systemctl restart fwproject-firewall
sudo nft list table inet fwproject
sudo journalctl -u fwproject-dashboard -f
sudo journalctl -k -g FWPROJECT_ --no-pager
```

The project firewall is loaded into its own table and does not flush the entire nftables ruleset. To remove the project, run `sudo bash uninstall.sh` from the extracted project folder. Uninstall removes only the `inet fwproject` table and project files; it does not intentionally delete other nftables tables.

## Safe testing scope and limitations

Use only systems and networks you own or have explicit permission to test. The included tester runs targeted Nmap scans against the selected Ubuntu host; it does not run denial-of-service, ARP poisoning, DNS poisoning, or IP-spoofing attacks. The SYN rate-limit rule provides a simple mitigation demonstration, not production-grade DDoS protection. ARP spoofing generally requires a separate same-LAN experiment and can disrupt other users, so it is not automated here. This implementation does not provide a VPN, DNS resolver, router segmentation, or a complete IDS.

## Troubleshooting

- **Dashboard not reachable:** verify that your tester IP belongs to the management CIDR; check `sudo systemctl status fwproject-dashboard`; confirm TCP/5000 is not changed; run `sudo nft list table inet fwproject`.
- **Firewall failed to start:** inspect `sudo journalctl -u fwproject-firewall --no-pager`; check `sudo nft --version`; the helper syntax-checks the ruleset before applying it.
- **Nmap says closed instead of filtered:** the demo service may not be running. Check `sudo systemctl status fwproject-demo`. A firewall drop generally appears as `filtered`, while an allowed port with no listening service appears `closed`.
- **No logs:** nftables kernel logging can be rate-limited and journal permissions vary. Check using the `sudo journalctl` command above.
- **Network manager/DHCP:** the policy includes DHCP client replies to UDP/68, loopback, established/related connections, and limited ICMP/ICMPv6.

## Project directory

```text
fwproject/
├── app.py                    # Flask dashboard/API
├── fwproject_firewall.py     # root-owned nftables rule compiler/controller
├── demo_server.py            # TCP/UDP test services
├── install.sh                # Ubuntu installer
├── uninstall.sh              # cleanup
├── requirements.txt
├── templates/index.html      # dashboard UI
└── tester/test_firewall.sh  # second-computer Nmap test
```
