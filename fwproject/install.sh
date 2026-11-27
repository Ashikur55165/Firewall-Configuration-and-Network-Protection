#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="/opt/fwproject"
SERVICE_USER="fwproject"

if [[ "${EUID}" -eq 0 ]]; then
  echo "Run this installer as your normal Ubuntu user, not with sudo."
  echo "Example: bash install.sh"
  exit 1
fi

if ! command -v sudo >/dev/null 2>&1; then echo "sudo is required."; exit 1; fi

# Avoid silently competing with an already active UFW policy.
if command -v ufw >/dev/null 2>&1 && sudo ufw status 2>/dev/null | grep -q 'Status: active'; then
  echo "UFW is active. This project uses its own nftables table and should not be layered over an unknown active UFW policy."
  echo "Review your current firewall first. To replace UFW for this lab, run: sudo ufw disable"
  echo "Then run this installer again. The installer will not disable UFW automatically."
  exit 1
fi

sudo apt-get update
sudo apt-get install -y nftables python3 python3-venv python3-pip iproute2

DEFAULT_CIDR="$(python3 - <<'PY'
import ipaddress, subprocess, sys
p = subprocess.run(['ip','-o','-f','inet','addr','show','scope','global'], text=True, capture_output=True)
for line in p.stdout.splitlines():
    fields = line.split()
    if 'inet' in fields:
        try:
            print(ipaddress.ip_interface(fields[fields.index('inet')+1]).network)
            raise SystemExit
        except (ValueError, IndexError):
            pass
print('192.168.1.0/24')
PY
)"

echo
echo "The management subnet will be allowed to reach SSH (TCP/22) and the dashboard (TCP/5000)."
echo "Use the LAN subnet that contains the computers which administer/test this Ubuntu host."
read -r -p "Management IPv4 CIDR [${DEFAULT_CIDR}]: " ADMIN_CIDR
ADMIN_CIDR="${ADMIN_CIDR:-$DEFAULT_CIDR}"
if ! ADMIN_CIDR="$ADMIN_CIDR" python3 - <<'PY'
import ipaddress, os, sys
try:
    network = ipaddress.ip_network(os.environ['ADMIN_CIDR'], strict=False)
    if network.version != 4 or not network.is_private:
        raise ValueError('Use a private IPv4 LAN network, for example 192.168.1.0/24.')
except ValueError as exc:
    print(f'Invalid management network: {exc}')
    sys.exit(1)
PY
then exit 1; fi

read -r -p "Dashboard TCP port [5000]: " DASHBOARD_PORT
DASHBOARD_PORT="${DASHBOARD_PORT:-5000}"
if ! [[ "$DASHBOARD_PORT" =~ ^[0-9]+$ ]] || (( DASHBOARD_PORT < 1 || DASHBOARD_PORT > 65535 )); then
  echo "Invalid dashboard port."; exit 1
fi

APP_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(20))')"

sudo useradd --system --home-dir "$APP_DIR" --create-home --shell /usr/sbin/nologin "$SERVICE_USER" 2>/dev/null || true
sudo install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$APP_DIR" "$APP_DIR/instance"
sudo install -d -o root -g root -m 0755 /etc/fwproject
sudo install -o root -g root -m 0755 "$PROJECT_DIR/fwproject_firewall.py" /usr/local/sbin/fwproject-firewall
sudo install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0644 "$PROJECT_DIR/app.py" "$APP_DIR/app.py"
sudo install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0644 "$PROJECT_DIR/demo_server.py" "$APP_DIR/demo_server.py"
sudo install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0644 "$PROJECT_DIR/requirements.txt" "$APP_DIR/requirements.txt"
sudo install -d -o "$SERVICE_USER" -g "$SERVICE_USER" "$APP_DIR/templates"
sudo install -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0644 "$PROJECT_DIR/templates/index.html" "$APP_DIR/templates/index.html"

sudo python3 -m venv "$APP_DIR/venv"
sudo "$APP_DIR/venv/bin/pip" install --disable-pip-version-check -r "$APP_DIR/requirements.txt"
sudo chown -R "$SERVICE_USER:$SERVICE_USER" "$APP_DIR"

sudo tee /etc/fwproject/config.json >/dev/null <<EOF
{
  "admin_cidr": "$ADMIN_CIDR",
  "dashboard_port": $DASHBOARD_PORT,
  "ssh_port": 22
}
EOF
sudo chmod 0644 /etc/fwproject/config.json

sudo tee /etc/fwproject/web.env >/dev/null <<EOF
FWPROJECT_USER=admin
FWPROJECT_PASSWORD=$APP_PASSWORD
FWPROJECT_PORT=$DASHBOARD_PORT
EOF
sudo chmod 0640 /etc/fwproject/web.env
sudo chown root:"$SERVICE_USER" /etc/fwproject/web.env

# The dashboard can read kernel journal entries for the firewall's log prefix.
for group in adm systemd-journal; do
  if getent group "$group" >/dev/null; then sudo usermod -aG "$group" "$SERVICE_USER"; fi
done

sudo tee /etc/sudoers.d/fwproject >/dev/null <<EOF
$SERVICE_USER ALL=(root) NOPASSWD: /usr/local/sbin/fwproject-firewall apply, /usr/local/sbin/fwproject-firewall status
EOF
sudo chmod 0440 /etc/sudoers.d/fwproject
sudo visudo -cf /etc/sudoers.d/fwproject >/dev/null

sudo tee /etc/systemd/system/fwproject-firewall.service >/dev/null <<'EOF'
[Unit]
Description=Firewall Project nftables policy
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/fwproject-firewall apply
ExecReload=/usr/local/sbin/fwproject-firewall apply
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/fwproject-dashboard.service >/dev/null <<EOF
[Unit]
Description=Firewall Project web dashboard
After=network-online.target fwproject-firewall.service
Wants=network-online.target
Requires=fwproject-firewall.service

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
EnvironmentFile=/etc/fwproject/web.env
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/app.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full
ReadWritePaths=$APP_DIR/instance

[Install]
WantedBy=multi-user.target
EOF

sudo tee /etc/systemd/system/fwproject-demo.service >/dev/null <<EOF
[Unit]
Description=Firewall Project TCP/UDP demo services
After=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/venv/bin/python $APP_DIR/demo_server.py
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=full

[Install]
WantedBy=multi-user.target
EOF

sudo -u "$SERVICE_USER" "$APP_DIR/venv/bin/python" "$APP_DIR/app.py" --init-db
sudo systemctl daemon-reload
sudo systemctl enable fwproject-firewall.service fwproject-dashboard.service fwproject-demo.service
sudo systemctl restart fwproject-firewall.service
sudo systemctl restart fwproject-dashboard.service fwproject-demo.service

UBUNTU_IP="$(hostname -I | awk '{print $1}')"
echo
echo "=============================================================="
echo "Firewall Project installed."
echo "Dashboard: http://${UBUNTU_IP:-<UBUNTU-IP>}:${DASHBOARD_PORT}/"
echo "Username:  admin"
echo "Password:  ${APP_PASSWORD}"
echo "TCP demo:  ${UBUNTU_IP:-<UBUNTU-IP>}:8080"
echo "UDP demo:  ${UBUNTU_IP:-<UBUNTU-IP>}:9999"
echo "Management CIDR: ${ADMIN_CIDR}"
echo "=============================================================="
echo "Save the dashboard password now. The firewall defaults to DROP for other inbound traffic."
echo "From another computer, run: nmap -n -Pn -sT -p 22,5000,8080 ${UBUNTU_IP:-<UBUNTU-IP>}"
echo "Project logs: sudo journalctl -k -g FWPROJECT_ --no-pager"
echo "Dashboard logs: sudo journalctl -u fwproject-dashboard -f"
