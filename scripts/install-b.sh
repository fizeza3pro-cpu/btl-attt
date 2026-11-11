#!/usr/bin/env bash
# =============================================================================
# install-b.sh — Dựng máy B (hệ thống phòng thủ) từ Ubuntu "trắng".
# Thay cho việc tải file OVA 7 GB: mỗi người tự cài Ubuntu rồi chạy script này.
#
#   sudo bash scripts/install-b.sh
#
# Tùy chọn (biến môi trường):
#   DEV_TOOLS=1   cài thêm Claude Code + Codex CLI (npm toàn cục)
#   SETUP_NET=1   tự áp netplan mạng lab (config/netplan-lab.yaml) — xem CẢNH BÁO
#
# ================= YÊU CẦU TRƯỚC KHI CHẠY =================
# 1) Ubuntu khớp bản đã làm: 26.04 (Python 3.14). Bản khác có thể lệch tên gói.
# 2) VM có 3 CARD MẠNG đúng thứ tự (VirtualBox → Settings → Network):
#       Adapter 1 = NAT                          -> enp0s3 (internet)
#       Adapter 2 = Host-only lab  10.77.0.0/24  -> enp0s8 (Suricata giám sát)
#       Adapter 3 = Host-only mgmt 192.168.56.0/24 -> enp0s9 (SSH, dashboard)
#    Đặt IP tĩnh: enp0s8 = 10.77.0.20/24, enp0s9 = 192.168.56.101/24
#    (dùng SETUP_NET=1, hoặc Settings → Network của GNOME, hoặc config/netplan-lab.yaml)
# 3) Đã git clone repo và đang đứng trong thư mục repo.
# =============================================================================
set -euo pipefail

[ "$(id -u)" -eq 0 ] || { echo "Phải chạy bằng sudo:  sudo bash scripts/install-b.sh"; exit 1; }
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
ok(){ printf '  \e[1;32m✓\e[0m %s\n' "$*"; }
warn(){ printf '  \e[1;33m!\e[0m %s\n' "$*"; }

echo "== [1/7] Cài gói hệ thống =="
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y suricata nginx nftables dnsmasq ethtool tcpdump jq curl git \
  python3 python3.14-venv nodejs npm >/dev/null
ok "suricata, nginx, nftables, dnsmasq, python venv, nodejs… đã cài"

echo "== [2/7] (tùy chọn) Mạng lab =="
if [ "${SETUP_NET:-0}" = 1 ]; then
  install -m 600 config/netplan-lab.yaml /etc/netplan/99-lab.yaml
  netplan apply && ok "Đã áp netplan (enp0s8=10.77.0.20, enp0s9=192.168.56.101)" \
    || warn "netplan apply lỗi — kiểm tra tên card/mạng VM"
else
  ip -br addr show enp0s8 2>/dev/null | grep -q 10.77.0.20 \
    && ok "enp0s8 đã có 10.77.0.20" \
    || warn "enp0s8 CHƯA có 10.77.0.20 — đặt IP tĩnh (xem config/netplan-lab.yaml) rồi chạy lại nếu dịch vụ không lên"
fi

echo "== [3/7] User hệ thống + sudoers =="
add_user(){ # $1=user  $2=group phụ (tùy chọn)
  getent group "$1" >/dev/null || groupadd --system "$1"
  id "$1" >/dev/null 2>&1 || useradd --system --gid "$1" --home-dir "/home/$1" \
      --create-home --shell /usr/sbin/nologin "$1"
  [ -n "${2:-}" ] && usermod -aG "$2" "$1"
}
add_user labresp adm
add_user labhoney ""
add_user labshop ""
cat > /etc/sudoers.d/lab-response <<'SUDO'
labresp ALL=(root) NOPASSWD: /usr/local/sbin/lab-block
labresp ALL=(root) NOPASSWD: /usr/local/sbin/lab-rule
SUDO
chmod 440 /etc/sudoers.d/lab-response
visudo -cf /etc/sudoers.d/lab-response >/dev/null
ok "labresp (+adm), labhoney, labshop + sudoers"

echo "== [4/7] Thư mục trạng thái =="
install -d -o root -g root -m 755 /etc/nftables.d /var/lib/lab-rule /var/lib/lab-rulegen-benign-src
if [ ! -f /var/lib/lab-rule/auto.rules ]; then
  printf '# Rule tu sinh (lab-rulegen de xuat, nguoi van hanh duyet). Bat dau rong.\n' \
    > /var/lib/lab-rule/auto.rules
  chmod 644 /var/lib/lab-rule/auto.rules
fi
ok "/etc/nftables.d, /var/lib/lab-rule (+auto.rules), lab-rulegen-benign-src"

echo "== [5/7] Deploy cấu hình + mã nguồn (deploy.sh --local) =="
for c in sensor response soc web net; do
  echo "   -- $c --"
  bash scripts/deploy.sh "$c" --local
done
if [ -n "${SUDO_USER:-}" ]; then
  sudo -u "$SUDO_USER" bash scripts/deploy.sh tools --local >/dev/null 2>&1 \
    && ok "Script trợ giúp ~/lab cho $SUDO_USER" || warn "Bỏ qua ~/lab tools"
fi
ok "Đã deploy toàn bộ cấu hình và dịch vụ"

echo "== [6/7] Bật dịch vụ khởi động cùng máy =="
systemctl daemon-reload
systemctl enable suricata nginx lab-nic-offload lab-response lab-analyzer \
  lab-soc lab-honeypot lab-shop-api lab-rulegen lab-pcap-ring dnsmasq >/dev/null 2>&1 || true
ok "Đã enable 11 dịch vụ"

echo "== [7/7] (tùy chọn) Công cụ dev =="
if [ "${DEV_TOOLS:-0}" = 1 ]; then
  npm install -g @anthropic-ai/claude-code @openai/codex >/dev/null 2>&1 \
    && ok "Claude Code + Codex CLI" || warn "Bỏ qua dev tools (mạng npm?)"
else
  echo "   (bỏ qua; chạy lại với  DEV_TOOLS=1  để cài Claude Code + Codex)"
fi

echo
echo "================= XONG ================="
echo "Kiểm tra nhanh:"
echo "  systemctl is-active suricata nginx lab-shop-api lab-soc lab-honeypot"
echo "  curl -s http://localhost/api/health"
echo "Nếu dịch vụ nào không 'active': thường do MẠNG chưa đúng (enp0s8=10.77.0.20,"
echo "enp0s9=192.168.56.101) — sửa mạng rồi:  sudo systemctl restart <tên-dịch-vụ>"
