#!/usr/bin/env bash
# =============================================================================
# deploy.sh — Đẩy mã nguồn trong repo lên máy B (Ubuntu) rồi restart dịch vụ.
#
# Thay cho việc sửa tay trực tiếp trên VM. Chạy từ Git Bash trên máy thật.
# Mỗi người chỉ cần đẩy MẢNG của mình:
#
#   bash scripts/deploy.sh sensor      # P1: Suricata + rule + rulegen
#   bash scripts/deploy.sh response    # P2: analyzer + nftables
#   bash scripts/deploy.sh soc         # P3a: dashboard + honeypot
#   bash scripts/deploy.sh web         # P3b: Lab Shop (API + web tĩnh + nginx)
#   bash scripts/deploy.sh tools       # các script trợ giúp ~/lab/*.sh
#   bash scripts/deploy.sh net         # dnsmasq (ít khi đổi)
#   bash scripts/deploy.sh all         # tất cả
#
# Cờ:
#   --host=labB     máy đích SSH (mặc định: biến LAB_HOST hoặc "labB")
#   --dry-run       chỉ in ra sẽ làm gì, KHÔNG thay đổi gì trên B
#
# Trước khi reload luôn KIỂM TRA cú pháp (suricata -T, nginx -t, nft -c);
# sai thì dừng, KHÔNG reload dịch vụ đang chạy.
#
# Đường dẫn nginx/www có thể khác máy — ghi đè trong deploy.local.conf nếu cần
# (file này bị .gitignore, riêng từng người).
# =============================================================================
set -euo pipefail

HOST="${LAB_HOST:-labB}"
DRYRUN=0
COMPONENT=""

# Đường dẫn có thể ghi đè trong deploy.local.conf
NGINX_LAB_DEST="/etc/nginx/sites-available/lab"
NGINX_HP_DEST="/etc/nginx/sites-available/lab-honeypot"
WWW_ROOT="/var/www/lab"
[ -f "$(dirname "$0")/../deploy.local.conf" ] && . "$(dirname "$0")/../deploy.local.conf"

for a in "$@"; do
  case "$a" in
    --host=*)  HOST="${a#--host=}" ;;
    --dry-run) DRYRUN=1 ;;
    -h|--help) grep '^#' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    sensor|response|soc|web|tools|net|all) COMPONENT="$a" ;;
    *) echo "Tham số lạ: $a (chạy --help)"; exit 2 ;;
  esac
done
[ -z "$COMPONENT" ] && { echo "Thiếu mảng cần đẩy. Ví dụ: bash scripts/deploy.sh sensor  (xem --help)"; exit 2; }

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# --- Manifest: dòng "relpath<TAB>dest<TAB>owner<TAB>group<TAB>mode" ---
# owner "@me" = cài vào $HOME trên B, không cần sudo (các script trợ giúp).
emit() { printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "$5"; }

manifest_sensor() {
  emit config/suricata.yaml          /etc/suricata/suricata.yaml        root root 0644
  emit config/local.rules            /etc/suricata/rules/local.rules    root root 0644
  emit config/lab-nic-offload.service /etc/systemd/system/lab-nic-offload.service root root 0644
  emit config/lab-pcap-ring.service  /etc/systemd/system/lab-pcap-ring.service   root root 0644
  emit config/lab-rulegen.service    /etc/systemd/system/lab-rulegen.service     root root 0644
  emit scripts/lab-rulegen.py        /usr/local/lib/lab/lab-rulegen.py  root root 0755
  emit scripts/lab-rule              /usr/local/sbin/lab-rule           root root 0755
}
manifest_response() {
  emit scripts/analyzer.py           /usr/local/lib/lab/analyzer.py     root root 0755
  emit scripts/lab-block             /usr/local/sbin/lab-block          root root 0755
  emit config/lab-response.nft       /etc/nftables.d/lab-response.nft   root root 0644
  emit config/lab-analyzer.service   /etc/systemd/system/lab-analyzer.service root root 0644
  emit config/lab-response.service   /etc/systemd/system/lab-response.service root root 0644
}
manifest_soc() {
  emit scripts/lab-soc.py            /usr/local/lib/lab/lab-soc.py      root root 0755
  emit scripts/lab-honeypot.py       /usr/local/lib/lab/lab-honeypot.py root root 0755
  emit config/lab-soc.service        /etc/systemd/system/lab-soc.service root root 0644
  emit config/lab-honeypot.service   /etc/systemd/system/lab-honeypot.service root root 0644
  emit config/nginx-honeypot.conf    "$NGINX_HP_DEST"                   root root 0644
}
manifest_web() {
  # Web app mới: FastAPI + SQLite trong /usr/local/lib/lab/webapp (chạy bằng venv)
  emit webapp/app.py                 /usr/local/lib/lab/webapp/app.py        root root 0755
  emit webapp/seed.py                /usr/local/lib/lab/webapp/seed.py       root root 0755
  emit webapp/db/schema.sql          /usr/local/lib/lab/webapp/db/schema.sql root root 0644
  emit webapp/requirements.txt       /usr/local/lib/lab/webapp/requirements.txt root root 0644
  emit config/lab-shop-api.service   /etc/systemd/system/lab-shop-api.service root root 0644
  emit config/nginx-lab.conf         "$NGINX_LAB_DEST"                  root root 0644
  local f
  for f in config/www/*; do
    [ -d "$f" ] && continue
    emit "$f" "$WWW_ROOT/$(basename "$f")" root root 0644
  done
  for f in config/www/img/*; do
    [ -e "$f" ] || continue
    emit "$f" "$WWW_ROOT/img/$(basename "$f")" root root 0644
  done
}
manifest_net() {
  emit config/dnsmasq-ids-lab.conf   /etc/dnsmasq.d/ids-lab.conf        root root 0644
}
manifest_tools() {
  local f
  for f in scripts/*.sh; do
    [ "$f" = "scripts/deploy.sh" ] && continue
    emit "$f" "lab/$(basename "$f")" @me @me 0755
  done
}

# --- Dịch vụ cần xử lý sau khi đẩy (reload/restart) ---
SERVICES=""; DO_SURICATA=0; DO_NGINX=0; DO_NFT=0; DO_DAEMONRELOAD=0
plan_services() {
  case "$1" in
    sensor)   DO_SURICATA=1; DO_DAEMONRELOAD=1; SERVICES="lab-rulegen lab-pcap-ring lab-nic-offload" ;;
    response) DO_NFT=1; DO_DAEMONRELOAD=1; SERVICES="lab-response lab-analyzer" ;;
    soc)      DO_NGINX=1; DO_DAEMONRELOAD=1; SERVICES="lab-honeypot lab-soc" ;;
    web)      DO_NGINX=1; DO_DAEMONRELOAD=1; SERVICES="lab-shop-api" ;;
    net)      SERVICES="dnsmasq" ;;
    tools)    : ;;
  esac
}

COMPONENTS="$COMPONENT"
[ "$COMPONENT" = "all" ] && COMPONENTS="sensor response soc web net tools"

# Gom manifest + kế hoạch dịch vụ
MANIFEST="$(mktemp)"; TARBALL=""; trap 'rm -f "${MANIFEST:-}" "${TARBALL:-}" 2>/dev/null || true' EXIT
ALLSVC=""
for c in $COMPONENTS; do
  "manifest_$c" >> "$MANIFEST"
  plan_services "$c"
  ALLSVC="$ALLSVC $SERVICES"
  [ "$DO_SURICATA" = 1 ] && SURI=1
  [ "$DO_NGINX" = 1 ] && NGX=1
  [ "$DO_NFT" = 1 ] && NFT=1
  [ "$DO_DAEMONRELOAD" = 1 ] && DRL=1
  DO_SURICATA=0; DO_NGINX=0; DO_NFT=0; DO_DAEMONRELOAD=0
done
SURI=${SURI:-0}; NGX=${NGX:-0}; NFT=${NFT:-0}; DRL=${DRL:-0}
SVCLIST="$(echo $ALLSVC | tr ' ' '\n' | grep -v '^$' | sort -u | tr '\n' ' ')"
# Mảng web cần dựng venv FastAPI + seed DB trên B
case " $COMPONENTS " in *" web "*) WEBAPP=1 ;; *) WEBAPP=0 ;; esac

echo "== deploy.sh =="
echo "  Máy đích : $HOST"
echo "  Mảng     : $COMPONENT"
echo "  Dịch vụ  : ${SVCLIST:-(không)}  | suricata=$SURI nginx=$NGX nft=$NFT daemon-reload=$DRL"
echo "  Số file  : $(wc -l < "$MANIFEST")"
echo

if [ "$DRYRUN" = 1 ]; then
  echo "[DRY-RUN] Sẽ cài các file sau (nguồn -> đích, owner mode):"
  awk -F'\t' '{printf "  %-34s -> %s  (%s %s)\n", $1, $2, $3, $5}' "$MANIFEST"
  exit 0
fi

# Đóng gói: manifest + đúng các file cần đẩy (giữ đường dẫn tương đối)
TARBALL="$(mktemp --suffix=.tgz)"
tar -czf "$TARBALL" -C "$ROOT" \
    $(cut -f1 "$MANIFEST" | sort -u) \
    -C "$(dirname "$MANIFEST")" "$(basename "$MANIFEST")"

# B1: đẩy tarball thành FILE trên B (stdin của ssh = tarball)
cat "$TARBALL" | ssh "$HOST" 'cat > /tmp/lab-deploy.tgz'
# B2: chạy installer (stdin của ssh = script heredoc; tar đọc từ FILE)
ssh "$HOST" "MANIFEST_NAME='$(basename "$MANIFEST")' SVCLIST='$SVCLIST' SURI='$SURI' NGX='$NGX' NFT='$NFT' DRL='$DRL' WEBAPP='$WEBAPP' bash -s" <<'REMOTE'
set -euo pipefail
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"; rm -f /tmp/lab-deploy.tgz' EXIT
tar -xzf /tmp/lab-deploy.tgz -C "$WORK"
MAN="$WORK/$MANIFEST_NAME"
cd "$WORK"

echo "-- Cài file --"
while IFS=$'\t' read -r rel dest owner group mode; do
  [ -z "$rel" ] && continue
  if [ "$owner" = "@me" ]; then
    dst="$HOME/$dest"
    install -D -m "$mode" "$rel" "$dst"
  else
    sudo install -D -o "$owner" -g "$group" -m "$mode" "$rel" "$dest"
  fi
  echo "  ✓ $dest"
done < "$MAN"

# nginx: đảm bảo bật site (sites-available -> sites-enabled)
if [ "$NGX" = 1 ]; then
  for sa in /etc/nginx/sites-available/lab /etc/nginx/sites-available/lab-honeypot; do
    [ -f "$sa" ] && sudo ln -sf "$sa" "/etc/nginx/sites-enabled/$(basename "$sa")"
  done
fi

# Web app: dựng venv FastAPI + seed CSDL (idempotent)
if [ "$WEBAPP" = 1 ]; then
  echo "-- Web app: venv + CSDL --"
  VENV=/usr/local/lib/lab/webapp/venv
  [ -x "$VENV/bin/python" ] || sudo python3 -m venv "$VENV"
  sudo "$VENV/bin/pip" install -q --upgrade pip
  sudo "$VENV/bin/pip" install -q -r /usr/local/lib/lab/webapp/requirements.txt \
    && echo "  ✓ venv + fastapi/uvicorn" || { echo "  ✗ pip cài thất bại (B có ra pypi không?)"; exit 1; }
  sudo install -d -o labshop -g labshop -m 0750 /var/lib/lab-shop
  if sudo test ! -f /var/lib/lab-shop/lab.db; then
    sudo -u labshop "$VENV/bin/python" /usr/local/lib/lab/webapp/seed.py /var/lib/lab-shop/lab.db \
      && echo "  ✓ tạo lab.db" || echo "  ! seed lab.db lỗi"
  else
    echo "  ✓ lab.db đã có (giữ nguyên đơn hàng)"
  fi
fi

echo "-- Kiểm tra cú pháp --"
if [ "$SURI" = 1 ]; then
  sudo suricata -T -c /etc/suricata/suricata.yaml -S /etc/suricata/rules/local.rules >/dev/null \
    && echo "  ✓ suricata -T OK" || { echo "  ✗ Suricata config/rule SAI — DỪNG, không reload"; exit 1; }
fi
if [ "$NGX" = 1 ]; then
  sudo nginx -t >/dev/null 2>&1 && echo "  ✓ nginx -t OK" || { echo "  ✗ nginx -t SAI — DỪNG"; exit 1; }
fi
if [ "$NFT" = 1 ]; then
  sudo nft -c -f /etc/nftables.d/lab-response.nft >/dev/null 2>&1 && echo "  ✓ nft -c OK" || { echo "  ✗ nft kiểm tra SAI — DỪNG"; exit 1; }
fi

echo "-- Áp dụng --"
[ "$DRL" = 1 ] && { sudo systemctl daemon-reload; echo "  ✓ systemctl daemon-reload"; }
if [ "$SURI" = 1 ]; then
  sudo systemctl reload suricata 2>/dev/null && echo "  ✓ suricata reload" \
    || { sudo systemctl restart suricata; echo "  ✓ suricata restart"; }
fi
if [ "$NGX" = 1 ]; then sudo systemctl reload nginx && echo "  ✓ nginx reload"; fi
for s in $SVCLIST; do
  sudo systemctl restart "$s" 2>/dev/null && echo "  ✓ restart $s" || echo "  ! bỏ qua $s (chưa cài?)"
done

echo "-- Trạng thái --"
for s in suricata nginx $SVCLIST; do
  printf '  %-16s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || echo n/a)"
done
echo "Xong trên $(hostname)."
REMOTE

echo
echo "✓ Đã đẩy mảng '$COMPONENT' lên $HOST."
