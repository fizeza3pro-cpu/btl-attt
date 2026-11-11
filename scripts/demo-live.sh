#!/usr/bin/env bash
# Kich ban demo THAT de quay video (chay tren may that, trong cua so mintty "BTL-DEMO").
# Moi lenh deu chay that tren A/B/C; ghi moc thoi gian vao video/demo-marks.txt de dung khi cat ghep.
set -u
T=10.77.0.20
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
MARKS=${MARKS:-/d/BTL_ATTT/video/demo-marks.txt}
: > "$MARKS"
mark() { echo "$(date +%s.%N) $1" >> "$MARKS"; }
B=$'\e[1m'; R=$'\e[0m'; CY=$'\e[1;36m'; GR=$'\e[1;32m'; RD=$'\e[1;31m'; YL=$'\e[33m'; MU=$'\e[90m'
step() { echo; echo "${CY}━━━ $1 ━━━${R}"; sleep 1.2; }
cmd()  { echo "${YL}$1${R} ${B}\$${R} $2"; sleep 0.6; }
show() { $SSH labB "~/lab/demo-show.sh $*"; }

printf '\e]0;BTLDEMO\a'   # tieu de cua so chinh xac de ffmpeg tim thay
clear
# Chuan bi (khong hien): analyzer sang che do apply
$SSH labB "echo MODE=apply | sudo tee /etc/default/lab-analyzer >/dev/null && sudo systemctl restart lab-analyzer" >/dev/null 2>&1
sleep 3
mark start
echo "${B}BTL ATTT — Demo: phát hiện xâm nhập và phản ứng tự động${R}"
echo "${MU}A = Kali 10.77.0.10 (kẻ tấn công) · B = Ubuntu 10.77.0.20 (máy chủ) · C = Win10 10.77.0.30 (người dùng)${R}"
echo "${MU}Analyzer trên B: MODE=apply (được phép chặn tự động)${R}"
sleep 2.5

mark normal
step "BƯỚC 1 — Truy cập bình thường"
cmd "A" "curl http://$T/"
echo "  HTTP $($SSH labA "curl -s -o /dev/null -w '%{http_code}' http://$T/")"
cmd "C" "curl.exe http://$T/"
echo "  HTTP $($SSH labC "curl.exe -s -o NUL -w '%{http_code}' http://$T/")"
show fw
sleep 2

mark scan
off=$(show offset); n0=$(show inc-count)
step "BƯỚC 2 — A quét 100 cổng của B"
cmd "A" "nmap -sT -Pn -n --max-rate 20 -p 1-100 $T"
$SSH labA "nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T" | grep -E 'open|closed|done' | sed 's/^/  /'
sleep 2
mark scan_alerts
echo; echo "${B}Suricata trên B ghi cảnh báo:${R}"
show alerts "$off"
echo; echo "${B}Analyzer chấm điểm:${R}"
show inc "$n0"
show fw
echo "  ${YL}→ 120 điểm nhưng toàn tín hiệu giả mạo IP được → KHÔNG chặn${R}"
sleep 4

mark decoy
off=$(show offset); n1=$(show inc-count)
step "BƯỚC 3 — A truy cập đường dẫn bẫy /lab-admin"
cmd "A" "curl -i http://$T/lab-admin"
$SSH labA "curl -s -i http://$T/lab-admin" | head -1 | sed 's/^/  /'
sleep 1.5
mark decoy_alerts
echo; echo "${B}Suricata:${R}"
show alerts "$off"
echo; echo "${B}Analyzer:${R}"
show inc "$n1"
show fw
echo "  ${RD}→ Có tín hiệu từ kết nối TCP thật → CHẶN A (TCP/80, 60 giây)${R}"
sleep 4

mark verify
step "BƯỚC 4 — Kiểm tra hiệu lực"
cmd "A" "curl --connect-timeout 2 http://$T/"
r=$($SSH labA "curl -s -o /dev/null --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/")
echo "  ${RD}HTTP ${r} — A không kết nối được${R}"
cmd "C" "curl.exe http://$T/"
r=$($SSH labC "curl.exe -s -o NUL --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/")
echo "  ${GR}HTTP ${r} — C vẫn dùng web bình thường${R}"
show fw
sleep 3

mark wait
step "BƯỚC 5 — Chờ hết hạn chặn (tự gỡ trong kernel)"
while :; do
  r=$($SSH labA "curl -s -o /dev/null --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/")
  if [ "$r" = "200" ]; then break; fi
  echo "  $(date +%T)  A -> web: ${RD}${r}${R}   $($SSH labB "sudo nft list set inet lab_response blocked_l1 | grep -o 'expires [0-9a-z]*' || echo 'het han'")"
  sleep 4
done
mark recovered
echo "  $(date +%T)  A -> web: ${GR}${r}${R}  — A tự phục hồi"
show fw

$SSH labB "echo MODE=recommend | sudo tee /etc/default/lab-analyzer >/dev/null && sudo systemctl restart lab-analyzer" >/dev/null 2>&1
echo; echo "${GR}${B}KẾT THÚC DEMO${R}  ${MU}(analyzer trả về MODE=recommend)${R}"
mark end
sleep 4
