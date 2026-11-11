#!/usr/bin/env bash
# Kiem thu phan ung thu cong: chan A (muc 1, TCP/80, 60 s), xac minh, cho het han, do thoi gian phuc hoi.
# Chay tu may that (Git Bash). Dung: bash scripts/run-block-test.sh [hau-to]
set -uo pipefail
SUFFIX=${1:-01}
ID="R01-$SUFFIX"
T=10.77.0.20
A=10.77.0.10
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
now() { $SSH labB 'date +%s.%N'; }
a_http() { $SSH labA "curl -s -o /dev/null --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/" 2>/dev/null; }
c_http() { $SSH labC "curl.exe -s -o NUL --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/" 2>/dev/null; }
counter() { $SSH labB "sudo nft list chain inet lab_response input | grep -o 'packets [0-9]*' | awk '{print \$2}'"; }
elem() { $SSH labB "sudo nft list set inet lab_response blocked_l1 | grep -o 'elements = {[^}]*}' || echo 'elements = {}'"; }

$SSH labB "sudo ~/lab/case-start.sh '$ID' 'Chan thu cong A muc 1 (TCP/80, 60 s), xac minh A va C, phuc hoi' 'A: 200 -> that bai khi bi chan -> 200 sau het han; C luon 200; counter tang; cong 22 cua A khong bi anh huong'"

echo "1) Truoc khi chan: A -> web = $(a_http); C -> web = $(c_http)"
c0=$(counter); echo "   counter ban dau = $c0"

t_block=$(now)
$SSH labB "sudo nft add element inet lab_response blocked_l1 { $A }"
echo "2) Da chan luc $t_block: $(elem)"

r1=$(a_http); t_fail=$(now)
echo "3) Khi bi chan: A -> web = ${r1:-000} (000 = khong ket noi duoc)"
echo "   CUNG LUC: C -> web = $(c_http) (ky vong 200)"
echo "   A van SSH qua mang quan tri: $($SSH labA 'echo ok')"
echo "   A -> B cong 22 tren mang lab: $($SSH labA "timeout 3 bash -c 'exec 3<>/dev/tcp/$T/22' && echo mo || echo dong")"
c1=$(counter); echo "   counter sau khi bi chan = $c1 (tang $((c1 - c0)) goi)"

echo "4) Cho het han, thu lai moi 2 s..."
while :; do
  r=$(a_http)
  if [ "$r" = "200" ]; then t_ok=$(now); break; fi
  sleep 2
done
echo "   A truy cap lai duoc: $r luc $t_ok; set hien tai: $(elem)"

awk -v b="$t_block" -v f="$t_fail" -v o="$t_ok" 'BEGIN{
  printf "5) Tong thoi gian bi chan (tu lenh chan toi khi A vao lai) = %.1f s\n", o-b
  printf "   Tu lenh chan toi lan thu that bai dau tien ket thuc = %.1f s (gom timeout curl 2-3 s)\n", f-b }'

$SSH labB "sudo ~/lab/case-stop.sh '$ID'" | tail -n 9
