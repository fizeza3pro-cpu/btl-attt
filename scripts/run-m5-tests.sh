#!/usr/bin/env bash
# M5 - kiem thu live analyzer + executor. Chay tu may that (Git Bash).
# Giai doan 1: MODE=recommend -> chi de xuat, firewall khong doi.
# Giai doan 2: MODE=apply     -> chan tu dong co gioi han, cooldown, phuc hoi.
# Cuoi cung tra analyzer ve MODE=recommend.
set -uo pipefail
T=10.77.0.20
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
WAIT_WINDOW=${WAIT_WINDOW:-125}   # > CORR_WINDOW 120 s de cua so cua nghi pham het han giua cac ca
INC=/var/lib/lab-analyzer/incidents.jsonl

a_http() { $SSH labA "curl -s -o /dev/null --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/" 2>/dev/null; }
c_http() { $SSH labC "curl.exe -s -o NUL --connect-timeout 2 --max-time 3 -w '%{http_code}' http://$T/" 2>/dev/null; }
fw()     { $SSH labB "sudo /usr/local/sbin/lab-block status"; }
inc_n()  { $SSH labB "sudo cat $INC 2>/dev/null | wc -l"; }
# In incident moi (Python chay tren B; may that khong can cai Python)
inc_new(){ $SSH labB "sudo tail -n +$(( $1 + 1 )) $INC 2>/dev/null | jq -r '\"  INCIDENT \(.suspect_ip) score=\(.score) unspoof=\(.has_unspoofable_signal) sids=\([.signals[].sid]) -> \(.decision) (tre \(.event_age_s) s)\" + (if .action then \" | action=\" + .action.status else \"\" end)'"; }
set_mode() { $SSH labB "echo MODE=$1 | sudo tee /etc/default/lab-analyzer >/dev/null && sudo systemctl restart lab-analyzer && sleep 2 && systemctl is-active lab-analyzer && ps -o args= -C python3 | grep -o 'mode [a-z]*'"; }
start() { $SSH labB "sudo ~/lab/case-start.sh '$1' '$2' '$3' '$4'" >/dev/null; }
stop()  { $SSH labB "sudo FLUSH_WAIT=3 ~/lab/case-stop.sh '$1'" | sed -n '/Alert theo SID/,/Thoi diem/p' | grep -vE 'Alert theo|Thoi diem'; }
scan_and_decoy="nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T | grep -c open; sleep 3; curl -s -o /dev/null -w 'lab-admin=%{http_code}\n' http://$T/lab-admin"

echo "=== Giai doan 1: MODE=recommend ==="
set_mode recommend
n0=$(inc_n)
start M5-REC-01 "Analyzer recommend: A quet + vao bay" "Incident recommend_block_l1; firewall khong doi; A van vao duoc" attack
$SSH labA "$scan_and_decoy"
sleep 3
inc_new "$n0"
echo "  firewall: $(fw)"
echo "  A -> web: $(a_http)   C -> web: $(c_http)"
stop M5-REC-01

echo; echo "Cho ${WAIT_WINDOW}s de cua so tuong quan cua A het han..."; sleep "$WAIT_WINDOW"

echo; echo "=== Giai doan 2: MODE=apply ==="
set_mode apply

n0=$(inc_n)
start M5-APP-01 "Analyzer apply: A chi vao bay (70 diem)" "incident_medium; KHONG chan" attack
$SSH labA "curl -s -o /dev/null -w 'lab-admin=%{http_code}\n' http://$T/lab-admin"
sleep 4
inc_new "$n0"; echo "  firewall: $(fw)"; echo "  A -> web: $(a_http)"
stop M5-APP-01
echo; echo "Cho ${WAIT_WINDOW}s..."; sleep "$WAIT_WINDOW"

n0=$(inc_n)
start M5-APP-02 "Analyzer apply: A quet + vao bay -> chan tu dong" "block_l1; A that bai; C 200; tu phuc hoi sau 60 s" attack
$SSH labA "$scan_and_decoy"
sleep 3
inc_new "$n0"
echo "  firewall: $(fw)"
echo "  A -> web: $(a_http)   C -> web: $(c_http)"

echo "  -- Cooldown: A lap lai hanh vi khi dang bi chan --"
before=$($SSH labB "sudo nft list set inet lab_response blocked_l1 | grep -o 'expires [0-9a-z]*'")
n1=$(inc_n)
$SSH labA "nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T | grep -c open"
sleep 3
after=$($SSH labB "sudo nft list set inet lab_response blocked_l1 | grep -o 'expires [0-9a-z]*'")
inc_new "$n1"
echo "  het han truoc: $before | sau: $after (khong duoc gia han)"

echo "  -- Cho het han --"
t0=$(date +%s)
while :; do r=$(a_http); [ "$r" = "200" ] && break; sleep 3; done
echo "  A vao lai duoc sau $(( $(date +%s) - t0 )) s ke tu luc bat dau cho; firewall: $(fw)"
stop M5-APP-02

echo; echo "=== Tra analyzer ve MODE=recommend ==="
set_mode recommend
echo "XONG M5"
