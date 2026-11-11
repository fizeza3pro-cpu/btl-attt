#!/usr/bin/env bash
# Chay bo ca thu MVP tu may that (Git Bash): B ghi bang chung, A tao luu luong.
# Yeu cau: ~/.ssh/config co Host labA (Kali) va labB (Ubuntu), dang nhap bang khoa.
# Dung: bash scripts/run-mvp-tests.sh [hau-to-lan-chay]   vd: bash scripts/run-mvp-tests.sh 01
set -uo pipefail
SUFFIX=${1:-01}
GAP=${GAP:-15}          # nghi giua cac ca de cua so threshold 10 s het han
T=10.77.0.20
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"

run_case() {
  local id="$1-$SUFFIX" desc="$2" expect="$3" action="$4"
  echo
  echo "################ $id ################"
  $SSH labB "sudo ~/lab/case-start.sh '$id' '$desc' '$expect'" || return 1
  echo "[A] $action"
  $SSH labA "$action" 2>&1 | tail -n 15
  $SSH labB "sudo ~/lab/case-stop.sh '$id'"
  sleep "$GAP"
}

# ---- Nhom N: luu luong binh thuong (do bao nham) ----
run_case N03 "HTTP nhe tu A: 10 request, cach 2 s" \
  "Khong alert phat hien; khong chan" \
  "for i in \$(seq 10); do curl -s -o /dev/null -w '%{http_code} ' http://$T/; sleep 2; done; echo"

run_case N04 "HTTP nhanh tu A: 30 request lien tuc, moi request 1 ket noi moi" \
  "Co the SID 1000001 (FP duoc ghi nhan); khong 1000002/1000003" \
  "for i in \$(seq 30); do curl -s -o /dev/null -w '%{http_code} ' http://$T/; done; echo"

run_case N07 "Duong dan hop le va duong dan gan giong bay" \
  "Khong SID 1000002 (rule khop chat); Nginx 404 cho /lab-administrator" \
  "curl -s -o /dev/null -w '%{http_code} ' http://$T/about.html; curl -s -o /dev/null -w '%{http_code}\n' http://$T/lab-administrator"

# ---- Nhom A: hanh vi can phat hien ----
run_case A01 "Tham do cong TCP connect 1-100 (nmap -sT, 20 goi/s)" \
  "SID 1000001 (yeu) va 1000003 (cung co); khong 1000002" \
  "nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T | tail -n 6"

run_case A02 "Doc robots.txt roi truy cap duong dan moi" \
  "SID 1000002; khong 1000007 (Nginx tra 403)" \
  "curl -s http://$T/robots.txt; curl -s -o /dev/null -w 'lab-admin=%{http_code}\n' http://$T/lab-admin"

run_case A03 "Tham do cong roi truy cap duong dan moi trong 60 s" \
  "SID 1000001 + 1000003 + 1000002 cung nguon A; du dieu kien incident" \
  "nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T | tail -n 3; sleep 5; curl -s -o /dev/null -w 'lab-admin=%{http_code}\n' http://$T/lab-admin"

echo
echo "XONG. Bang chung tren B: ~/lab/evidence/run-*-$SUFFIX"
