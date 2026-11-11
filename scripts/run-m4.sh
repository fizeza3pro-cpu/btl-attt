#!/usr/bin/env bash
# M4 - Danh gia: lap cac ca chinh, baseline tu C, cac ca bien. Chay tu may that (Git Bash).
# Dung: bash scripts/run-m4.sh [repeat|cbase|edge|all]
set -uo pipefail
PART=${1:-all}
GAP=${GAP:-15}
T=10.77.0.20
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
CT='powershell -NoProfile -ExecutionPolicy Bypass -File C:\Users\vboxuser\lab\c-traffic.ps1'

run_case() {   # id label host desc expect action
  local id="$1" label="$2" host="$3" desc="$4" expect="$5" action="$6"
  echo; echo "######## $id [$label] ########"
  $SSH labB "sudo ~/lab/case-start.sh '$id' '$desc' '$expect' '$label'" >/dev/null || { echo "START FAIL $id"; return 1; }
  $SSH "$host" "$action" 2>&1 | tail -n 4
  $SSH labB "sudo ~/lab/case-stop.sh '$id'" | sed -n '/Alert theo SID/,/Thoi diem/p' | grep -vE 'Alert theo|Thoi diem'
  sleep "$GAP"
}

NMAP_FAST="nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T | grep -E 'open|done'"

repeat_main() {   # lap 4 lan nua (lan 01 da co) -> tong 5 lan moi ca
  for r in 02 03 04 05; do
    run_case "N03-$r" normal labA "HTTP nhe tu A: 10 request, cach 2 s" "Khong alert" \
      "for i in \$(seq 10); do curl -s -o /dev/null -w '%{http_code} ' http://$T/; sleep 2; done; echo"
    run_case "N04-$r" normal labA "HTTP nhanh tu A: 30 request lien tuc" "Co the 1000001 (FP tin hieu yeu)" \
      "for i in \$(seq 30); do curl -s -o /dev/null -w '%{http_code} ' http://$T/; done; echo"
    run_case "N07-$r" normal labA "Duong dan hop le va gan giong bay" "Khong 1000002" \
      "curl -s -o /dev/null -w '%{http_code} ' http://$T/about.html; curl -s -o /dev/null -w '%{http_code}\n' http://$T/lab-administrator"
    run_case "A01-$r" attack labA "Tham do cong TCP connect 1-100, 20 goi/s" "1000001 + 1000003" "$NMAP_FAST"
    run_case "A02-$r" attack labA "robots.txt roi duong dan moi" "1000002" \
      "curl -s -o /dev/null http://$T/robots.txt; curl -s -o /dev/null -w 'lab-admin=%{http_code}\n' http://$T/lab-admin"
    run_case "A03-$r" attack labA "Tham do cong roi duong dan moi trong 60 s" "1000001 + 1000003 + 1000002" \
      "$NMAP_FAST; sleep 5; curl -s -o /dev/null -w 'lab-admin=%{http_code}\n' http://$T/lab-admin"
  done
}

c_baseline() {    # baseline tu win10, 3 lan moi ca
  for r in 01 02 03; do
    run_case "CN01-$r" normal labC "C: 10 request, cach 2 s" "Khong alert" "$CT -Mode light"
    run_case "CN04-$r" normal labC "C: 30 request lien tuc" "Co the 1000001" "$CT -Mode burst"
    run_case "CN05-$r" normal labC "C: tai gallery nhu trinh duyet (6 ket noi song song)" "Khong alert" "$CT -Mode browse -Parallel 6"
    run_case "CN06-$r" normal labC "C: tai gallery 32 ket noi song song" "Co the 1000001" "$CT -Mode browse -Parallel 32"
    run_case "CN09-$r" normal labC "C: khong thao tac 60 s (luu luong nen cua Windows)" "Khong alert" "$CT -Mode idle -Seconds 60"
  done
}

edge_cases() {
  for r in 01 02 03; do
    run_case "E01-$r" attack labA "Tham do cong CHAM 1-20, 1 cong / 1.5 s" "Du kien FN: duoi nguong 10/10 s" \
      "nmap -sT -Pn -n --max-retries 0 --scan-delay 1500ms -p 1-20 $T | grep -E 'open|done'"
  done
  run_case "E02a-01" attack labA "Duong dan moi ma hoa %6c" "1000002 neu Suricata chuan hoa URI" \
    "curl -s --path-as-is -o /dev/null -w '%{http_code}\n' 'http://$T/%6cab-admin'"
  run_case "E02b-01" attack labA "Duong dan moi voi // o dau" "Doi chieu Suricata va Nginx" \
    "curl -s --path-as-is -o /dev/null -w '%{http_code}\n' 'http://$T//lab-admin'"
  run_case "E02c-01" attack labA "Duong dan moi voi /./" "Doi chieu Suricata va Nginx" \
    "curl -s --path-as-is -o /dev/null -w '%{http_code}\n' 'http://$T/./lab-admin'"
  run_case "E02d-01" edge labA "Duong dan moi viet hoa /LAB-ADMIN" "Khong 1000002; Nginx 404 (khong cham bay)" \
    "curl -s --path-as-is -o /dev/null -w '%{http_code}\n' 'http://$T/LAB-ADMIN'"
  run_case "E02e-01" attack labA "Duong dan moi kem query ?x=1" "1000002; Nginx 403" \
    "curl -s -o /dev/null -w '%{http_code}\n' 'http://$T/lab-admin?x=1'"
}

rest_after_stop() {   # phan con lai sau lan dung giua chung ngay 08/11
  run_case "CN09-03" normal labC "C: khong thao tac 60 s (luu luong nen cua Windows)" "Khong alert" "$CT -Mode idle -Seconds 60"
  edge_cases
}

validate_v3() {   # kiem chung rule 1000005 tren bien the CHUA dung khi thiet ke rule
  run_case "E03-01" attack labA "Tham do cham 1-25, 1 cong / 3 s (bien the moi)" \
    "1000005: ~20 RST/60 s, tren nguong 10" \
    "nmap -sT -Pn -n --max-retries 0 --scan-delay 3000ms -p 1-25 $T | grep -E 'open|done'"
  run_case "E04-01" attack labA "Tham do rat cham 1-12, 1 cong / 8 s (duoi gioi han ly thuyet)" \
    "Du kien FN: ~7,5 RST/60 s, duoi nguong 10" \
    "nmap -sT -Pn -n --max-retries 0 --scan-delay 8000ms -p 1-12 $T | grep -E 'open|done'"
  run_case "N04-06" normal labA "HTTP nhanh tu A: 30 request lien tuc (kiem tra lai sau khi them rule)" \
    "Chi 1000001; khong 1000005" \
    "for i in \$(seq 30); do curl -s -o /dev/null -w '%{http_code} ' http://$T/; done; echo"
  run_case "CN06-04" normal labC "C: tai gallery 32 ket noi (kiem tra lai sau khi them rule)" \
    "Chi 1000001; khong 1000005" "$CT -Mode browse -Parallel 32"
}

case "$PART" in
  v3)     validate_v3 ;;
  rest)   rest_after_stop ;;
  repeat) repeat_main ;;
  cbase)  c_baseline ;;
  edge)   edge_cases ;;
  all)    repeat_main; c_baseline; edge_cases ;;
esac
echo; echo "XONG phan: $PART"
