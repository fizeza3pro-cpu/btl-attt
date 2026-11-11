#!/usr/bin/env bash
# Kich ban tong hop S01: trinh sat -> danh lua -> can cau -> nguoi van hanh duyet -> chan hoan toan.
# Chay tu may that (Git Bash). Analyzer duoc dat MODE=apply RESPONSE=deceive trong luc chay, xong tra ve recommend.
#   bash scripts/run-soc-scenario.sh [hau-to] [--no-approve]
set -uo pipefail
SUFFIX=${1:-01}; NOAPPROVE=${2:-}
ID="S01-$SUFFIX"; T=10.77.0.20; SOC=http://192.168.56.101:9000
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
if [ "$SUFFIX" = "cleanup" ]; then
  $SSH labB "for l in l1 l2 dec; do sudo /usr/local/sbin/lab-block del \$l 10.77.0.10 >/dev/null; done; printf 'MODE=recommend\nRESPONSE=deceive\n' | sudo tee /etc/default/lab-analyzer >/dev/null; sudo systemctl restart lab-analyzer; sudo /usr/local/sbin/lab-block status; cat /etc/default/lab-analyzer"
  exit 0
fi
A() { $SSH labA "$1" 2>/dev/null; }
step() { echo; echo "=== $1"; }
inc_new() { $SSH labB "sudo tail -n +$(( $1 + 1 )) /var/lib/lab-analyzer/incidents.jsonl | jq -r '\"  [analyzer] \(.suspect_ip) diem=\(.score) -> \(.decision)  \([.attack[].id] | join(\",\"))\" + (if .action then \"  [\" + .action.result.msg + \"]\" else \"\" end)'"; }
cnt() { $SSH labB "sudo wc -l < /var/lib/lab-analyzer/incidents.jsonl"; }

$SSH labB "printf 'MODE=apply\nRESPONSE=deceive\n' | sudo tee /etc/default/lab-analyzer >/dev/null && sudo systemctl restart lab-analyzer && sudo ~/lab/case-start.sh '$ID' 'Kich ban SOC: trinh sat, danh lua, can cau, duyet chan' 'deceive sau trinh sat; attacker_engaged khi dung honeytoken; l2 sau khi duyet; C khong bi anh huong' attack" >/dev/null
sleep 3

step "1. C (khach hang) mua hang va dang nhap binh thuong"
echo "  C trang chu: $($SSH labC "curl.exe -s -o NUL -w '%{http_code}' http://$T/")  C dang nhap: $($SSH labC "curl.exe -s -o NUL -w '%{http_code}' -H 'Content-Type: application/json' --data-binary '@C:\\Users\\vboxuser\\lab\\login-ok.json' http://$T/api/login")"

step "2. A trinh sat: quet 100 cong (nmap -sT)"
n=$(cnt); A "nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T | grep -E 'open'" | sed 's/^/  [A] /'
sleep 3; inc_new "$n"

step "3. A doc robots.txt va ma nguon trang chu (A khong biet minh dang o trong honeypot)"
A "curl -s http://$T/robots.txt" | sed 's/^/  [A] /'
A "curl -s http://$T/ | grep -o '<!-- TODO.*-->'" | sed 's/^/  [A] /'

step "4. A dung tai khoan lo trong comment de vao /admin, roi thu them mat khau khac"
n=$(cnt)
echo "  [A] /admin -> $(A "curl -s -o /dev/null -w '%{http_code}' http://$T/admin")  (200 = trang admin GIA)"
echo "  [A] dang nhap admin/LabShop@2026! -> $(A "curl -s -o /dev/null -w '%{http_code}' -d 'user=admin&pass=LabShop@2026!' http://$T/admin/login")  (302 = 'thanh cong' gia)"
echo "  [A] thu root/toor -> $(A "curl -s -o /dev/null -w '%{http_code}' -d 'user=root&pass=toor' http://$T/admin/login")"
sleep 3; inc_new "$n"

step "5. Dashboard SOC: yeu cau cho duyet (dashboard chi nhan ket noi tu may that -> goi tu Git Bash)"
STATE=$(curl -s $SOC/api/state)
printf '%s' "$STATE" | $SSH labB "jq -r '.pending[] | \"  [SOC] cho duyet: \(.incident_id) \(.suspect_ip) diem \(.score) \([.attack[].id] | join(\",\"))\"'"

if [ "$NOAPPROVE" != "--no-approve" ]; then
  step "6. Nguoi van hanh DUYET chan hoan toan (mo phong bam nut tren dashboard)"
  INC=$(printf '%s' "$STATE" | $SSH labB "jq -r '.pending[-1].incident_id'")
  TOK=$(curl -s $SOC/ | grep -o 'TOKEN="[0-9a-f]*"' | cut -d'"' -f2)
  curl -s -X POST -H 'Content-Type: application/json' -H "X-SOC-Token: $TOK" \
    -d "{\"action\":\"approve_l2\",\"ip\":\"10.77.0.10\",\"incident_id\":\"$INC\"}" $SOC/api/action | $SSH labB "jq -r '\"  [SOC] \" + .action + \" -> \" + .result'"
  sleep 1
  step "7. Kiem tra hieu luc"
  echo "  A web: $(A "curl -s -o /dev/null --connect-timeout 3 --max-time 4 -w '%{http_code}' http://$T/")   A SSH cong 22: $(A "timeout 4 bash -c 'exec 3<>/dev/tcp/$T/22' && echo mo || echo bi_chan")"
  echo "  C web: $($SSH labC "curl.exe -s -o NUL --max-time 4 -w '%{http_code}' http://$T/")"
fi

$SSH labB "sudo /usr/local/sbin/lab-block status" | sed 's/^/  [fw] /'
$SSH labB "sudo FLUSH_WAIT=2 ~/lab/case-stop.sh '$ID' >/dev/null; sudo cp /var/log/nginx/honeypot-access.log /var/lib/lab-analyzer/decisions.jsonl ~/lab/evidence/run-$ID/ 2>/dev/null; sudo chown -R \$(id -un) ~/lab/evidence/run-$ID"
echo; echo "Bang chung: ~/lab/evidence/run-$ID   Dashboard: $SOC"
echo "(Analyzer van o MODE=apply; A dang bi chan/danh lua neu da duyet. Go va tra ve recommend: bash scripts/run-soc-scenario.sh cleanup)"
