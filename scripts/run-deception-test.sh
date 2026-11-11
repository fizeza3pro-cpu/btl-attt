#!/usr/bin/env bash
# Kiem thu chuoi danh lua (D01). Chay tu may that (Git Bash). Dieu khien thu cong muc "dec" (khong qua analyzer).
set -uo pipefail
SUFFIX=${1:-01}; ID="D01-$SUFFIX"
T=10.77.0.20
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
code() { $SSH "$1" "$2" 2>/dev/null; }
A() { code labA "curl -s -o /dev/null --max-time 5 -w '%{http_code}' $1"; }

$SSH labB "sudo ~/lab/case-start.sh '$ID' 'Chuoi danh lua: A bi chuyen sang honeypot, dung honeytoken' 'A thay trang admin gia; moi thao tac ghi vao events.jsonl; C khong bi anh huong' attack" >/dev/null
n0=$($SSH labB "sudo cat /var/log/lab-honeypot/events.jsonl 2>/dev/null | wc -l")

echo "1) Binh thuong:        A /admin -> $(A http://$T/admin)   (ky vong 403)"
$SSH labB "sudo /usr/local/sbin/lab-block add dec 10.77.0.10" | sed 's/^/   /'
sleep 1
echo "2) A bi danh lua:      A /admin -> $(A http://$T/admin)   (ky vong 200 = trang admin gia)"
echo "   C cung luc:         C /admin -> $(code labC "curl.exe -s -o NUL --max-time 5 -w '%{http_code}' http://$T/admin")   (ky vong 403 = C khong bi anh huong)"
echo "   A trang chu:        A /      -> $(A http://$T/)   (ky vong 200 = A khong nhan ra)"
echo "3) A thu dang nhap sai:      $(code labA "curl -s -o /dev/null -w '%{http_code}' -d 'user=root&pass=123456' http://$T/admin/login")"
echo "4) A dung tai khoan trong comment HTML: $(code labA "curl -s -o /dev/null -w '%{http_code}' -d 'user=admin&pass=LabShop@2026!' http://$T/admin/login")  (302 = 'vao duoc')"
echo "5) A tai file trong robots.txt: $(A http://$T/backup/db-2026-11.sql.gz)"
echo "6) A dung API key trong shop.js: $(code labA "curl -s -o /dev/null -w '%{http_code}' -H 'X-Api-Key: ls_live_7f3a9c2e51b84d06a1e9' http://$T/api/admin/orders")"
echo "7) A ket noi cong bay 3306:  $(code labA "timeout 3 bash -c 'exec 3<>/dev/tcp/$T/3306; head -c 40 <&3 | tr -cd \"[:print:]\"'")"
$SSH labB "sudo /usr/local/sbin/lab-block status; sudo /usr/local/sbin/lab-block del dec 10.77.0.10 >/dev/null"
echo "8) Sau khi go:         A /admin -> $(A http://$T/admin)   (ky vong 403)"
echo
echo "== Su kien honeypot ghi duoc trong ca nay:"
$SSH labB "sudo tail -n +$((n0 + 1)) /var/log/lab-honeypot/events.jsonl | jq -r '\"  \(.ts[11:19])  \(.src_ip)  \(.kind)  \(.user // \"\") \(.password // \"\") \(.path // \"\") \(.port // \"\")\"'"
$SSH labB "sudo FLUSH_WAIT=2 ~/lab/case-stop.sh '$ID' >/dev/null; sudo cp /var/log/nginx/honeypot-access.log ~/lab/evidence/run-$ID/ 2>/dev/null; sudo tail -n +$((n0 + 1)) /var/log/lab-honeypot/events.jsonl > /tmp/hp.jsonl; cp /tmp/hp.jsonl ~/lab/evidence/run-$ID/honeypot-events.jsonl"
