#!/usr/bin/env bash
# Dua B ve TRANG THAI SACH truoc moi kich ban (chay tren B):
#   ~/lab/reset-lab.sh [che-do] [--xoa-rule]
#     che-do:  recommend (mac dinh, an toan: chi de xuat) | danh-lua (tu dong, danh lua truoc) | chan (tu dong, chan web ngay)
#     --xoa-rule: thu hoi het rule tu sinh + xoa phieu (mac dinh GIU NGUYEN rule; chi can khi demo lai kich ban 9)
# Lam gi:
#   1. Go moi chan / danh lua cua firewall           (lab-block del ...)
#   2. Bo qua moi yeu cau "cho duyet" tren dashboard  (ghi vao decisions.jsonl nhu nguoi van hanh bam "Bo qua")
#   3. Khoi dong lai analyzer theo che do chon        (xoa tri nho: diem trong 120 s, muc da bao)
#   4. Khoi dong lai API cua hang                     (xoa khoa dang nhap 5 phut, gio hang, phien)
#   5. (chi khi --xoa-rule) Thu hoi rule tu sinh + xoa phieu de xuat (rulegen-reset.sh)
# KHONG xoa log / lich su: van dung lam bang chung va bao cao.
set -u
MODE_ARG=${1:-recommend}
DROP_RULES=0
for a in "$@"; do [ "$a" = "--xoa-rule" ] && DROP_RULES=1; done
case "$MODE_ARG" in
  recommend|--xoa-rule) MODE=recommend; RESP=deceive; TXT="CHI DE XUAT (khong tu phan ung)" ;;
  danh-lua|deceive)     MODE=apply;     RESP=deceive; TXT="TU DONG - danh lua truoc" ;;
  chan|block)           MODE=apply;     RESP=block;   TXT="TU DONG - chan web ngay" ;;
  *) echo "Che do khong hop le: $MODE_ARG  (dung: recommend | danh-lua | chan)"; exit 2 ;;
esac
ok(){ printf '  \e[1;32m✓\e[0m %s\n' "$*"; }
sudo -n true 2>/dev/null || sudo true || exit 1
echo "== Dua B ve trang thai sach =="

# 1. firewall
for ip in $(sudo /usr/local/sbin/lab-block status | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+ expires' | awk '{print $1}' | sort -u) 10.77.0.10; do
  for l in l1 l2 dec; do sudo /usr/local/sbin/lab-block del "$l" "$ip" >/dev/null 2>&1; done
done
ok "Firewall: khong con IP nao bi chan / danh lua"

# 2. yeu cau cho duyet tren dashboard
S=http://192.168.56.101:9000
TOK=$(curl -s -m 5 "$S/" | grep -o 'TOKEN="[0-9a-f]*"' | cut -d'"' -f2)
n=0
if [ -n "$TOK" ]; then
  while read -r inc ip; do
    [ -z "$inc" ] && continue
    curl -s -o /dev/null -m 10 -X POST -H "Content-Type: application/json" -H "X-SOC-Token: $TOK" \
      -d "{\"action\":\"dismiss\",\"ip\":\"$ip\",\"incident_id\":\"$inc\"}" "$S/api/action" && n=$((n+1))
  done < <(curl -s -m 10 "$S/api/state" | python3 -c 'import json,sys
for p in json.load(sys.stdin).get("pending", []): print(p["incident_id"], p["suspect_ip"])' 2>/dev/null)
  ok "Dashboard: da bo qua $n yeu cau cho duyet"
else
  echo "  ! Khong ket noi duoc dashboard (lab-soc) - bo qua buoc nay"
fi

# 3. analyzer
printf 'MODE=%s\nRESPONSE=%s\n' "$MODE" "$RESP" | sudo tee /etc/default/lab-analyzer >/dev/null
sudo systemctl restart lab-analyzer
ok "Analyzer: che do $TXT (tri nho da xoa)"

# 4. API cua hang
sudo systemctl restart lab-shop-api
ok "Lab Shop: xoa khoa dang nhap, gio hang, phien dang nhap"

# 5. rule tu sinh
if [ $DROP_RULES -eq 1 ]; then
  ~/lab/rulegen-reset.sh >/dev/null 2>&1
  ok "Rule tu sinh: da thu hoi het, xoa phieu de xuat (--xoa-rule)"
else
  ok "Rule tu sinh: giu nguyen $(sudo /usr/local/sbin/lab-rule status | python3 -c "import json,sys; print(len(json.load(sys.stdin)['rules']))") rule (them --xoa-rule de thu hoi)"
fi

# 6. Ghi moc "dat lai" vao nhat ky quyet dinh: dashboard bo nhan rui ro cua MOI IP truoc moc nay,
#    monitor hien dong VAN HANH, va co dau vet kiem toan ai reset luc nao.
python3 -c 'import json,sys; from datetime import datetime,timezone
print(json.dumps({"at": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"), "incident_id": "", "ip": "*",
  "action": "reset_lab", "by": "nguoi van hanh (reset-lab.sh)", "result": "dua B ve trang thai sach, che do " + sys.argv[1], "ok": True}, ensure_ascii=False))' "$TXT" \
  | sudo -u labresp tee -a /var/lib/lab-analyzer/decisions.jsonl >/dev/null
ok "Dashboard: xoa nhan rui ro cu cua moi thiet bi"

sleep 2
sync
echo "== Kiem tra =="
st=$(systemctl is-active suricata nginx lab-analyzer lab-shop-api lab-honeypot lab-soc lab-rulegen lab-pcap-ring | sort -u | tr '\n' ' ')
[ "$st" = "active " ] && ok "8 dich vu dang chay" || echo "  ! Co dich vu khong chay: $(systemctl is-active suricata nginx lab-analyzer lab-shop-api lab-honeypot lab-soc lab-rulegen lab-pcap-ring | tr '\n' ' ')"
ok "Suricata: $(sudo suricatasc -c ruleset-stats 2>/dev/null | grep -o '"rules_loaded":[0-9]*' | cut -d: -f2) rule dang chay"
nb=$(~/lab/check-web.sh | grep -c ' OK$'); ok "Web + cong bay: $nb/24 muc OK"
echo "San sang cho kich ban moi. Neu A vua tan cong xong, nen doi them ~1 phut de Suricata reset bo dem nguong."
