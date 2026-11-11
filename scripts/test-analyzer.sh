#!/usr/bin/env bash
# Kiem thu offline cho analyzer.py (chay tren B). Moi ca: dua EVE vao, so quyet dinh cao nhat voi ky vong.
# Dung: ./test-analyzer.sh
set -u
AN=${AN:-/usr/local/lib/lab/analyzer.py}   # ban DANG CHAY that (truoc day tro nham ban sao cu trong ~/lab)
EV=$HOME/lab/evidence
RP=$HOME/lab/replay/v3-slowscan
T=$(mktemp -d)
pass=0; fail=0

check() {  # ten file-eve ky-vong [tham-so-them...]
  local name="$1" eve="$2" expect="$3" got; shift 3
  got=$(python3 "$AN" --eve "$eve" --offline "$@" 2>/dev/null | python3 -c '
import sys, json
rank = {"incident_medium":1,"incident_high_spoof_suspect":2,"incident_high_protected":2,
        "recommend_only_out_of_scope":2,"recommend_block_l1":3,"block_l1":3,"already_blocked":3,
        "recommend_deceive":3,"deceive":3,"attacker_engaged":4}
best = "log"
for l in sys.stdin:
    d = json.loads(l)["decision"]
    if rank.get(d,0) >= rank.get(best,0): best = d
print(best)')
  if [ "$got" = "$expect" ]; then pass=$((pass+1)); r=PASS; else fail=$((fail+1)); r=FAIL; fi
  printf '%-4s %-34s ky_vong=%-28s thuc_te=%s\n' "$r" "$name" "$expect" "$got"
}

# Sinh EVE gia lap: gen <file> "<sid>:<src>:<dst>[:url]" ...
gen() {
  local f="$1"; shift
  python3 - "$f" "$@" <<'PY'
import sys, json
from datetime import datetime, timezone, timedelta
f = sys.argv[1]; t0 = datetime(2026, 11, 8, 23, 0, 0, tzinfo=timezone(timedelta(hours=7)))
with open(f, "w") as out:
    for i, spec in enumerate(sys.argv[2:]):
        if spec == "BADJSON":
            out.write('{"timestamp": "2026-11-08T23:00:0\n'); continue
        p = spec.split("|"); sid, src, dst = int(p[0]), p[1], p[2]
        ev = {"timestamp": (t0 + timedelta(seconds=5*i)).strftime("%Y-%m-%dT%H:%M:%S.%f%z"),
              "event_type": "alert", "src_ip": src, "dest_ip": dst,
              "alert": {"signature_id": sid, "signature": f"synthetic {sid}"}}
        if len(p) > 3: ev["http"] = {"url": p[3]}
        out.write(json.dumps(ev) + "\n")
PY
}

echo "== EVE that tu cac ca da chay (rule v2 live) =="
check "N03-01 web nhe"            "$EV/run-N03-01/eve.json" log
check "N04-01 web don dap"        "$EV/run-N04-01/eve.json" log
check "CN06-01 C 32 ket noi"      "$EV/run-CN06-01/eve.json" log
check "A01-01 quet cong (20+50)"  "$EV/run-A01-01/eve.json" incident_medium
check "A02-01 vao bay"            "$EV/run-A02-01/eve.json" incident_medium
check "A03-01 quet + bay"         "$EV/run-A03-01/eve.json" recommend_block_l1
echo "== EVE phat lai voi rule v3 =="
check "E01-01 quet cham (v3)"     "$RP/E01-01/eve.json" incident_medium
check "A03-02 quet + bay (v3)"    "$RP/A03-02/eve.json" recommend_block_l1

echo "== EVE gia lap: tinh huong kho dung trong lab =="
B=10.77.0.20; A=10.77.0.10; C=10.77.0.30; X=10.77.0.40
gen "$T/spoofC.json" "1000001|$C|$B" "1000003|$B|$C" "1000005|$B|$C" "1000001|$C|$B"
check "Gia mao C: 120 diem, toan gia mao duoc" "$T/spoofC.json" incident_high_spoof_suspect
gen "$T/spoofC2.json" "1000001|$C|$B" "1000003|$B|$C" "1000005|$B|$C" "1000003|$B|$C" "1000005|$B|$C"
check "Gia mao C (lap lai, khong cong don)" "$T/spoofC2.json" incident_high_spoof_suspect
gen "$T/spoofA.json" "1000001|$A|$B" "1000003|$B|$A" "1000005|$B|$A"
check "A: 120 diem nhung khong tin hieu that" "$T/spoofA.json" incident_high_spoof_suspect
gen "$T/weak.json" "1000001|$A|$B" "1000001|$A|$B" "1000001|$A|$B"
check "Chi tin hieu yeu lap lai" "$T/weak.json" log
gen "$T/protC.json" "1000001|$C|$B" "1000003|$B|$C" "1000002|$C|$B|/lab-admin"
check "C that su vao bay (C KHONG con dac cach)" "$T/protC.json" recommend_block_l1
gen "$T/outX.json" "1000001|$X|$B" "1000003|$B|$X" "1000002|$X|$B|/lab-admin"
check "Nguon la 10.77.0.40" "$T/outX.json" recommend_only_out_of_scope
gen "$T/ext.json" "1000002|8.8.8.8|$B|/lab-admin" "1000001|8.8.8.8|$B" "1000003|$B|8.8.8.8"
check "IP ngoai mang lab" "$T/ext.json" log
gen "$T/crit.json" "1000002|$A|$B|/lab-admin" "1000007|$B|$A"
check "Bay tra ma khac 403 (nghiem trong)" "$T/crit.json" recommend_block_l1
gen "$T/inj.json" "1000002|$A|$B|/lab-admin\$(id)\u0007\u001b[31m" BADJSON "1000001|$A|$B"
check "Du lieu doc hai + JSON hong" "$T/inj.json" incident_medium
if python3 "$AN" --eve "$T/inj.json" --offline 2>/dev/null | grep -qP '[\x00-\x08\x0b-\x1f]'; then
  echo "FAIL ky tu dieu khien lot ra output"; fail=$((fail+1)); else echo "PASS khong co ky tu dieu khien trong output"; pass=$((pass+1)); fi

echo "== v2: nhieu nguon, danh lua, ATT&CK (dry-run: executor GIA) =="
# Sinh su kien honeypot / auth: genx <file> "<kind>|<src>|<giay-tu-moc>" ...
genx() {
  local f="$1"; shift
  python3 - "$f" "$@" <<'PY'
import sys, json
from datetime import datetime, timezone, timedelta
f = sys.argv[1]; t0 = datetime(2026, 11, 8, 23, 0, 0, tzinfo=timezone(timedelta(hours=7)))
with open(f, "w") as out:
    for spec in sys.argv[2:]:
        kind, src, sec = spec.split("|")
        out.write(json.dumps({"ts": (t0 + timedelta(seconds=float(sec))).isoformat(timespec="milliseconds"),
                              "src_ip": src, "kind": kind, "email": "khach@labshop.vn"}) + "\n")
PY
}
EMPTY="$T/empty.json"; : > "$EMPTY"
DR="--dry-run-apply --response deceive"

genx "$T/hp1.jsonl" "honeytoken_file|$A|1"
check "Honeytoken file (truc tiep) -> danh lua" "$EMPTY" deceive --honeypot "$T/hp1.jsonl" $DR

gen "$T/scan.json" "1000001|$A|$B" "1000003|$B|$A" "1000005|$B|$A"
genx "$T/hp2.jsonl" "honeyport_connect|$A|16"
check "Quet + cham cong bay 3306 -> danh lua" "$T/scan.json" deceive --honeypot "$T/hp2.jsonl" $DR
check "Quet + cong bay, khong dry-run -> chi de xuat" "$T/scan.json" recommend_deceive --honeypot "$T/hp2.jsonl" --response deceive

genx "$T/hp3.jsonl" "honeytoken_file|$A|1" "honeypot_admin_login|$A|30" "honeytoken_creds|$A|40"
check "Bi danh lua roi van can cau -> cho nguoi duyet" "$EMPTY" attacker_engaged --honeypot "$T/hp3.jsonl" $DR

genx "$T/auth1.jsonl" "login_fail|$A|1" "login_fail|$A|2" "login_fail|$A|3" "login_fail|$A|4" "login_fail|$A|5"
check "5 lan dang nhap sai (log ung dung)" "$EMPTY" incident_medium --auth "$T/auth1.jsonl" $DR
genx "$T/auth2.jsonl" "login_fail|$A|1" "login_fail|$A|2" "login_fail|$A|3" "login_fail|$A|4" "login_fail|$A|5" "login_locked|$A|6"
check "Do mat khau den muc bi khoa -> danh lua" "$EMPTY" deceive --auth "$T/auth2.jsonl" $DR
genx "$T/auth3.jsonl" "login_fail|$A|1" "login_fail|$A|50" "login_fail|$A|100" "login_fail|$A|150" "login_fail|$A|200"
check "5 lan sai rai rac (> 120 s) -> chi ghi nhan" "$EMPTY" log --auth "$T/auth3.jsonl" $DR

gen "$T/sqli.json" "1000013|$A|$B" "1000015|$A|$B"
check "SQLi URL + body (100 diem, tin hieu that)" "$T/sqli.json" deceive $DR
check "SQLi, response=block (mac dinh) -> de xuat chan" "$T/sqli.json" recommend_block_l1

genx "$T/hpC.jsonl" "honeytoken_creds|$C|1"
check "C dung honeytoken (C KHONG con dac cach)" "$EMPTY" deceive --honeypot "$T/hpC.jsonl" $DR

# 1000007 (moi tra khac 403) phai bi bo qua khi A dang bi danh lua (honeypot co chu dich tra 200)
genx "$T/hp4.jsonl" "honeytoken_file|$A|1"
gen "$T/crit2.json" "1000001|$A|$B" "1000001|$A|$B" "1000001|$A|$B" "1000001|$A|$B" "1000007|$B|$A"
n=$(python3 "$AN" --eve "$T/crit2.json" --honeypot "$T/hp4.jsonl" --offline $DR 2>/dev/null | grep -c '"sid": 1000007')
if [ "$n" = "0" ]; then echo "PASS 1000007 bi bo qua khi dang danh lua"; pass=$((pass+1)); else echo "FAIL 1000007 van duoc tinh khi dang danh lua"; fail=$((fail+1)); fi

att=$(python3 "$AN" --eve "$EMPTY" --honeypot "$T/hp3.jsonl" --offline $DR 2>/dev/null | tail -1 | python3 -c 'import sys,json; print(",".join(sorted(a["id"] for a in json.loads(sys.stdin.read())["attack"])))')
if [ "$att" = "T1078,T1110.001" ]; then echo "PASS ATT&CK cua giai doan can cau: $att"; pass=$((pass+1)); else echo "FAIL ATT&CK: '$att'"; fail=$((fail+1)); fi
ne=$(python3 "$AN" --eve "$EMPTY" --honeypot "$T/hp3.jsonl" --offline $DR 2>/dev/null | grep -c '"attacker_engaged"')
if [ "$ne" = "2" ]; then echo "PASS moi loai hanh vi can cau moi deu thanh incident (2)"; pass=$((pass+1)); else echo "FAIL so incident can cau = $ne (ky vong 2)"; fail=$((fail+1)); fi

echo "== Rule TU SINH (lab-rulegen, SID 5000000-5999999) =="
gen "$T/auto1.json" "5000000|$A|$B"
check "1 rule tu sinh (50 diem)" "$T/auto1.json" incident_medium
gen "$T/auto2.json" "5000000|$A|$B" "5000001|$A|$B"
check "2 rule tu sinh (100 diem, tin hieu that)" "$T/auto2.json" deceive $DR
gen "$T/autoC.json" "5000000|$C|$B" "5000001|$C|$B"
check "C khop rule tu sinh (C KHONG con dac cach)" "$T/autoC.json" deceive $DR
gen "$T/auto3.json" "5000002|$A|$B" "5500000|$A|$B"
att=$(python3 "$AN" --eve "$T/auto3.json" --offline 2>/dev/null | tail -1 | python3 -c 'import sys,json; print(",".join(sorted(a["id"] for a in json.loads(sys.stdin.read())["attack"])))')
if [ "$att" = "T1595.002,T1595.003" ]; then echo "PASS ATT&CK rule tu sinh: $att"; pass=$((pass+1)); else echo "FAIL ATT&CK rule tu sinh: '$att'"; fail=$((fail+1)); fi

echo "== Dot tan cong MOI sau khi im lang > 120 s phai duoc bao lai =="
genx "$T/hp2dot.jsonl" "honeytoken_file|$A|1" "honeytoken_file|$A|300"
n=$(python3 "$AN" --eve "$EMPTY" --honeypot "$T/hp2dot.jsonl" --offline --response deceive 2>/dev/null | grep -c '"recommend_deceive"')
if [ "$n" = "2" ]; then echo "PASS 2 dot tan cong cach nhau 5 phut -> 2 su co"; pass=$((pass+1)); else echo "FAIL 2 dot tan cong -> $n su co (ky vong 2)"; fail=$((fail+1)); fi

echo "== Che do offline khong bao gio goi executor =="
before=$(sudo -n /usr/local/sbin/lab-block status)
python3 "$AN" --eve "$EV/run-A03-01/eve.json" --offline --mode apply >/dev/null 2>&1
after=$(sudo -n /usr/local/sbin/lab-block status)
if [ "$before" = "$after" ] && echo "$after" | grep -q '"blocked_l1":"","blocked_l2":"","deceive":""'; then
  echo "PASS --offline --mode apply: firewall khong doi"; pass=$((pass+1))
else echo "FAIL firewall bi thay doi: $after"; fail=$((fail+1)); fi

rm -rf "$T"
echo "== Tong: PASS=$pass FAIL=$fail =="
[ $fail -eq 0 ]
