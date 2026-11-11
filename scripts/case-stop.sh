#!/usr/bin/env bash
# Ket thuc mot ca thu tren may B: dung PCAP, cat phan log moi, tom tat alert.
# Dung: sudo ./case-stop.sh <RUN_ID>
set -euo pipefail
RUN_ID=${1:?Thieu RUN_ID}
BASE=${EVIDENCE_DIR:-/home/laamf-tung/lab/evidence}
DIR="$BASE/run-$RUN_ID"
EVE=/var/log/suricata/eve.json
ACC=/var/log/nginx/access.log

[ -e "$DIR/.running" ] || { echo "Ca $RUN_ID chua bat dau" >&2; exit 1; }

# Cho Suricata ghi het alert cua cac goi cuoi
sleep "${FLUSH_WAIT:-3}"

kill "$(cat "$DIR/.tcpdump.pid")" 2>/dev/null || true
sleep 1

tail -c +"$(( $(cat "$DIR/.eve_offset") + 1 ))" "$EVE" > "$DIR/eve.json"
tail -c +"$(( $(cat "$DIR/.acc_offset") + 1 ))" "$ACC" > "$DIR/access.log"

echo "ket_thuc: $(date --iso-8601=ns)" >> "$DIR/metadata.txt"

{
  echo "== Ca: $RUN_ID"
  grep -E '^(mo_ta|ky_vong):' "$DIR/metadata.txt"
  echo "== Alert theo SID (khong tinh SID 9xxxxxx)"
  jq -r 'select(.event_type=="alert" and .alert.signature_id < 9000000)
         | "\(.alert.signature_id) \(.src_ip)->\(.dest_ip) \(.alert.signature)"' "$DIR/eve.json" \
    | sort | uniq -c || true
  echo "== Thoi diem alert dau tien moi SID"
  jq -r 'select(.event_type=="alert" and .alert.signature_id < 9000000)
         | "\(.alert.signature_id) \(.timestamp)"' "$DIR/eve.json" | sort -k1,1 -u || true
  echo "== HTTP thay boi Suricata"
  jq -r 'select(.event_type=="http") | "\(.src_ip) \(.http.http_method // "-") \(.http.url // "-") -> \(.http.status // "-")"' \
    "$DIR/eve.json" | sort | uniq -c || true
  echo "== Nginx access log"
  awk '{print $1, $6, $7, $9}' "$DIR/access.log" | tr -d '"' | sort | uniq -c || true
  echo "== PCAP"
  echo "goi: $(tcpdump -nn -r "$DIR/traffic.pcap" 2>/dev/null | wc -l)"
  echo "SYN (khong ACK) tu nguon toi B: $(tcpdump -nn -r "$DIR/traffic.pcap" 'dst host 10.77.0.20 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null | wc -l)"
  echo "So cong dich khac nhau nhan SYN: $(tcpdump -nn -r "$DIR/traffic.pcap" 'dst host 10.77.0.20 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 2>/dev/null | awk '{print $5}' | awk -F. '{print $NF}' | tr -d ':' | sort -u | wc -l)"
  echo "RST/ACK tu B: $(tcpdump -nn -r "$DIR/traffic.pcap" 'src host 10.77.0.20 and tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)' 2>/dev/null | wc -l)"
} > "$DIR/summary.txt"

rm -f "$DIR/.running" "$DIR/.tcpdump.pid"
chown -R laamf-tung:laamf-tung "$DIR"
cat "$DIR/summary.txt"
