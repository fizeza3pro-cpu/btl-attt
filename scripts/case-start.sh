#!/usr/bin/env bash
# Bat dau mot ca thu tren may B: ghi moc log va bat PCAP.
# Dung: sudo ./case-start.sh <RUN_ID> "<mo ta / lenh mo phong>" "<ky vong>"
set -euo pipefail
RUN_ID=${1:?Thieu RUN_ID, vd A01-01}
DESC=${2:-}
EXPECT=${3:-}
LABEL=${4:-}      # normal | attack | edge  (chot TRUOC khi chay)
BASE=${EVIDENCE_DIR:-/home/laamf-tung/lab/evidence}
DIR="$BASE/run-$RUN_ID"
EVE=/var/log/suricata/eve.json
ACC=/var/log/nginx/access.log
IFACE=enp0s8

if [ -e "$DIR/.running" ]; then echo "Ca $RUN_ID dang chay" >&2; exit 1; fi
mkdir -p "$DIR"

stat -c %s "$EVE" > "$DIR/.eve_offset"
stat -c %s "$ACC" > "$DIR/.acc_offset"

{
  echo "run_id: $RUN_ID"
  echo "mo_ta: $DESC"
  echo "ky_vong: $EXPECT"
  echo "nhan: $LABEL"
  echo "bat_dau: $(date --iso-8601=ns)"
  echo "may: $(hostname)"
  echo "suricata: $(suricata -V 2>/dev/null)"
  echo "rules_sha256: $(sha256sum /etc/suricata/rules/local.rules | cut -d' ' -f1)"
  echo "suricata_yaml_sha256: $(sha256sum /etc/suricata/suricata.yaml | cut -d' ' -f1)"
  echo "nft_lab_response: $(nft list table inet lab_response >/dev/null 2>&1 && echo co || echo khong)"
} > "$DIR/metadata.txt"

# Bat ca IPv6 (truoc day chi IPv4 -> khong thay duoc kich ban lach qua IPv6)
nohup tcpdump -i "$IFACE" -nn -s 0 -U -w "$DIR/traffic.pcap" 'host 10.77.0.20 or (ip6 and not icmp6)' \
  > "$DIR/.tcpdump.log" 2>&1 &
echo $! > "$DIR/.tcpdump.pid"
touch "$DIR/.running"
sleep 1
echo "START $RUN_ID -> $DIR (tcpdump pid $(cat "$DIR/.tcpdump.pid"))"
