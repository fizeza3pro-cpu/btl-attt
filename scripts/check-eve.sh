#!/usr/bin/env bash
# Tom tat nhanh EVE JSON cua Suricata tren may B.
# Dung: sudo ./check-eve.sh [tu-thoi-diem]   vd: sudo ./check-eve.sh 2026-11-08T16:31
set -u
EVE=${EVE:-/var/log/suricata/eve.json}
SINCE=${1:-0000}

echo "== File: $EVE"
ls -la "$EVE"

echo "== So su kien theo loai (tu $SINCE)"
jq -r --arg s "$SINCE" 'select(.timestamp >= $s) | .event_type' "$EVE" | sort | uniq -c

echo "== Cap IP trong mang lab (tu $SINCE)"
jq -r --arg s "$SINCE" 'select(.timestamp >= $s and .src_ip != null)
  | "\(.src_ip) -> \(.dest_ip):\(.dest_port // "-") \(.proto) \(.app_proto // "")"' "$EVE" \
  | sort | uniq -c | sort -rn | head -15

echo "== Alert (tu $SINCE)"
jq -c --arg s "$SINCE" 'select(.timestamp >= $s and .event_type == "alert")
  | {ts: .timestamp, src: .src_ip, dst: .dest_ip, sid: .alert.signature_id, msg: .alert.signature}' "$EVE" | tail -10

echo "== Thong ke bat goi moi nhat"
jq -c 'select(.event_type == "stats")
  | {ts: .timestamp, kernel_packets: .stats.capture.kernel_packets, kernel_drops: .stats.capture.kernel_drops,
     decoder_pkts: .stats.decoder.pkts, invalid: .stats.decoder.invalid}' "$EVE" | tail -1
