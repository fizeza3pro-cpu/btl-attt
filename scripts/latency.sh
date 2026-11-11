#!/usr/bin/env bash
# Tinh do tre phat hien cho mot ca thu tu PCAP + EVE (chay tren B).
# - SID 1000001: tu goi SYN thu 10 (du nguong count 10) toi alert
# - SID 1000003: tu RST/ACK thu 10 tu B toi alert
# - SID 1000002: tu goi HTTP request chua /lab-admin toi alert
# Dung: ./latency.sh <thu-muc-run>
D=${1:?Thieu thu muc run}
P="$D/traffic.pcap"; E="$D/eve.json"

alert_ts() { jq -r --argjson s "$1" 'select(.event_type=="alert" and .alert.signature_id==$s) | .timestamp' "$E" | head -1; }
to_epoch() { [ -n "$1" ] && date -d "$1" +%s.%N; }
nth_pkt() { tcpdump -tt -nn -r "$P" "$1" 2>/dev/null | sed -n "${2}p" | awk '{print $1}'; }
diff_ms() { awk -v a="$1" -v b="$2" 'BEGIN{printf "%.1f", (b-a)*1000}'; }

echo "== $(basename "$D")"
first=$(tcpdump -tt -nn -r "$P" 2>/dev/null | head -1 | awk '{print $1}')

a=$(alert_ts 1000001)
if [ -n "$a" ]; then
  p=$(nth_pkt 'dst host 10.77.0.20 and tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn' 10)
  echo "SID 1000001: SYN thu 10 -> alert = $(diff_ms "$p" "$(to_epoch "$a")") ms; tu goi dau tien = $(diff_ms "$first" "$(to_epoch "$a")") ms"
fi
a=$(alert_ts 1000003)
if [ -n "$a" ]; then
  p=$(nth_pkt 'src host 10.77.0.20 and tcp[tcpflags] & (tcp-rst|tcp-ack) == (tcp-rst|tcp-ack)' 10)
  echo "SID 1000003: RST/ACK thu 10 -> alert = $(diff_ms "$p" "$(to_epoch "$a")") ms"
fi
a=$(alert_ts 1000002)
if [ -n "$a" ]; then
  p=$(tcpdump -tt -nn -A -r "$P" 'dst host 10.77.0.20 and tcp dst port 80' 2>/dev/null | grep -B20 'GET /lab-admin' | grep -E '^[0-9]+\.[0-9]+ ' | tail -1 | awk '{print $1}')
  echo "SID 1000002: HTTP request -> alert = $(diff_ms "$p" "$(to_epoch "$a")") ms"
fi
