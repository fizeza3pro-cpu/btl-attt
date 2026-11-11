#!/usr/bin/env bash
# Theo doi do on dinh cua B (chay tren B): moi 30 s ghi tai CPU, RAM, lockup, so lan gnome-shell khoi dong,
# goi Suricata nhan/mat. Dung: sudo ./watch-stability.sh <so-phut> > log
MIN=${1:-10}
EVE=/var/log/suricata/eve.json
since=$(date '+%Y-%m-%d %H:%M:%S')
echo "thoi_gian load1 ram_used_MB gnome_cpu lockups gnome_starts kernel_packets kernel_drops"
for i in $(seq 1 $((MIN * 2))); do
  ld=$(cut -d' ' -f1 /proc/loadavg)
  ram=$(free -m | awk '/Mem:/{print $3}')
  gcpu=$(ps -C gnome-shell -o pcpu= | awk '{s+=$1} END{printf "%.1f", s+0}')
  lk=$(dmesg | grep -cE 'soft lockup|hung_task')
  gs=$(journalctl --since "$since" --no-pager -o cat 2>/dev/null | grep -c 'Started.*gnome-shell\|gnome-shell.*Starting\|GNOME Shell started')
  st=$(tail -n 400 "$EVE" | jq -R -r 'fromjson? | select(.event_type=="stats") | "\(.stats.capture.kernel_packets) \(.stats.capture.kernel_drops)"' | tail -1)
  echo "$(date +%T) $ld $ram $gcpu $lk $gs ${st:-? ?}"
  sleep 30
done
