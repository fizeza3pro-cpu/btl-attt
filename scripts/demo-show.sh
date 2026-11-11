#!/usr/bin/env bash
# Tro giup hien thi cho demo (chay tren B). Doc du lieu that, in gon de quay video.
#   demo-show.sh offset              -> in kich thuoc hien tai cua eve.json (moc bat dau)
#   demo-show.sh alerts <offset>     -> alert moi tu moc
#   demo-show.sh inc <so-dong-cu>    -> incident moi cua analyzer
#   demo-show.sh inc-count           -> so dong incident hien tai
#   demo-show.sh fw                  -> trang thai bang chan + counter
EVE=/var/log/suricata/eve.json
INC=/var/lib/lab-analyzer/incidents.jsonl
case "${1:-}" in
  offset) stat -c %s "$EVE" ;;
  alerts)
    tail -c +$(( ${2:-0} + 1 )) "$EVE" | jq -R -r 'fromjson? | select(.event_type=="alert" and .alert.signature_id < 9000000)
      | "  \(.timestamp[11:23])  SID \(.alert.signature_id)  \(.src_ip) -> \(.dest_ip)  \(.alert.signature)"' ;;
  inc-count) sudo cat "$INC" 2>/dev/null | wc -l ;;
  inc)
    sudo tail -n +$(( ${2:-0} + 1 )) "$INC" 2>/dev/null | jq -r '
      "  score=\(.score)  tin_hieu_that=\(.has_unspoofable_signal)  SIDs=\([.signals[].sid] | map(tostring) | join(","))\n    -> \(.decision)  (tre \(.event_age_s) s)"
      + (if .action then "\n    -> lab-block: " + .action.result.msg else "" end)' ;;
  fw)
    sudo /usr/local/sbin/lab-block status | jq -r '"  nftables blocked_l1: \(.blocked_l1)   | goi bi drop: \(.drop_packets)"' ;;
  *) echo "usage" >&2; exit 2 ;;
esac
