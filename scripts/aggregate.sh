#!/usr/bin/env bash
# Tong hop ket qua cac ca thu (chay tren B, can jq). Xuat CSV ra stdout.
# Dung: ./aggregate.sh [thu-muc-evidence] > results.csv
#
# Nhan (label): lay tu dong "nhan:" trong metadata; neu thieu thi suy ra tu ma ca:
#   N*, CN*  -> normal ;  A*, E01, E02a/b/c/e -> attack ;  E02d -> edge ;  R* -> response
# Phat hien:
#   any    = co bat ky alert nao trong SID 1000001-1000099
#   policy = co tin hieu cung co/manh: 1000003, 1000005, 1000002 hoac 1000007
#            (1000001 don le chi "ghi nhan", khong tao incident)
BASE=${1:-/home/laamf-tung/lab/evidence}

echo "run_id,case,rep,label,sid1000001,sid1000002,sid1000003,sid1000007,syn_to_b,distinct_ports,rst_from_b,nginx_codes,detect_any,detect_policy,outcome_any,outcome_policy,sid1000005"
for d in "$BASE"/run-*; do
  [ -f "$d/eve.json" ] || continue
  id=${d##*/run-}; case_id=${id%-*}; rep=${id##*-}
  label=$(sed -n 's/^nhan: *//p' "$d/metadata.txt" | head -1)
  if [ -z "$label" ]; then
    case "$case_id" in
      N*|CN*) label=normal ;; E02d) label=edge ;; A*|E*) label=attack ;; R*) label=response ;; *) label=unknown ;;
    esac
  fi
  cnt() { jq -R -r --argjson s "$1" 'fromjson? | select(.event_type=="alert" and .alert.signature_id==$s) | 1' "$d/eve.json" | wc -l; }
  s1=$(cnt 1000001); s2=$(cnt 1000002); s3=$(cnt 1000003); s5=$(cnt 1000005); s7=$(cnt 1000007)
  syn=$(sed -n 's/^SYN (khong ACK) tu nguon toi B: //p' "$d/summary.txt")
  ports=$(sed -n 's/^So cong dich khac nhau nhan SYN: //p' "$d/summary.txt")
  rst=$(sed -n 's/^RST\/ACK tu B: //p' "$d/summary.txt")
  codes=$(awk '{print $9}' "$d/access.log" | sort | uniq -c | awk '{printf "%s%sx%s", (NR>1?" ":""), $2, $1}')
  any=0; [ $((s1+s2+s3+s5+s7)) -gt 0 ] && any=1
  pol=0; [ $((s2+s3+s5+s7)) -gt 0 ] && pol=1
  out() { # $1 = detected
    case "$label" in
      normal) [ "$1" = 1 ] && echo FP || echo TN ;;
      attack) [ "$1" = 1 ] && echo TP || echo FN ;;
      *) echo NA ;;
    esac; }
  echo "$id,$case_id,$rep,$label,$s1,$s2,$s3,$s7,${syn:-},${ports:-},${rst:-},\"$codes\",$any,$pol,$(out $any),$(out $pol),$s5"
done
