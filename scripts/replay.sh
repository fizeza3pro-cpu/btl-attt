#!/usr/bin/env bash
# Phat lai PCAP da ghi qua Suricata (che do offline) voi mot bo rule, dem alert theo SID.
# Chay tren B. Khong dung toi Suricata dang chay (tat unix socket, log ra thu muc rieng).
# Dung: sudo ./replay.sh <file-rule> <ten-lan-phat> [thu-muc-evidence]
#   vd: sudo ./replay.sh /etc/suricata/rules/local.rules baseline
# Ket qua: /home/laamf-tung/lab/replay/<ten>/<run_id>/eve.json va replay-<ten>.csv
set -uo pipefail
RULES=${1:?Thieu file rule}
NAME=${2:?Thieu ten lan phat}
BASE=${3:-/home/laamf-tung/lab/evidence}
OUT=/home/laamf-tung/lab/replay/$NAME
SIDS="1000001 1000002 1000003 1000005 1000007"
mkdir -p "$OUT"
cp "$RULES" "$OUT/rules-used.rules"

hdr="run_id"; for s in $SIDS; do hdr="$hdr,sid$s"; done
echo "$hdr" > "$OUT/../replay-$NAME.csv"

for d in "$BASE"/run-*; do
  [ -f "$d/traffic.pcap" ] || continue
  id=${d##*/run-}
  o="$OUT/$id"; mkdir -p "$o"
  # -k none: khong kiem checksum (goi di tu B co the mang checksum chua tinh do offload TX)
  # --runmode single: BAT BUOC. Che do nhieu luong (autofp) lam lech cua so threshold khi doc PCAP
  #   (da kiem chung: cung mot PCAP cho ket qua khac nhau giua cac lan chay).
  suricata -c /etc/suricata/suricata.yaml -S "$RULES" -r "$d/traffic.pcap" -k none -l "$o" \
    --runmode single --set unix-command.enabled=no >"$o/suricata-stdout.log" 2>&1
  line="$id"
  for s in $SIDS; do
    n=$(jq -R -r --argjson s "$s" 'fromjson? | select(.event_type=="alert" and .alert.signature_id==$s) | 1' "$o/eve.json" 2>/dev/null | wc -l)
    line="$line,$n"
  done
  echo "$line" >> "$OUT/../replay-$NAME.csv"
done
chown -R laamf-tung:laamf-tung "$OUT" "$OUT/../replay-$NAME.csv"
echo "Xong: $OUT/../replay-$NAME.csv ($(($(wc -l < "$OUT/../replay-$NAME.csv")-1)) lan chay)"
