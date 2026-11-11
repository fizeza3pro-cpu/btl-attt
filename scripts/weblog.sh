#!/usr/bin/env bash
# Xem request toi Lab Shop theo thoi gian thuc (giong log cua dev server). Chay tren B.
#   ~/lab/weblog.sh          -> moi request (ca /api/health)
#   ~/lab/weblog.sh api      -> chi request API
#   ~/lab/weblog.sh api-log  -> log rieng cua backend API (journald)
case "${1:-}" in
  api-log) exec sudo journalctl -u lab-shop-api -f -o short-iso ;;
esac
FILTER=${1:-}
G=$'\e[32m'; Y=$'\e[33m'; RD=$'\e[1;31m'; D=$'\e[2m'; R=$'\e[0m'
echo "Thoi gian  May goi        Method Duong dan                                Ma   Byte   User-Agent"
sudo tail -n 15 -F /var/log/nginx/access.log | awk -v f="$FILTER" -v g="$G" -v y="$Y" -v rd="$RD" -v d="$D" -v r="$R" -F'"' '
  { split($1, a, " "); ip=a[1]; t=substr(a[4],14,8)
    split($2, q, " "); m=q[1]; u=q[2]
    split($3, s, " "); c=s[1]; b=s[2]; ua=$6
    if (f=="api" && u !~ /^\/api\//) next
    col = (c ~ /^[23]/) ? g : (c=="403" ? rd : y)
    printf "%s  %-13s  %-6s %-40s %s%s%s  %-6s %s%s%s\n", t, ip, m, substr(u,1,40), col, c, r, b, d, substr(ua,1,40), r; fflush() }'
