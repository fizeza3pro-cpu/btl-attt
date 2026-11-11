#!/usr/bin/env bash
# Kiem tra phan hoi cua web lab (Lab Shop) theo tung duong dan.
# Dung: ./check-web.sh [base-url]   (mac dinh http://127.0.0.1)
BASE=${1:-http://127.0.0.1}
printf '%-22s %-6s %s\n' "PATH" "CODE" "KY_VONG"
while read -r path expect; do
  [ -z "$path" ] && continue
  code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE$path")
  mark=OK; [ "$code" = "$expect" ] || mark=SAI
  printf '%-22s %-6s %s %s\n' "$path" "$code" "$expect" "$mark"
done <<'EOF'
/ 200
/cart.html 200
/login.html 200
/shop.css 200
/shop.js 200
/about.html 200
/gallery.html 200
/robots.txt 200
/api/health 200
/api/products 200
/api/cart 200
/api/khong-co 404
/admin 403
/admin/ 403
/admin/users?id=1 403
/lab-admin 403
/lab-admin/ 403
/administrator 404
/lab-administrator 404
/403.html 404
/khong-ton-tai 404
EOF

# Cong bay cua honeypot phai DANG MO (neu mat, lop phat hien quet bang cong bay se tat am tham)
for p in 23 2222 3306; do
  if ss -ltn "( sport = :$p )" 2>/dev/null | grep -q "10.77.0.20:$p"; then st=MO; mark=OK; else st=DONG; mark=SAI; fi
  printf '%-22s %-6s %s %s\n' "cong-bay:$p" "$st" "MO" "$mark"
done
