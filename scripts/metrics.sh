#!/usr/bin/env bash
# Tinh chi so tu results.csv (do aggregate.sh tao). Chay duoc tren B hoac Git Bash.
# Dung: ./metrics.sh results.csv
F=${1:?Thieu results.csv}

echo "== Theo tung ca (so lan: TP/FP/FN/TN theo muc any | policy)"
awk -F, 'NR>1 && $4!="response" {
  k=$2" ["$4"]"; n[k]++; a[k,$15]++; p[k,$16]++ }
  END { for (k in n) printf "%-18s n=%d | any: TP=%d FP=%d FN=%d TN=%d | policy: TP=%d FP=%d FN=%d TN=%d\n",
        k, n[k], a[k,"TP"], a[k,"FP"], a[k,"FN"], a[k,"TN"], p[k,"TP"], p[k,"FP"], p[k,"FN"], p[k,"TN"] }' "$F" | sort

for lvl in any policy; do
  col=15; [ "$lvl" = policy ] && col=16
  awk -F, -v c=$col -v L=$lvl 'NR>1 { x[$c]++ }
    END {
      tp=x["TP"]+0; fp=x["FP"]+0; fn=x["FN"]+0; tn=x["TN"]+0
      printf "\n== Tong hop muc %s: TP=%d FP=%d FN=%d TN=%d\n", L, tp, fp, fn, tn
      if (tp+fn) printf "Recall    = %d/%d = %.3f\n", tp, tp+fn, tp/(tp+fn); else print "Recall    = khong xac dinh"
      if (fp+tn) printf "FPR       = %d/%d = %.3f\n", fp, fp+tn, fp/(fp+tn); else print "FPR       = khong xac dinh"
      if (tp+fp) { pr=tp/(tp+fp); printf "Precision = %d/%d = %.3f\n", tp, tp+fp, pr } else print "Precision = khong xac dinh"
      if (tp+fp && tp+fn && tp>0) { r=tp/(tp+fn); printf "F1        = %.3f\n", 2*pr*r/(pr+r) }
    }' "$F"
done
