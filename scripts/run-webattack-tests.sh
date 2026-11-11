#!/usr/bin/env bash
# Kiem thu tan cong ung dung web (W10-W14) va dang nhap hop le (N10). Chay tu may that (Git Bash).
# Dung: bash scripts/run-webattack-tests.sh [hau-to]
set -uo pipefail
SUFFIX=${1:-01}; GAP=${GAP:-8}
T=10.77.0.20
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"

run_case() {   # id label host desc expect action
  local id="$1-$SUFFIX" label="$2" host="$3" desc="$4" expect="$5" action="$6"
  echo; echo "######## $id [$label] $desc"
  $SSH labB "sudo ~/lab/case-start.sh '$id' '$desc' '$expect' '$label'" >/dev/null
  local a0; a0=$($SSH labB "sudo cat /var/log/lab-shop/auth.jsonl 2>/dev/null | wc -l")
  $SSH "$host" "$action" 2>&1 | tail -n 3 | sed 's/^/  [may] /'
  $SSH labB "sudo ~/lab/case-stop.sh '$id'" | sed -n '/Alert theo SID/,/Thoi diem/p' | grep -vE 'Alert theo|Thoi diem' | sed 's/^/  [alert]/'
  $SSH labB "sudo tail -n +$((a0 + 1)) /var/log/lab-shop/auth.jsonl 2>/dev/null | jq -r .kind | sort | uniq -c | sed 's/^/  [auth] /'"
  sleep "$GAP"
}

LOGIN="curl -s -o /dev/null -w '%{http_code} ' -H 'Content-Type: application/json'"

run_case N10 normal labC "C dang nhap dung tai khoan thu nghiem" "200; khong alert; auth login_ok" \
  "curl.exe -s -o NUL -w '%{http_code}' -H 'Content-Type: application/json' --data-binary '@C:\\Users\\vboxuser\\lab\\login-ok.json' http://$T/api/login"

run_case W10 attack labA "A do mat khau: 7 lan sai lien tiep" "401 x5 roi 429 (khoa IP); SID 1000017; auth login_fail/login_locked" \
  "for p in 123456 password qwerty admin123 letmein abc123 iloveyou; do $LOGIN -d \"{\\\"email\\\":\\\"khach@labshop.vn\\\",\\\"password\\\":\\\"\$p\\\"}\" http://$T/api/login; done; echo"

run_case W11 attack labA "A thu SQL injection o URL va noi dung dang nhap" "SID 1000013 + 1000015; API tu choi" \
  "curl -s -o /dev/null -w '%{http_code} ' 'http://$T/api/products?q=1%20UNION%20SELECT%20email,password%20FROM%20users'; $LOGIN -d \"{\\\"email\\\":\\\"a@b.c\\\",\\\"password\\\":\\\"' OR '1'='1\\\"}\" http://$T/api/login; echo"

run_case W12 attack labA "A thu XSS o URL" "SID 1000014" \
  "curl -s -o /dev/null -w '%{http_code}\n' 'http://$T/?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E'"

run_case W13 attack labA "A thu path traversal" "SID 1000006 (+1000008)" \
  "curl -s --path-as-is -o /dev/null -w '%{http_code} ' 'http://$T/../../etc/passwd'; curl -s --path-as-is -o /dev/null -w '%{http_code}\n' 'http://$T/%2e%2e/%2e%2e/etc/passwd'"

run_case W14 attack labA "A gui 15 request dang nhap thật nhanh (vuot gioi han toc do)" "Mot phan bi Nginx tra 429 (rate limit)" \
  "for i in \$(seq 15); do $LOGIN -d '{\"email\":\"x@y.z\",\"password\":\"x\"}' http://$T/api/login; done; echo"

echo; echo "XONG. Bang chung: ~/lab/evidence/run-{N10,W10..W14}-$SUFFIX"
