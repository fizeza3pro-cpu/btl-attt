#!/usr/bin/env bash
# Kiem thu lo hong lach chan qua IPv6 (X02). Chay tu may that (Git Bash).
#   bash scripts/run-ipv6-test.sh before <hau-to>   -> chua va: ky vong A lach duoc qua IPv6
#   bash scripts/run-ipv6-test.sh after  <hau-to>   -> da va:  ky vong A bi chan ca IPv4 lan IPv6
set -uo pipefail
PHASE=${1:?before|after}; SUFFIX=${2:-01}
ID="X02-$PHASE-$SUFFIX"
B4=10.77.0.20
B6='fe80::255:32a1:aece:77f2'
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
a4() { $SSH labA "curl -s -o /dev/null --connect-timeout 3 --max-time 4 -w '%{http_code}' http://$B4/" 2>/dev/null; }
a6() { $SSH labA "curl -g -s -o /dev/null --connect-timeout 3 --max-time 4 -w '%{http_code}' 'http://[$B6%eth0]/'" 2>/dev/null; }

$SSH labB "sudo ~/lab/case-start.sh '$ID' 'Lach chan qua IPv6 ($PHASE): A bi chan IPv4, thu vao web qua IPv6 link-local' 'before: IPv6 lot qua; after: IPv6 bi chan' attack" >/dev/null
echo "Truoc khi chan:  A->IPv4 $(a4)   A->IPv6 $(a6)"
$SSH labB "sudo /usr/local/sbin/lab-block add l1 10.77.0.10" >/dev/null
sleep 1
r4=$(a4); r6=$(a6)
echo "KHI A BI CHAN:   A->IPv4 ${r4:-000}   A->IPv6 ${r6:-000}"
$SSH labB "sudo /usr/local/sbin/lab-block del l1 10.77.0.10" >/dev/null
echo "Nginx ghi nhan request IPv6 trong ca nay:"
$SSH labB "sudo FLUSH_WAIT=2 ~/lab/case-stop.sh '$ID' >/dev/null; awk '\$1 ~ /:/' ~/lab/evidence/run-$ID/access.log | sed 's/^/  /'"
$SSH labB "echo \"  counter rule IPv6: \$(sudo nft list chain inet lab_response input | grep -o 'lab-ipv6-policy' >/dev/null && sudo nft list chain inet lab_response input | grep 'lab-ipv6-policy' | grep -o 'packets [0-9]*' || echo 'chua co rule IPv6')\""
if [ "${r6:-000}" = "200" ]; then echo "KET LUAN: A LACH DUOC qua IPv6 (lo hong)"; else echo "KET LUAN: IPv6 bi chan"; fi
