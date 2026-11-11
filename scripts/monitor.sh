#!/usr/bin/env bash
# Man hinh giam sat cua B - ban DE DOC (tieng Viet, giai thich tung su kien).
#   ~/lab/monitor.sh            WEB, CANH BAO, HONEYPOT, DANG NHAP, PHAN TICH, TUONG LUA, VAN HANH, RULE MOI
#   ~/lab/monitor.sh --tat-ca   hien ca file tinh (.css, .js, anh)
#   ~/lab/monitor.sh --health   hien ca /api/health (trang web goi 3 giay/lan)
# Ctrl+C de thoat. Ma nguon: /usr/local/lib/lab/lab-monitor.py
printf '\e]0;BTLMON\a'
sudo -n /usr/local/sbin/lab-block status >/dev/null 2>&1 || sudo true || exit 1
clear
exec python3 /usr/local/lib/lab/lab-monitor.py "$@"
