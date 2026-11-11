#!/usr/bin/env bash
# Terminal "ke tan cong" tren Kali cho video demo.
# Nhan lenh tu FIFO /tmp/demo-cmd (do kich ban dieu khien gui qua SSH), go tung ky tu cho tu nhien roi CHAY THAT.
FIFO=/tmp/demo-cmd
rm -f "$FIFO"; mkfifo "$FIFO"
prompt() { printf '\e[1;34m┌──(\e[1;31mkali㉿kali\e[1;34m)-[\e[0;1m~\e[1;34m]\n└─\e[1;31m$\e[0m '; }
clear
printf '\e[1;31m[A] Kali 10.77.0.10\e[0m — kẻ tấn công\n\n'
prompt
while :; do
  if IFS= read -r line < "$FIFO"; then
    [ "$line" = "__clear__" ] && { clear; printf '\e[1;31m[ A — Kali 10.77.0.10 ]\e[0m\n\n'; prompt; continue; }
    for ((i = 0; i < ${#line}; i++)); do printf '%s' "${line:i:1}"; sleep 0.035; done
    sleep 0.3; echo
    bash -c "$line"
    echo
    prompt
  fi
done
