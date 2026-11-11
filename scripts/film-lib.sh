# Thu vien quay video kich ban (source tu Git Bash tren may that).
# Quay bang tinh nang recording cua VirtualBox (dung man hinh may ao, 1920x1080), danh dau moc thoi gian.
VB="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
VA="kali-linux-2026.2-virtualbox-amd64"; VBM="unbutu"; VC="win10"
T=10.77.0.20
RAW=/d/BTL_ATTT/video/raw
MARKS=$RAW/marks.txt
SSH="ssh -o BatchMode=yes -o ConnectTimeout=10"

now()  { date +%s.%N; }
mark() { echo "$(now) $*" >> "$MARKS"; echo "[mark] $*"; }

# rec_start <vm> <ten>: bat dau quay, ghi moc
rec_start() {
  "$VB" controlvm "$1" recording filename "$(cygpath -w "$RAW/$2.webm")"
  "$VB" controlvm "$1" recording videores 1920 1080
  "$VB" controlvm "$1" recording videofps 30
  "$VB" controlvm "$1" recording videorate 8000
  "$VB" controlvm "$1" recording on >/dev/null 2>&1
  "$VB" controlvm "$1" recording start >/dev/null && mark "REC_START $2"
}
rec_stop() { "$VB" controlvm "$1" recording stop >/dev/null; mark "REC_STOP $2"; }

# A: go lenh vao terminal ke tan cong (FIFO), dua terminal len truoc
a_term() { $SSH labA 'export DISPLAY=:0; xdotool windowactivate $(xdotool search --onlyvisible --class qterminal | tail -1)'; }
atk()    { a_term; printf '%s\n' "$1" | $SSH labA 'cat > /tmp/demo-cmd'; }
# A: Firefox mo URL
ff_go()  { $SSH labA "export DISPLAY=:0; W=\$(xdotool search --onlyvisible --class firefox-esr | tail -1); xdotool windowactivate --sync \$W; xdotool key --clearmodifiers ctrl+l; sleep 0.4; xdotool type --delay 45 '$1'; sleep 0.3; xdotool key Return"; }
ff_key() { $SSH labA "export DISPLAY=:0; W=\$(xdotool search --onlyvisible --class firefox-esr | tail -1); xdotool windowactivate --sync \$W; xdotool key --clearmodifiers $1"; }
ff_type(){ $SSH labA "export DISPLAY=:0; xdotool type --delay 60 '$1'"; }
# B: chuyen giua man hinh giam sat va dashboard (alt+tab)
b_alttab() { "$VB" controlvm "$VBM" keyboardputscancode 38 0f 8f b8; }
# C: Edge mo URL
edge_go() { "$VB" controlvm "$VC" keyboardputscancode 1d 26 a6 9d; sleep 0.5; "$VB" controlvm "$VC" keyboardputstring "$1"; sleep 0.4; "$VB" controlvm "$VC" keyboardputscancode 1c 9c; }
shot()   { "$VB" controlvm "$1" screenshotpng "$(cygpath -w "$2")"; }
