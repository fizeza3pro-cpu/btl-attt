#!/usr/bin/env bash
# Kich ban demo 3 may cho video (chay tu Git Bash tren may that).
#   RECORD=0 bash scripts/demo-3vm.sh   -> chay thu, khong quay
#   RECORD=1 bash scripts/demo-3vm.sh   -> quay toan man hinh ra video/public/demo-raw.mkv
# Moi thao tac la THAT: A (Kali) go lenh + Firefox, C (win10) Edge, B hien alert/quyet dinh cua analyzer.
set -u
T=10.77.0.20
VBM="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
FF=/c/Users/OS/AppData/Local/Microsoft/WinGet/Links/ffmpeg.exe
SSH="ssh -o BatchMode=yes -o ConnectTimeout=8"
RECORD=${RECORD:-0}
ROOT=/d/BTL_ATTT
MARKS=$ROOT/video/demo-marks.txt

# ---------------- cong cu ----------------
atk()      { printf '%s\n' "$1" | $SSH labA 'cat > /tmp/demo-cmd'; }                 # A go lenh trong terminal
ff_go()    { $SSH labA "export DISPLAY=:0; W=\$(xdotool search --onlyvisible --class firefox-esr | tail -1); xdotool windowactivate --sync \$W; xdotool key --clearmodifiers ctrl+l; sleep 0.4; xdotool type --delay 45 '$1'; sleep 0.3; xdotool key Return"; }
ff_reload(){ $SSH labA "export DISPLAY=:0; W=\$(xdotool search --onlyvisible --class firefox-esr | tail -1); xdotool windowactivate --sync \$W; xdotool key --clearmodifiers F5"; }
edge_go()  { "$VBM" controlvm win10 keyboardputscancode 1d 26 a6 9d; sleep 0.5; "$VBM" controlvm win10 keyboardputstring "$1"; sleep 0.4; "$VBM" controlvm win10 keyboardputscancode 1c 9c; }
blocked()  { $SSH labB "sudo nft list set inet lab_response blocked_l1 | grep -q 'elements = {'"; }
t0=0
mark()     { local now; now=$(date +%s.%N); echo "$(awk -v a="$now" -v b="$t0" 'BEGIN{printf "%.2f", a-b}') $1" | tee -a "$MARKS"; }

# ---------------- chuan bi ----------------
echo "[chuan bi] analyzer -> apply, mo lai man hinh giam sat B, nen den, sap xep cua so"
$SSH labB "echo MODE=apply | sudo tee /etc/default/lab-analyzer >/dev/null && sudo systemctl restart lab-analyzer"
powershell.exe -NoProfile -Command "Get-Process mintty -ErrorAction SilentlyContinue | Where-Object { \$_.MainWindowTitle -match 'BTLMON' } | Stop-Process -Force" 2>/dev/null
powershell.exe -NoProfile -WindowStyle Hidden -Command "Start-Process powershell -WindowStyle Hidden -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-File','D:\BTL_ATTT\scripts\backdrop.ps1'"
sleep 2
(/usr/bin/mintty.exe -o Font="Cascadia Mono" -o FontHeight=13 -o Scrollbar=none -o BackgroundColour=11,18,32 \
   -o ForegroundColour=230,237,247 -o CursorType=line -s 200,14 /usr/bin/ssh -t -o BatchMode=yes labB '~/lab/monitor.sh' &)
sleep 5
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ROOT/scripts/layout.ps1" -Top on
atk "__clear__"
ff_go "http://$T/"
edge_go "http://$T/"
sleep 4

# ---------------- quay ----------------
FPID=""
if [ "$RECORD" = "1" ]; then
  mkdir -p "$ROOT/video/public"
  "$FF" -hide_banner -loglevel error -y -f gdigrab -framerate 30 -draw_mouse 0 -i desktop \
    -c:v libx264 -preset veryfast -crf 18 -pix_fmt yuv420p "$ROOT/video/public/demo-raw.mkv" &
  FPID=$!
  sleep 1.5
fi
t0=$(date +%s.%N); : > "$MARKS"
mark start
sleep 3

mark c_shop                                   # C mua hang binh thuong
edge_go "http://$T/?them=1"; sleep 3.5
edge_go "http://$T/?them=3"; sleep 3.5
edge_go "http://$T/cart.html"; sleep 4

mark a_scan                                   # A quet cong
atk "nmap -sT -Pn -n --max-retries 0 --max-rate 20 -p 1-100 $T"
sleep 12
mark a_scan_done                              # B: 120 diem nhung KHONG chan
sleep 6

mark a_robots                                 # A do tim trang quan tri
atk "curl -s http://$T/robots.txt"
sleep 5
mark a_admin
ff_go "http://$T/admin"                       # Firefox vao bay -> 403
sleep 4
mark blocked                                  # B: CHAN A
sleep 5

mark verify                                   # A that bai, C van mua duoc
atk "curl -s --connect-timeout 3 -o /dev/null -w 'HTTP %{http_code}\n' http://$T/ || echo 'Ket noi that bai - A da bi chan'"
ff_reload
sleep 6
edge_go "http://$T/cart.html?dathang=1"
sleep 6

mark wait                                     # cho het han chan
while blocked; do sleep 3; done
mark expired
atk "curl -s -o /dev/null -w 'HTTP %{http_code}\n' http://$T/"
sleep 1
ff_go "http://$T/"
sleep 6
mark end

# ---------------- don dep ----------------
if [ -n "$FPID" ]; then kill -INT "$FPID" 2>/dev/null; sleep 2; kill "$FPID" 2>/dev/null; fi
$SSH labB "echo MODE=recommend | sudo tee /etc/default/lab-analyzer >/dev/null && sudo systemctl restart lab-analyzer"
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$ROOT/scripts/layout.ps1" -Top off >/dev/null
powershell.exe -NoProfile -Command "Get-CimInstance Win32_Process -Filter \"Name='powershell.exe'\" | Where-Object { \$_.CommandLine -match 'backdrop.ps1' } | ForEach-Object { Stop-Process -Id \$_.ProcessId -Force }" 2>/dev/null
echo "[xong] analyzer tra ve recommend; moc thoi gian: $MARKS"
