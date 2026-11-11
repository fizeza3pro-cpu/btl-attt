#!/usr/bin/env bash
# Quay cua so demo bang ffmpeg (gdigrab theo tieu de cua so). Chay tu Git Bash tren may that.
# Ket qua: video/public/demo-raw.mkv, video/demo-marks.txt, video/demo-rec-start.txt
set -u
FF=/c/Users/OS/AppData/Local/Microsoft/WinGet/Links/ffmpeg.exe
OUT=/d/BTL_ATTT/video/public
mkdir -p "$OUT"
TITLE="BTLDEMO"   # do demo-live.sh dat bang ma OSC (tham so -t cua mintty bi them ky tu rac)

# Cua so terminal co dinh kich thuoc, chu lon de doc tren video
/usr/bin/mintty.exe -t "$TITLE" -s 112,36 -p 60,40 \
  -o Font="Cascadia Mono" -o FontHeight=15 -o Scrollbar=none -o Columns=112 -o Rows=36 \
  -o BackgroundColour=11,18,32 -o ForegroundColour=230,237,247 -o CursorType=line \
  -h never /usr/bin/bash /d/BTL_ATTT/scripts/demo-live.sh &
MPID=$!

# Doi den khi co cua so mang dung tieu de roi moi bat dau quay
for i in $(seq 1 40); do
  if powershell.exe -NoProfile -Command "if (Get-Process mintty -ErrorAction SilentlyContinue | Where-Object { \$_.MainWindowTitle -eq '$TITLE' }) { exit 0 } else { exit 1 }"; then break; fi
  sleep 0.25
done
date +%s.%N > /d/BTL_ATTT/video/demo-rec-start.txt
"$FF" -hide_banner -loglevel error -y -f gdigrab -framerate 30 -draw_mouse 0 -i title="$TITLE" \
  -c:v libx264 -preset veryfast -crf 18 -pix_fmt yuv420p "$OUT/demo-raw.mkv" &
FPID=$!

wait $MPID
sleep 1
kill -INT $FPID 2>/dev/null
wait $FPID 2>/dev/null
"$FF" -hide_banner -i "$OUT/demo-raw.mkv" 2>&1 | grep -E 'Duration|Stream'
