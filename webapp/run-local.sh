#!/usr/bin/env bash
# run-local.sh — Chạy Lab Shop ở localhost để dev/test (Linux/Kali/máy thật qua Git Bash).
#   ./run-local.sh            # chế độ AN TOÀN (LAB_VULN=0)
#   LAB_VULN=1 ./run-local.sh # BẬT lỗ hổng SQLi
#   RESEED=1 ./run-local.sh   # tạo lại lab.db
set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python3}"
[ -d .venv ] || { echo "== Tạo venv =="; "$PY" -m venv .venv; }
PY=.venv/bin/python
[ -x "$PY" ] || PY=.venv/Scripts/python   # Git Bash trên Windows

echo "== Cài phụ thuộc =="
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet -r requirements.txt

if [ "${RESEED:-0}" = 1 ] || [ ! -f lab.db ]; then
  echo "== Tạo CSDL lab.db =="; "$PY" seed.py
fi

export LAB_VULN="${LAB_VULN:-0}" LAB_HOST=127.0.0.1 LAB_PORT=8081
[ "$LAB_VULN" = 1 ] && echo "== Lab Shop [CÓ LỖ HỔNG] http://localhost:8081 ==" \
                    || echo "== Lab Shop [AN TOÀN] http://localhost:8081 =="
echo "   Swagger: http://localhost:8081/api/docs"
exec "$PY" app.py
