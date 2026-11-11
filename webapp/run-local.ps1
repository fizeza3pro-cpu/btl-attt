# run-local.ps1 — Chạy Lab Shop trên MÁY THẬT (Windows) để dev/sửa/test.
#   Lần đầu tự tạo venv + cài phụ thuộc + tạo lab.db, rồi chạy ở http://localhost:8081
#
#   .\run-local.ps1              # chế độ AN TOÀN (LAB_VULN=0)
#   .\run-local.ps1 -Vuln        # BẬT lỗ hổng SQLi để thử tấn công
#   .\run-local.ps1 -Reseed      # tạo lại lab.db từ đầu
param([switch]$Vuln, [switch]$Reseed)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

$pyLauncher = if (Get-Command py -ErrorAction SilentlyContinue) { "py" } else { "python" }

if (-not (Test-Path ".venv")) {
    Write-Host "== Tạo venv ==" -ForegroundColor Cyan
    & $pyLauncher -m venv .venv
}
$py = Join-Path $PSScriptRoot ".venv\Scripts\python.exe"

Write-Host "== Cài phụ thuộc (fastapi, uvicorn) ==" -ForegroundColor Cyan
& $py -m pip install --quiet --upgrade pip
& $py -m pip install --quiet -r requirements.txt

if ($Reseed -or -not (Test-Path "lab.db")) {
    Write-Host "== Tạo CSDL lab.db ==" -ForegroundColor Cyan
    & $py seed.py
}

$env:LAB_VULN = if ($Vuln) { "1" } else { "0" }
$env:LAB_HOST = "127.0.0.1"; $env:LAB_PORT = "8081"
$mode = if ($Vuln) { "CÓ LỖ HỔNG (SQLi bật)" } else { "AN TOÀN" }
Write-Host "== Lab Shop chạy ở http://localhost:8081  [$mode] ==" -ForegroundColor Green
Write-Host "   Swagger: http://localhost:8081/api/docs   (Ctrl+C để dừng)" -ForegroundColor DarkGray
& $py app.py
