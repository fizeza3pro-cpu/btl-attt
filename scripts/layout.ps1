# Sap xep 3 cua so VirtualBox cho quay demo (toa do pixel that, man hinh 2560x1600).
#   powershell -File layout.ps1            -> dat vi tri
#   powershell -File layout.ps1 -Top on    -> dat vi tri + luon nam tren (khi quay)
#   powershell -File layout.ps1 -Top off   -> bo "luon nam tren"
param([string]$Top = '')
Add-Type @"
using System; using System.Runtime.InteropServices;
public class L {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hh, uint f);
}
"@
[L]::SetProcessDPIAware() | Out-Null
$W = 2560; $TOPH = 1010; $BOTH = 1600 - 72 - $TOPH   # chua thanh taskbar ~72 px
# Vien vo hinh cua Windows ~7 px: cho cac cua so chong mep len nhau de khong lo cua so khac phia sau
$E = 8
$plan = @(
  @{ p = 'VirtualBoxVM'; m = 'kali-linux'; x = -$E;        y = 0;          w = $W / 2 + 2 * $E; h = $TOPH + $E },
  @{ p = 'VirtualBoxVM'; m = '^win10 ';    x = $W / 2 - $E; y = 0;          w = $W / 2 + 2 * $E; h = $TOPH + $E },
  # Dai duoi: terminal SSH vao B chay monitor.sh (console chu cua B khong doi duoc do phan giai)
  @{ p = 'mintty';       m = '^BTLMON';    x = -$E;        y = $TOPH - $E; w = $W + 2 * $E;     h = $BOTH + 2 * $E }
)
# Thu nho cua so console cua B (khong dung khi quay)
$b = Get-Process VirtualBoxVM -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match '^unbutu ' } | Select-Object -First 1
if ($b) { [L]::ShowWindow($b.MainWindowHandle, 6) | Out-Null }
$after = [IntPtr]::Zero
if ($Top -eq 'on') { $after = [IntPtr](-1) } elseif ($Top -eq 'off') { $after = [IntPtr](-2) }
$flags = 0x0040   # SWP_SHOWWINDOW
if ($Top -eq '') { $flags = $flags -bor 0x0004 }   # SWP_NOZORDER
foreach ($p in $plan) {
  $proc = Get-Process $p.p -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match $p.m } | Select-Object -First 1
  if (-not $proc) { "KHONG THAY cua so: $($p.m)"; continue }
  [L]::ShowWindow($proc.MainWindowHandle, 9) | Out-Null   # SW_RESTORE
  [L]::SetWindowPos($proc.MainWindowHandle, $after, $p.x, $p.y, $p.w, $p.h, $flags) | Out-Null
  "{0,-12} -> {1},{2} {3}x{4}" -f $p.m, $p.x, $p.y, $p.w, $p.h
}
