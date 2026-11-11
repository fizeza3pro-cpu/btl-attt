param([string]$Match, [int]$X, [int]$Y, [int]$W, [int]$H)
Add-Type @"
using System; using System.Runtime.InteropServices;
public class L2 {
  [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
  [DllImport("user32.dll")] public static extern bool SetWindowPos(IntPtr h, IntPtr after, int x, int y, int w, int hh, uint f);
}
"@
[L2]::SetProcessDPIAware() | Out-Null
$p = Get-Process VirtualBoxVM -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match $Match } | Select-Object -First 1
if (-not $p) { "not found"; exit 1 }
[L2]::ShowWindow($p.MainWindowHandle, 9) | Out-Null
[L2]::SetWindowPos($p.MainWindowHandle, [IntPtr]::Zero, $X, $Y, $W, $H, 0x0040) | Out-Null
$p.MainWindowTitle
