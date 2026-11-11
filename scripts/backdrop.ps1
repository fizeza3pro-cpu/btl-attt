# Tam nen den toan man hinh, luon nam tren (dat TRUOC 3 cua so demo de chung nam tren no).
# Che moi khe ho giua cac cua so va thanh taskbar khi quay -> khong lo noi dung ca nhan.
# Chay: powershell -WindowStyle Hidden -File backdrop.ps1   (dong bang: Stop-Process theo PID)
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System; using System.Runtime.InteropServices;
public class D { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }
"@
[D]::SetProcessDPIAware() | Out-Null
$f = New-Object System.Windows.Forms.Form
$f.Text = 'BTLBACKDROP'
$f.FormBorderStyle = 'None'
$f.BackColor = [System.Drawing.Color]::FromArgb(11, 18, 32)
$f.StartPosition = 'Manual'
$b = [System.Windows.Forms.Screen]::PrimaryScreen.Bounds
$f.Bounds = $b
$f.TopMost = $true
$f.ShowInTaskbar = $false
[System.Windows.Forms.Application]::Run($f)
