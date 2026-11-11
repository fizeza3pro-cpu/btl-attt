# Bat OpenSSH Server tren win10 (may C) de dieu khien kiem thu tu may that.
# Chay trong win10: PowerShell "Run as Administrator". Can card NAT tam thoi de tai OpenSSH.

# 1) Cai va bat dich vu
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Set-Service -Name sshd -StartupType Automatic
Start-Service sshd

# 2) Chi cho phep SSH tu may that qua mang quan tri (khong mo cong 22 tren mang lab)
Disable-NetFirewallRule -Name OpenSSH-Server-In-TCP -ErrorAction SilentlyContinue
New-NetFirewallRule -Name sshd-lab-mgmt -DisplayName "OpenSSH (lab mgmt only)" -Direction Inbound `
  -Protocol TCP -LocalPort 22 -RemoteAddress 192.168.56.1 -Action Allow | Out-Null

# 3) Shell mac dinh khi SSH vao la PowerShell
New-ItemProperty -Path "HKLM:\SOFTWARE\OpenSSH" -Name DefaultShell `
  -Value "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -PropertyType String -Force | Out-Null

# 4) Cai khoa cong khai cua may that (cho ca tai khoan admin va tai khoan thuong)
$k = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIM20zc5IG2NumdSjhNIT4HANq7QAF7z/+mfBQ069rozQ btl-attt-lab'
$admin = "$env:ProgramData\ssh\administrators_authorized_keys"
Add-Content -Path $admin -Value $k -Encoding ascii
icacls $admin /inheritance:r /grant "*S-1-5-32-544:F" /grant "SYSTEM:F" | Out-Null
New-Item -ItemType Directory -Force "$env:USERPROFILE\.ssh" | Out-Null
Add-Content -Path "$env:USERPROFILE\.ssh\authorized_keys" -Value $k -Encoding ascii

Restart-Service sshd
Get-Service sshd | Format-Table Name, Status, StartType
