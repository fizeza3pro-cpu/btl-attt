# Tao luu luong hop le tu may C (win10) toi web lab.
# Dung (qua SSH, shell mac dinh la PowerShell):
#   & C:\Users\vboxuser\lab\c-traffic.ps1 -Mode light            # 10 request, cach 2 s
#   & C:\Users\vboxuser\lab\c-traffic.ps1 -Mode burst            # 30 request lien tuc
#   & C:\Users\vboxuser\lab\c-traffic.ps1 -Mode browse -Parallel 6   # tai gallery + 31 tai nguyen
#   & C:\Users\vboxuser\lab\c-traffic.ps1 -Mode idle -Seconds 60     # khong tao traffic (do nen)
param(
    [ValidateSet('light', 'burst', 'browse', 'idle')] [string]$Mode = 'light',
    [int]$Parallel = 6,
    [int]$Seconds = 60
)
$T = 'http://10.77.0.20'
switch ($Mode) {
    'light' {
        $codes = foreach ($i in 1..10) { curl.exe -s -o NUL -w '%{http_code}' "$T/"; Start-Sleep -Seconds 2 }
        "light: $($codes -join ' ')"
    }
    'burst' {
        $codes = foreach ($i in 1..30) { curl.exe -s -o NUL -w '%{http_code}' "$T/" }
        "burst: $($codes -join ' ')"
    }
    'browse' {
        $urls = @("$T/gallery.html", "$T/style.css") + (1..30 | ForEach-Object { "$T/img/img{0:D2}.svg" -f $_ })
        $args2 = foreach ($u in $urls) { '-o'; 'NUL'; $u }
        $out = curl.exe -s -Z --parallel-max $Parallel -w '%{http_code} %{num_connects}\n' @args2
        $codes = $out | ForEach-Object { ($_ -split ' ')[0] }
        $conns = ($out | ForEach-Object { [int](($_ -split ' ')[1]) } | Measure-Object -Sum).Sum
        "browse parallel=${Parallel}: $($urls.Count) tai nguyen, ma: $(($codes | Group-Object | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ','), ket noi TCP moi: $conns"
    }
    'idle' {
        Start-Sleep -Seconds $Seconds
        "idle ${Seconds}s"
    }
}
