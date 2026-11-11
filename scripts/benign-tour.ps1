# Mot vong "khach hang that" tren Lab Shop (chay tren may C) - dung de dung KHO HOP LE cho lab-rulegen.
# Moi trang that, tai nguyen, API (xem, them gio, dang nhap, thanh toan, dang xuat), User-Agent trinh duyet that.
# Dung: powershell -ExecutionPolicy Bypass -File C:\Users\vboxuser\lab\benign-tour.ps1
$T  = 'http://10.77.0.20'
$UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0'
$J  = "$env:TEMP\lab-benign-cookies.txt"
Remove-Item $J -ErrorAction SilentlyContinue
$codes = @()
function G($p) { $script:codes += curl.exe -s -o NUL -w '%{http_code}' -A $UA -b $J -c $J "$T$p" }
function P($p, $file) { $script:codes += curl.exe -s -o NUL -w '%{http_code}' -A $UA -b $J -c $J -H 'Content-Type: application/json' --data-binary "@$file" "$T$p" }

$pages = '/', '/index.html', '/about.html', '/gallery.html', '/cart.html', '/login.html', '/login.html?next=cart.html',
         '/index.html?them=3', '/cart.html?dathang=1', '/robots.txt', '/favicon.ico',
         '/shop.css', '/shop.js', '/style.css'
foreach ($p in $pages) { G $p }
foreach ($i in 1..30) { G ('/img/img{0:D2}.svg' -f $i) }
foreach ($p in '/api/health', '/api/products', '/api/cart', '/api/me') { G $p }

$tmp = $env:TEMP
foreach ($id in 1, 3, 3, 7) { Set-Content -Encoding ascii "$tmp\c.json" "{`"id`":$id}"; P '/api/cart' "$tmp\c.json" }
G '/api/cart'
Set-Content -Encoding ascii "$tmp\o.json" '{}'
P '/api/order' "$tmp\o.json"                                   # chua dang nhap -> 401 (hop le)
Set-Content -Encoding ascii "$tmp\l.json" '{"email":"khach@labshop.vn","password":"Khach@2026"}'
P '/api/login' "$tmp\l.json"
G '/api/me'
P '/api/order' "$tmp\o.json"                                   # da dang nhap -> 201
P '/api/logout' "$tmp\o.json"
foreach ($i in 1..5) { G '/api/health' }
"benign-tour: $($codes.Count) request, ma: $(($codes | Group-Object | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ',')"
