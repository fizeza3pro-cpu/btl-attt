# Ảnh / video thật cần cho video BtlReel (bản 2)

Trong video, mỗi chỗ còn thiếu hiện **ô viền cam nét đứt "CHỜ ẢNH/VIDEO THẬT · <tên>"**.
Quay/chụp xong, đặt file vào `video/public/reel/media/` với đúng tên bên dưới (đuôi `.png` cho ảnh, `.mp4` cho video) rồi báo mình.

- Video: **1920×1080**, MP4, không cần tiếng. Quay bằng Xbox Game Bar (Win + Alt + R) trên máy thật, phóng to cửa sổ VM.
- Mỗi đoạn **10–25 giây**, quay dư một chút; mình sẽ cắt / tua nhanh cho khớp lời đọc.
- Phần KỊCH BẢN chạy theo một mạch: nên quay liền một lượt theo thứ tự dưới đây (xem lệnh ở "Kịch bản 4" và "Kịch bản 9" trong file Word).

## Phần giới thiệu thành phần

| Tên file | Loại | Phần | Nội dung |
|---|---|---|---|
| `lab-shop.png` | ảnh | LAB SHOP | Trang chủ Lab Shop mở từ máy C |
| `admin-gia.png` | ảnh | HONEYPOT | Máy A **đang bị đánh lừa** mở `/admin` → trang đăng nhập quản trị **giả** |
| `dashboard.png` | ảnh | DASHBOARD | Dashboard `http://192.168.56.101:9000` lúc có cảnh báo và thẻ chờ duyệt |

## Phần KỊCH BẢN (theo thứ tự)

| # | Tên file | Máy | Nội dung |
|---|---|---|---|
| 1 | `s-nmap.mp4` | A | `nmap -sT -p 1-100 10.77.0.20` (thấy cổng 23, 80…) |
| 2 | `s-canh-bao.mp4` | B | Dashboard/monitor: cảnh báo quét cổng, sự kiện cổng bẫy 23, A chuyển sang **đánh lừa** |
| 3 | `s-robots.mp4` | A | Xem `/robots.txt` (thấy `/admin`, `/backup/`), rồi xem mã nguồn trang chủ (thấy comment `admin / LabShop@2026!`) |
| 4 | `s-admin-login.mp4` | A | Mở `/admin` (trang giả), đăng nhập bằng `admin / LabShop@2026!` |
| 5 | `s-cho-duyet.mp4` | B | Dashboard: sự cố "cắn câu", điểm 310, thẻ chờ duyệt chặn toàn bộ |
| 6 | `s-do-file.mp4` | A | Dò `/.env`, `/.git/config`, `/wp-login.php`, `/phpmyadmin/`… + một yêu cầu SQL injection |
| 7 | `s-sqli.mp4` | B | Monitor: có ALERT SQL injection; các dòng `/.env` chỉ là WEB 404, không có ALERT |
| 8 | `s-luat-moi.mp4` | B | Dashboard mục 🧬 Rule tự sinh: 4 phiếu chờ duyệt, 5 cửa G1–G5 đều ✓ |
| 9 | `s-nap-luat.mp4` | B | Bấm "Duyệt & nạp" 4 phiếu; "Rule đang chạy" hiện 4 rule (hoặc `ruleset-stats`: 17) |
| 10 | `s-bien-the.mp4` | A/B | A dò `/.env.production`, `/.ENV.dev`…; monitor B hiện ALERT `LAB AUTO uri probe` |
| 11 | `s-chan.mp4` | B | Dashboard: bấm "Duyệt chặn toàn bộ" cho 10.77.0.10 |
| 12 | `s-ket-qua.mp4` | A + C | Hai cửa sổ cạnh nhau: A chạy `curl` bị treo/000 · C vẫn thêm giỏ hàng, đặt hàng |

Lưu ý khi quay bước 6–10: để analyzer ở chế độ `recommend` nếu muốn A không bị chặn giữa chừng (như Kịch bản 9 trong file Word), và chạy `~/lab/rulegen-reset.sh` trước để bộ tự sinh luật về ban đầu.
