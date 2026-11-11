# Kết quả nâng cấp — Mini-SOC phòng thủ nhiều lớp

- **Ngày thực hiện:** 10/11/2026.
- **Mục tiêu:** nâng bài từ "IDS chặn quét cổng" thành hệ thống phòng thủ nhiều lớp: phòng ngừa, phát hiện đa nguồn, đánh lừa chủ động, phản ứng có con người duyệt, điều tra (ATT&CK, báo cáo sự cố), và tự kiểm chứng lỗ hổng của chính hệ thống.
- **Bằng chứng:** `evidence/run-{X02-before-01, X02-after-01, D01-01, N10-01, W10-01…W14-01, S01-01}/`, `tests/soc-incidents.jsonl`, `tests/soc-decisions.jsonl`, `tests/honeypot-events.jsonl`, `tests/auth-events.jsonl`, `logs/test-analyzer-v2.log`.

## 1. Kiến trúc sau nâng cấp

```text
                       Mạng lab 10.77.0.0/24 (chỉ IPv4)
A Kali ─┬────────────────────────────────────────────────────────┐
C Win10 ┘                                                         ▼
                                                  B Ubuntu 10.77.0.20
  nftables inet lab_response ── prerouting: A "bị đánh lừa" :80 → :8083 (bản sao honeypot)
                              └ input: IPv6 TCP/UDP drop · chặn web (l1) · chặn toàn bộ TCP (l2)
  Nginx :80   Lab Shop + API (/api/*, rate limit, CSP)  · /api/admin, /backup → honeypot
  Nginx :8083 bản sao Lab Shop: /admin = trang quản trị GIẢ
  lab-shop-api (user labshop)   → auth.jsonl  (đăng nhập sai / bị khóa)
  lab-honeypot (user labhoney)  → events.jsonl (admin giả, honeytoken, cổng bẫy 23/2222/3306)
  Suricata 8.0.3 (20 rule)      → eve.json
  analyzer v2 (user labresp)    ← 3 nguồn → chấm điểm + ATT&CK → incident → lab-block (sudo, quyền duy nhất)
  lab-soc :9000 (chỉ mạng quản trị 192.168.56.0/24, chỉ máy thật) → dashboard, duyệt, báo cáo
```

| Dịch vụ | User | Quyền đặc biệt |
|---|---|---|
| lab-shop-api | `labshop` | không |
| lab-honeypot | `labhoney` | chỉ `CAP_NET_BIND_SERVICE` (mở cổng 23) |
| lab-analyzer, lab-soc | `labresp` | chỉ `sudo /usr/local/sbin/lab-block` |
| lab-block | root | nhận đúng `add/del l1/l2/dec <IP>`, IP phải thuộc danh sách cho phép |

## 2. Các lớp phòng thủ

### 2.1. Phòng ngừa
- Lab Shop: mật khẩu băm PBKDF2-SHA256, **khóa IP 5 phút sau 5 lần sai**; kiểm tra định dạng đầu vào; cookie phiên `HttpOnly; SameSite=Lax`.
- Nginx: giới hạn tốc độ (`/api/login` 10 request/phút, API 30 request/giây), header `Content-Security-Policy`, `X-Frame-Options: DENY`, `X-Content-Type-Options`, `Referrer-Policy`, ẩn phiên bản.
- Firewall: chặn IPv6 trên card lab (vá lỗ hổng X02).

### 2.2. Phát hiện đa nguồn
| Nguồn | Tín hiệu |
|---|---|
| Suricata (mạng) | quét cổng nhanh/chậm, trang bẫy, **SQLi** (URL + body), **XSS** (URL + body), **path traversal**, **nhiều phản hồi 401** |
| Honeypot | xem/đăng nhập trang admin giả, **dùng honeytoken** (tài khoản, API key, file sao lưu), kết nối cổng bẫy |
| Ứng dụng | ≥ 5 lần đăng nhập sai / 120 s, IP bị khóa |

### 2.3. Đánh lừa (deception)
- **Honeytoken** gài sẵn: tài khoản admin trong comment HTML, API key trong một dòng code bị comment của `shop.js`, thư mục `/backup/` trong `robots.txt`. Người dùng thật không bao giờ đụng tới → **gần như không báo nhầm**, và mọi tín hiệu đều cần kết nối TCP thật → **không giả mạo IP được**.
- **Cổng bẫy** 23/2222/3306: banner giống dịch vụ thật, ghi lại dữ liệu kẻ tấn công gửi.
- **Phản ứng đánh lừa**: thay vì chặn ngay, kẻ tấn công bị chuyển sang bản sao Lab Shop. Trang chủ trông như cũ, đèn máy chủ vẫn xanh, nhưng `/admin` là trang đăng nhập giả ghi lại mọi tài khoản/mật khẩu thử.

### 2.4. Phản ứng có con người duyệt
| Giai đoạn | Điều kiện | Hành động |
|---|---|---|
| Trinh sát | điểm < 100 hoặc chỉ tín hiệu giả mạo được | ghi nhận / incident |
| Đủ bằng chứng | điểm ≥ 100 **và** có tín hiệu thật, nguồn được phép | **đánh lừa** (`dec`, 10 phút) — tự động |
| Cắn câu | đang bị đánh lừa mà tiếp tục dùng honeypot/honeytoken | incident `attacker_engaged` → **chờ người vận hành duyệt** |
| Duyệt | bấm "Duyệt chặn hoàn toàn" trên dashboard | **chặn toàn bộ TCP** (`l2`, 10 phút), gỡ đánh lừa, ghi nhật ký quyết định |

Vẫn giữ: danh sách không bao giờ chặn (B, C), giới hạn chỉ chặn được A, mọi trạng thái tự hết hạn trong kernel, cooldown.

### 2.5. Điều tra
- Mỗi tín hiệu gắn **MITRE ATT&CK**: T1595, T1046, T1083, T1190, T1078, T1110.001, T1552.001, T1213.
- **Báo cáo sự cố** tự sinh `/report/<incident_id>`: nghi phạm, điểm, lý do quyết định, bảng ATT&CK, dòng thời gian bằng chứng nhiều nguồn, quyết định của người vận hành, nơi tra bằng chứng gốc.

## 3. Kết quả kiểm thử

### 3.1. Lỗ hổng lách chặn qua IPv6 (X02) — tự tìm và tự vá
| | A → IPv4 | A → IPv6 (link-local) |
|---|---|---|
| Trước khi vá, A bị chặn | 000 | **200 — lách được**, Nginx ghi request từ `fe80::90a5:…`, Suricata không cảnh báo |
| Sau khi vá, A bị chặn | 000 | **000**, rule `lab-ipv6-policy` drop 7 gói |

### 3.2. Đánh lừa (D01)
| Bước | Kết quả |
|---|---|
| A vào `/admin` khi chưa bị đánh lừa | 403 |
| Sau khi bị đánh lừa | **200: trang admin giả**; C cùng lúc vẫn 403; trang chủ của A vẫn 200 (A không nhận ra) |
| A thử `root/123456`, dùng tài khoản trong comment, tải `/backup/…`, dùng API key, kết nối 3306 | 6 sự kiện honeypot ghi đầy đủ (kể cả mật khẩu thử) |

### 3.3. Tấn công ứng dụng web (W10–W14, N10)
| Ca | Tấn công | Kết quả |
|---|---|---|
| N10 | C đăng nhập đúng | 200, không cảnh báo |
| W10 | A dò mật khẩu 7 lần | 401 ×5 → **429 (khóa IP)**; SID 1000017; auth: 5 sai + 1 khóa |
| W11 | SQLi trong URL và body | **SID 1000013 + 1000015** (phát hiện kể cả khi API đang khóa A) |
| W12 | XSS trong URL | **SID 1000014** |
| W13 | Path traversal thô và mã hóa | **SID 1000006 + 1000008**, Nginx 400 |
| W14 | 15 request đăng nhập dồn dập | toàn bộ 429 (giới hạn tốc độ Nginx + khóa ở ứng dụng) |

### 3.4. Kịch bản tổng hợp (S01)
1. C mua hàng, đăng nhập: 200/200.
2. A `nmap -sT` cổng 1–100 → chạm **cổng bẫy 23** (bắt tay TCP đầy đủ = tín hiệu thật) → 60 điểm → 110 điểm → **analyzer tự đánh lừa A**.
3. A đọc `robots.txt`, mã nguồn trang → thấy tài khoản trong comment.
4. A vào `/admin` (200 — trang giả), đăng nhập bằng tài khoản bẫy (302), thử `root/toor` → **3 incident `attacker_engaged`**: ATT&CK T1046 → T1595 → **T1078** → **T1110.001**, điểm 310.
5. Dashboard: **1 yêu cầu chờ duyệt** (gộp theo IP) → người vận hành duyệt → **A bị chặn toàn bộ TCP** (web 000, SSH bị chặn), C vẫn 200.

### 3.5. Bộ kiểm thử analyzer offline: **32/32**
Gồm 19 ca cũ (không thay đổi hành vi) và 13 ca mới: honeytoken → đánh lừa; quét + cổng bẫy → đánh lừa; không dry-run → chỉ đề xuất; cắn câu → chờ duyệt; 5 lần sai (incident) / 5 lần sai + bị khóa (đánh lừa) / 5 lần sai rải rác > 120 s (chỉ ghi nhận); SQLi → đánh lừa hoặc đề xuất chặn tùy chế độ; C dùng honeytoken → được bảo vệ; bỏ qua SID 1000007 khi đang đánh lừa; ATT&CK đúng; mỗi loại hành vi cắn câu mới đều thành incident; offline không chạm firewall.

### 3.6. Bảo mật của chính hệ thống giám sát
| Kiểm tra | Kết quả |
|---|---|
| Dashboard từ mạng lab (A) | không kết nối được |
| Dashboard từ chính B (không phải máy thật) | 403 |
| Gửi lệnh với token sai (CSRF) | 403 |
| A nhét `<img src=x onerror=alert(1)>` vào email đăng nhập | API trả 400; dashboard hiển thị như chữ thường, 0 thẻ `<img>` được tạo |
| Analyzer đọc log của dịch vụ khác | chuyển dịch vụ từ `DynamicUser` (log nằm trong `/var/log/private` 0700) sang user cố định, log 0644 |

## 4. Sự cố và bài học khi triển khai
- Hai rule SQLi lỗi cú pháp vì dấu `;` trong `pcre` → Suricata vẫn chạy với các rule còn lại. Đã viết `;` thành `\x3b`, và quy trình cài rule giờ **dừng hẳn nếu `suricata -T` báo lỗi**.
- Bộ kiểm thử phát hiện analyzer chỉ báo hành vi cắn câu đầu tiên, bỏ sót việc dùng tài khoản bẫy ngay sau đó → sửa: mỗi **loại** hành vi mới đều thành incident.
- Dashboard ban đầu hiện nhiều thẻ chờ duyệt cho cùng một IP → gộp còn thẻ mới nhất.

## 5. Giới hạn
- Honeypot dễ bị kẻ tấn công kinh nghiệm nhận ra (cổng 8083 lộ nếu quét đủ cổng, dữ liệu admin giả đơn giản).
- `nmap -sS` (SYN scan) không hoàn tất bắt tay → không kích hoạt cổng bẫy; trường hợp này quay về các tín hiệu giả mạo được như trước.
- CSP còn `'unsafe-inline'` cho script do trang có script nội tuyến.
- Giỏ hàng, phiên, khóa IP lưu trong bộ nhớ của API (mất khi khởi động lại).
- Giả mạo IP thật trên mạng vẫn mới kiểm chứng bằng dữ liệu giả lập.
