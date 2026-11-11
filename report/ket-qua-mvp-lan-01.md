# Kết quả kiểm thử MVP — lần chạy 01

- **Ngày chạy:** 08/11/2026, 19:54–19:57 (+07:00), đồng hồ của B (đã đối chiếu với máy thật).
- **Phạm vi:** detection (chưa có response/nftables).
- **Bằng chứng:** `evidence/run-<ID>-01/` gồm `metadata.txt`, `traffic.pcap`, `eve.json`, `access.log`, `summary.txt`.
- **Script:** `scripts/run-mvp-tests.sh` (điều khiển), `scripts/case-start.sh` / `case-stop.sh` (thu bằng chứng trên B), `scripts/latency.sh`.

## 1. Môi trường

| Thành phần | Giá trị |
|---|---|
| Hypervisor | VirtualBox 7.2.10 trên Windows 11 (chạy qua Hyper-V/NEM) |
| A — Kali Rolling | `10.77.0.10` (lab), `192.168.56.102` (quản trị), nmap 7.99, curl 8.20 |
| B — Ubuntu 26.04.1, kernel 7.0.0 | `10.77.0.20` (lab), 4 vCPU, 4 GB, chế độ dòng lệnh |
| Sensor | Suricata 8.0.3, AF_PACKET trên `enp0s8`, `HOME_NET=[10.77.0.20/32]`, offload GRO/TSO/GSO tắt |
| Web | Nginx 1.28.3, đường dẫn mồi `/lab-admin` → 403, `robots.txt` chứa `Disallow: /lab-admin` |
| Rule | `config/local.rules`: SID 1000001, 1000002, 1000003, 1000007 (+ 9000001 kiểm tra hệ thống) |

## 2. Ma trận kết quả

| ID | Hành vi | Kỳ vọng | Alert thực tế | Nginx | Đánh giá |
|---|---|---|---|---|---|
| N03-01 | 10 request HTTP, cách 2 s | Không alert | Không | 10 × 200 | **TN** ✅ |
| N04-01 | 30 request HTTP liên tục | Có thể 1000001 | 1 × **1000001** | 30 × 200 | **FP** của tín hiệu yếu (đã dự kiến) |
| N07-01 | `/about.html`, `/lab-administrator` | Không 1000002 | Không | 200, 404 | **TN** ✅ (rule khớp chặt) |
| A01-01 | nmap -sT cổng 1–100 | 1000001 + 1000003 | 1 × **1000001**, 1 × **1000003** | — | **TP** ✅ |
| A02-01 | `robots.txt` → `/lab-admin` | 1000002, không 1000007 | 1 × **1000002** | 200, 403 | **TP** ✅ |
| A03-01 | scan → 5 s → `/lab-admin` | 1000001 + 1000003 + 1000002 | đủ 3 SID, cùng nguồn A | 403 | **TP** ✅, đủ điều kiện incident |

Không có SID 1000007 ở mọi ca (đường dẫn mồi luôn trả 403), đúng kỳ vọng.

## 3. Bằng chứng PCAP hỗ trợ nhận định

| ID | SYN tới B | Số cổng đích khác nhau | RST/ACK từ B |
|---|---:|---:|---:|
| N03-01 | 10 | 1 | 0 |
| N04-01 | 30 | **1** | **0** |
| A01-01 | 100 | **100** | **98** |
| A03-01 | 101 | 100 | 98 |

**Nhận xét quan trọng:** N04 và A01 đều kích hoạt SID 1000001, nhưng PCAP phân biệt rõ hai trường hợp: N04 chỉ có **1 cổng đích, 0 RST/ACK** (web dồn dập hợp lệ), còn A01 có **100 cổng, 98 RST/ACK** (thăm dò cổng). SID 1000003 chỉ xuất hiện ở ca thăm dò, đúng như thiết kế tín hiệu củng cố, nên kết hợp 1000001 + 1000003 loại được FP của N04.

## 4. Thời gian

| ID | SID | Từ gói đầu tiên tới khi đủ ngưỡng | Gói đủ ngưỡng → timestamp alert |
|---|---|---:|---:|
| A01-01 | 1000001 | 462 ms | 0 ms |
| A03-01 | 1000001 | 457 ms | 0 ms |
| N04-01 | 1000001 | 175 ms | 0 ms |
| A02-01 | 1000002 | — | 5,0 ms (tới request HTTP) |
| A03-01 | 1000002 | — | 7,1 ms |

**Giới hạn của phép đo:** trường `timestamp` trong EVE là **thời điểm của gói tin**, không phải lúc dòng alert được ghi ra file. Cột cuối vì vậy chỉ xác nhận alert gắn đúng vào gói đủ ngưỡng, **chưa** đo độ trễ xử lý thực. Muốn đo độ trễ "tới khi người vận hành đọc được alert", cần ghi thời điểm dòng log xuất hiện (ví dụ `tail -F` kèm dấu thời gian) — việc của lần đo sau.

## 5. Chỉ số (đơn vị: ca thử có nhãn, n nhỏ)

Nhãn: N03, N04, N07 là bình thường; A01, A02, A03 là cần phát hiện.

| Mức đánh giá | TP | FN | FP | TN | Recall | FPR |
|---|---:|---:|---:|---:|---:|---:|
| Bất kỳ SID nào | 3 | 0 | 1 (N04) | 2 | 3/3 | 1/3 |
| Theo chính sách (cần tín hiệu củng cố hoặc tín hiệu mạnh) | 3 | 0 | 0 | 3 | 3/3 | 0/3 |

Mỗi ca chạy **1 lần**; chưa đủ để kết luận thống kê. Kế hoạch: lặp tối thiểu 5 lần mỗi ca sau khi đóng băng cấu hình.

## 6. Phản ứng thủ công — R01-01

Cấu hình: `config/lab-response.nft` (bảng riêng `inet lab_response`, nạp bằng `lab-response.service`). Chỉ tác động card `enp0s8`; `never_block` = {B, C}; `block_allowed` = {A}; set `blocked_l1` tự hết hạn sau 60 s; rule chỉ drop TCP/80 tới B.

| Bước | Kết quả |
|---|---|
| Trước khi chặn: A → web | 200 ✅ |
| Lệnh chặn | `nft add element inet lab_response blocked_l1 { 10.77.0.10 }` → phần tử có `expires 59s` |
| Khi bị chặn: A → web | thất bại (không kết nối được, curl hết thời gian chờ) ✅ |
| Counter của rule drop | 0 → 3 gói ✅ (chứng minh firewall drop, không phải Nginx từ chối) |
| A → B cổng 22 trên mạng lab | vẫn mở ✅ (chặn đúng phạm vi TCP/80) |
| Kênh quản trị tới A | không ảnh hưởng ✅ |
| Sau khi hết hạn | set rỗng, A → web 200 ✅ |
| Tổng thời gian bị chặn (lệnh chặn → A vào lại được) | **62,9 s** (60 s timeout + chu kỳ thử lại 2 s) |

Quan sát: PCAP ghi **37 gói SYN** của A tới cổng 80 trong lúc bị chặn, nhưng Nginx chỉ ghi **2 request** (trước khi chặn và sau khi hết hạn). Suricata và tcpdump vẫn nhìn thấy gói đã bị firewall drop (AF_PACKET nhận gói trước nftables), nên hiệu lực chặn phải xác minh bằng counter, curl và access log, không dựa vào số alert. Các lần thử lại rải đều trong 60 s nên không vượt ngưỡng SID 1000001.

**R01-01 chưa xác minh C** (chưa có kênh điều khiển win10). Đã bổ sung ở R01-02.

### R01-02 — có kiểm tra C (win10, điều khiển qua OpenSSH trên mạng quản trị)

| Bước | A (Kali) | C (win10) |
|---|---|---|
| Trước khi chặn | 200 | 200 |
| **Trong lúc A bị chặn** | **thất bại** (không kết nối được) | **200** ✅ |
| Sau khi hết hạn | 200 | — |

- Counter rule drop tăng 3 gói trong lúc chặn; cổng 22 của A tới B trên mạng lab vẫn mở.
- Tổng thời gian A bị chặn: **64,8 s**.
- Nginx ghi 2 request của A (trước chặn, sau hết hạn) và 2 request của C; PCAP có 38 SYN từ các nguồn tới B.
- **Kết luận:** chặn đúng đối tượng (A), đúng dịch vụ (TCP/80), có thời hạn, tự phục hồi, và **không ảnh hưởng người dùng hợp lệ C** — đạt tiêu chí 5–7 của demo.

## 7. Chưa kiểm thử / việc tiếp theo

- Baseline từ C (win10): duyệt web bằng Edge, lưu lượng nền của Windows.
- Các ca biên: quét chậm dưới ngưỡng, quét FIN/NULL/Xmas (cần sudo trên Kali), mã hóa URL, IPv6.
- Liên kết sự kiện tự động (analyzer) và chặn theo chính sách.
- Đo độ trễ ghi log thực tế.
