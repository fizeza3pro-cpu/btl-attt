# Kết quả M5 — Liên kết sự kiện và phản ứng tự động có giới hạn

- **Ngày chạy:** 08/11/2026, 22:00–22:30 (+07:00).
- **Thành phần:** `scripts/analyzer.py` (cài tại `/usr/local/lib/lab/analyzer.py`, service `lab-analyzer`), `scripts/lab-block` (cài tại `/usr/local/sbin/lab-block`), `config/lab-analyzer.service`.
- **Bằng chứng:** `evidence/run-M5-*`, `tests/m5-incidents.jsonl`, `logs/test-analyzer.log`, `logs/run-m5.log`.
- **Trạng thái sau kiểm thử:** analyzer chạy ở `MODE=recommend` (chỉ đề xuất). Đổi sang chặn tự động: `echo MODE=apply | sudo tee /etc/default/lab-analyzer && sudo systemctl restart lab-analyzer`.

## 1. Kiến trúc và tách quyền

```text
Suricata ──► eve.json (root, chỉ đọc với user khác)
                │  dữ liệu KHÔNG tin cậy (URL, User-Agent do kẻ tấn công kiểm soát)
                ▼
     analyzer.py  — user hệ thống labresp, không shell, không root
       chuẩn hóa → chấm điểm → quyết định → incidents.jsonl
                │  chỉ khi MODE=apply và đủ mọi điều kiện
                ▼
     sudo -n /usr/local/sbin/lab-block add l1 <ip>   ← quyền sudo DUY NHẤT của labresp
                │  kiểm tra lại IP (định dạng + danh sách cho phép), gọi nft đường dẫn tuyệt đối
                ▼
     nftables: inet lab_response / blocked_l1 (timeout 60 s trong kernel)
```

| Kiểm tra quyền (thực tế trên B) | Kết quả |
|---|---|
| `labresp` chặn C (`10.77.0.30`) qua executor | **Từ chối** — `ip not in ALLOWED` |
| `labresp` truyền `10.77.0.10;id` | **Từ chối** — `invalid ipv4` |
| `labresp` gọi trực tiếp `sudo nft` | **sudo từ chối** |
| Gỡ chặn một IP không có trong set | Báo **thất bại** (không báo thành công giả) |
| Mã nguồn analyzer | thuộc root, `labresp` không sửa được |

## 2. Chính sách chấm điểm (đã cài)

| SID | Điểm | Giả mạo IP được? | Nghi phạm |
|---|---:|---|---|
| 1000001 tốc độ SYN | 20 | có | nguồn |
| 1000003 RST/ACK 10 s | 50 | có | đích của alert |
| 1000005 RST/ACK 60 s | 50 | có | đích của alert |
| 1000002 đường dẫn mồi | 70 | **không** | nguồn |
| 1000007 mồi trả khác 403 | 100 | **không** | đích của alert |

Cửa sổ trượt 120 s theo nghi phạm; mỗi SID tính một lần trong cửa sổ. Ngưỡng incident 50, ngưỡng chặn 100.

| Điều kiện | Quyết định |
|---|---|
| < 50 | `log` (chỉ ghi nhận, không phát incident) |
| 50–99 | `incident_medium` |
| ≥ 100, không có tín hiệu không giả mạo được | `incident_high_spoof_suspect` — **không chặn** |
| ≥ 100, nghi phạm thuộc NEVER_BLOCK (B, C) | `incident_high_protected` — **không chặn** |
| ≥ 100, nghi phạm ngoài BLOCK_ALLOWED | `recommend_only_out_of_scope` |
| đang bị chặn | `already_blocked` — không gia hạn |
| offline / event cũ > 15 s / MODE=recommend | `recommend_block_l1` |
| còn lại | `block_l1` → gọi executor, xác minh lại trạng thái set |

Ghi chú thiết kế: điểm của tín hiệu củng cố được đặt **50** để thống nhất với định nghĩa "phát hiện theo chính sách" đã dùng ở M4 (một tín hiệu củng cố đủ tạo incident). Lần đầu đặt 30 khiến quét chậm chỉ được "ghi nhận" — mâu thuẫn được phát hiện nhờ bộ kiểm thử offline.

## 3. Kiểm thử offline — 19/19 đạt

`scripts/test-analyzer.sh` chạy analyzer `--offline` trên EVE thật và EVE giả lập:

| Nhóm | Ca | Kết quả |
|---|---|---|
| EVE thật (M4) | N03, N04, CN06 → `log`; A01, A02 → `incident_medium`; A03 → `recommend_block_l1` | đạt |
| EVE phát lại v3 | E01 (quét chậm) → `incident_medium`; A03-02 → `recommend_block_l1` | đạt |
| **Giả mạo C** (SYN + RST + RST-60s mang IP của C, 120 điểm) | `incident_high_spoof_suspect` — **không chặn C** | đạt |
| Giả mạo lặp lại | không cộng dồn điểm | đạt |
| C thực sự vào bẫy (có tín hiệu thật) | `incident_high_protected` — không chặn, báo người vận hành | đạt |
| Nguồn lạ 10.77.0.40 | `recommend_only_out_of_scope` | đạt |
| IP ngoài mạng lab | bỏ qua | đạt |
| Bẫy trả mã khác 403 | `recommend_block_l1` | đạt |
| URL chứa `$(id)`, ký tự điều khiển, JSON hỏng | xử lý bình thường, **không có ký tự điều khiển trong output** | đạt |
| `--offline --mode apply` | firewall **không thay đổi** | đạt |

## 4. Kiểm thử live

| Ca | Chế độ | Hành vi của A | Diễn biến incident (điểm cộng dồn) | Firewall | A / C |
|---|---|---|---|---|---|
| M5-REC-01 | recommend | quét + vào bẫy | 70 → 120 (nghi giả mạo) → 190 `recommend_block_l1` | **không đổi** | 200 / 200 |
| M5-APP-01 | apply | chỉ vào bẫy | 70 `incident_medium` | **không đổi** | 200 |
| M5-APP-02 | apply | quét + vào bẫy | 120 (nghi giả mạo, không chặn) → 190 **`block_l1`** | A bị chặn | **000 / 200** |
| (cooldown) | apply | A quét lại khi đang bị chặn | không phát incident mới | hạn chặn **không gia hạn** (50,6 s → 41,1 s) | — |
| (phục hồi) | — | — | — | set tự rỗng, counter drop = 19 gói | A 200 |

- **Độ trễ analyzer** (thời điểm gói tin trong EVE → quyết định): **0,07–0,22 s**.
- Ở cả hai ca quét + bẫy, analyzer **từ chối chặn ở mức 120 điểm** vì lúc đó chỉ có tín hiệu giả mạo được, và **chỉ chặn sau khi có tín hiệu từ kết nối TCP thật** (truy cập bẫy). Đây là điều kiện chống giả mạo hoạt động trong thực tế.
- Khởi động/khởi động lại service **không xử lý lại log cũ** (0 incident từ lịch sử).

## 5. Giới hạn

- Kịch bản giả mạo IP mới được kiểm chứng bằng **EVE giả lập** (logic quyết định), chưa phát gói giả mạo thật trên mạng lab (cần quyền root trên Kali).
- `already_blocked` không được ghi thành incident riêng (tránh lặp); bằng chứng cooldown là thời hạn trong set không bị đặt lại.
- Chặn theo IP: kẻ tấn công đổi IP thì cần phát hiện lại; nguồn ngoài `BLOCK_ALLOWED` chỉ được đề xuất (giới hạn an toàn có chủ đích của lab).
- Chỉ IPv4; IPv6 trên card lab vẫn mở (đã ghi nhận là rủi ro lách chặn, chưa xử lý).
- Trạng thái cửa sổ nằm trong bộ nhớ: khởi động lại analyzer làm mất điểm đang tích lũy (chặn đang có hiệu lực vẫn do kernel giữ đến hết hạn).
