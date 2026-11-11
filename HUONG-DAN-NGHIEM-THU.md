# Hướng dẫn nghiệm thu

## 1. Chuẩn bị (mỗi lần bật máy)

1. Mở VirtualBox, bật **B (unbutu) trước**, đợi khoảng 30 giây, rồi bật **A (Kali)** và **C (win10)**. B cấp IP cho A và C; nếu bật sai thứ tự, A/C sẽ không có IP.
2. Mở **Git Bash** trên máy thật, chuyển vào thư mục dự án:
   ```bash
   cd /d/BTL_ATTT
   ```
3. Kiểm tra kết nối tới 3 máy (mỗi dòng phải in `ok`):
   ```bash
   for h in labA labB labC; do printf "%s: " $h; ssh -o BatchMode=yes -o ConnectTimeout=5 $h "echo ok"; done
   ```
4. Kiểm tra dịch vụ trên B (phải ra 5 lần `active`):
   ```bash
   ssh labB 'systemctl is-active suricata nginx dnsmasq lab-response lab-analyzer'
   ```

**Lưu ý chung**
- **Đưa B về trạng thái sạch trước mỗi kịch bản: `~/lab/reset-lab.sh`** (gỡ chặn/đánh lừa, bỏ qua yêu cầu chờ duyệt, xóa trí nhớ analyzer, xóa khóa đăng nhập/giỏ hàng, tự kiểm tra; giữ log và rule tự sinh). Chọn chế độ luôn: `~/lab/reset-lab.sh danh-lua` hoặc `~/lab/reset-lab.sh chan`; thêm `--xoa-rule` để thu hồi rule tự sinh. Khoảng 8 giây, không cần chờ 2 phút như cách dưới.
- Giữa hai lần chạy ca tấn công (nếu không dùng `reset-lab.sh`), **chờ ít nhất 2 phút** để cửa sổ tương quan 120 giây của analyzer làm mới, nếu không điểm sẽ cộng dồn từ lần trước.
- Analyzer mặc định ở `MODE=recommend` (chỉ đề xuất, không chặn). Các script tự bật/tắt chế độ `apply` khi cần.
- Bộ chạy ghi bằng chứng vào `~/lab/evidence/run-<ca>-<lần>/` trên B. **Dùng hậu tố lần chạy mới** (ví dụ `10`, `11`) để không ghi đè dữ liệu cũ. Bản sao dữ liệu đã nộp nằm ở `D:\BTL_ATTT\evidence\`.

### Lab Shop có backend API (cập nhật 10/11/2026)

- Mọi thao tác trên web (tải sản phẩm, thêm giỏ, đặt hàng) gọi API thật trên B (`/api/...`, dịch vụ `lab-shop-api`).
- Góc trên trang có **đèn trạng thái máy chủ**, kiểm tra mỗi 3 giây: 🟢 "Máy chủ trực tuyến" / 🔴 "Mất kết nối máy chủ". Khi A bị chặn, đèn trên trình duyệt của A chuyển đỏ và thêm giỏ báo lỗi.
- Máy chủ đã tắt bộ nhớ đệm (`Cache-Control: no-cache`). **Lần đầu sau khi cập nhật, bấm Ctrl+F5 (Edge) / Ctrl+Shift+R (Firefox) một lần** để bỏ bản trang cũ đã lưu.
- **Thanh toán bắt buộc đăng nhập (cập nhật):** giỏ hàng chưa đăng nhập hiện nút *Đăng nhập để thanh toán*; `POST /api/order` trả **401** nếu phiên chưa đăng nhập (kiểm tra ở máy chủ, không chỉ ẩn nút). Tài khoản khách thử nghiệm: `khach@labshop.vn` / `Khach@2026`. Script demo cũ `cart.html?dathang=1` giờ cần đăng nhập trước.
- Tài liệu chi tiết toàn hệ thống + 8 kịch bản demo (làm hoàn toàn trên 3 máy ảo, không SSH): `BTL-ATTT-Huong-dan-chi-tiet.docx`.
- **Màn hình giám sát** trên B: `~/lab/monitor.sh` — tiếng Việt, mỗi sự kiện ghi rõ máy nào (A·Kali, C·Win10), làm gì, nghĩa là gì: 🌐 WEB, ⚠️ CẢNH BÁO (kèm điểm, bằng chứng thật hay có thể bị giả IP), 🍯 HONEYPOT, 🔑 ĐĂNG NHẬP, 🧠 PHÂN TÍCH (liệt kê từng bằng chứng + quyết định + lý do), 🛡 TƯỜNG LỬA, 👤 VẬN HÀNH, ⚙️ CHẾ ĐỘ, 🧬 RULE MỚI. Thêm `--tat-ca` để hiện cả file tĩnh, `--health` để hiện /api/health.
- Xem riêng log thô: hoặc riêng log web: `~/lab/weblog.sh`, chỉ API: `~/lab/weblog.sh api`, log của backend: `~/lab/weblog.sh api-log`.

## 2. Các bài kiểm tra

| # | Kiểm tra | Lệnh | Thời gian | Kết quả đúng |
|---|---|---|---|---|
| T1 | Web Lab Shop, API và trang bẫy | `ssh labB '~/lab/check-web.sh'` | vài giây | 24/24 dòng `OK` (gồm 3 cổng bẫy honeypot) |
| T2 | Bộ ca cơ bản (bình thường + tấn công) | `bash scripts/run-mvp-tests.sh 10` | ~3 phút | N03, N07: không alert · N04: chỉ SID 1000001 · A01: 1000001 + 1000003 (+1000005) · A02: 1000002 · A03: đủ cả |
| T3 | Chặn thủ công, kiểm tra C không bị ảnh hưởng | `bash scripts/run-block-test.sh 10` | ~1,5 phút | A: 200 → 000 khi bị chặn → 200 sau ~60 s · C luôn 200 · counter tăng |
| T4 | Analyzer offline (logic chính sách, chống giả mạo, đánh lừa, ATT&CK, rule tự sinh) | `ssh labB '~/lab/test-analyzer.sh'` | ~30 giây | `PASS=37 FAIL=0` |
| T5 | Analyzer live: đề xuất → chặn tự động → cooldown → phục hồi | `bash scripts/run-m5-tests.sh` | ~6 phút | 120 điểm: không chặn · 190 điểm: `block_l1` · A 000, C 200 · hạn chặn không được gia hạn · A phục hồi |
| T6 | Rule quét chậm trên biến thể mới | `bash scripts/run-m4.sh v3` | ~5 phút | E03 có SID 1000005 · E04 lọt (đúng giới hạn) · N04/CN06 không có 1000005 |
| T7 | Tổng hợp chỉ số từ toàn bộ bằng chứng trên B | `ssh labB '~/lab/aggregate.sh > ~/lab/results.csv && ~/lab/metrics.sh ~/lab/results.csv'` | ~1 phút | Bảng TP/FP/FN/TN và Recall/FPR/Precision/F1 |
| T8 | Phát lại PCAP với bộ rule hiện tại | `ssh labB 'sudo ~/lab/replay.sh /etc/suricata/rules/local.rules kiemtra'` | ~3 phút | File `~/lab/replay/replay-kiemtra.csv` |

### Mini-SOC (nâng cấp 10/11/2026)

| # | Kiểm tra | Lệnh | Kết quả đúng |
|---|---|---|---|
| T9 | Lỗ hổng IPv6 đã vá | `bash scripts/run-ipv6-test.sh after 10` | khi A bị chặn: IPv4 000, **IPv6 000** |
| T10 | Đánh lừa + honeytoken | `bash scripts/run-deception-test.sh 10` | A bị đánh lừa thấy /admin 200 (giả), C vẫn 403; 6 sự kiện honeypot |
| T11 | Tấn công ứng dụng web | `bash scripts/run-webattack-tests.sh 10` | dò mật khẩu → 429 + SID 1000017; SQLi/XSS/traversal có SID tương ứng; C đăng nhập 200 |
| T12 | Kịch bản SOC đầy đủ | `bash scripts/run-soc-scenario.sh 10` rồi mở dashboard | quét → đánh lừa → cắn câu → 1 yêu cầu duyệt → duyệt → A bị chặn toàn bộ, C 200 |
| T13 | Dọn dẹp sau T12 | `bash scripts/run-soc-scenario.sh cleanup` | gỡ hết chặn, analyzer về `recommend` |
| T14 | Tự sinh luật (lab-rulegen) | Làm theo **kịch bản 9** trong `BTL-ATTT-Huong-dan-chi-tiet.docx` (trực tiếp trên 3 máy ảo) | 4 phiếu `/.env` `/wp-` `/phpmyadmin` `/.git/` đạt G1–G5 → duyệt → Suricata 17 rule → 6/6 biến thể mới bị bắt, trang thật không bị bắt |
| T15 | Dọn dẹp sau T14 | `ssh labB '~/lab/reset-lab.sh --xoa-rule'` | 0 rule tự sinh, 0 phiếu, Suricata 13 rule |

**Dashboard:** mở `http://192.168.56.101:9000` trên trình duyệt của **máy thật** hoặc **Firefox ngay trên B** (A và C không mở được — đó là thiết kế). Mục 🧬 **Rule tự sinh**: phiếu đề xuất kèm 5 cửa kiểm chứng, nút Duyệt & nạp / Từ chối / Thu hồi / Phân tích ngay.
- Thiết bị **chỉ xuất hiện khi có hoạt động** (truy cập web, cảnh báo, honeypot, đăng nhập) trong 30 phút gần nhất, hoặc đang bị đánh lừa/chặn. Bật thêm một máy bất kỳ trong mạng lab và truy cập Lab Shop → máy đó tự hiện.
- Bấm vào một thiết bị (hoặc IP trong luồng sự kiện) để mở ngăn chi tiết: thống kê, ATT&CK, đường dẫn truy cập nhiều nhất, dòng thời gian riêng, các nút **Đánh lừa / Chặn web 60s / Chặn toàn bộ / Gỡ tất cả** (chỉ IP trong danh sách cho phép mới phản ứng được).
- Ô tìm kiếm lọc cả bảng thiết bị lẫn luồng sự kiện; tab lọc theo loại sự kiện; thông báo bật lên khi có sự cố mới.
- "Duyệt chặn toàn bộ" / "Bỏ qua" trong khung **Cần xử lý**; "Báo cáo ↗" mở báo cáo sự cố (Ctrl+P để lưu PDF).

**Bộ đánh giá đầy đủ M4** (khoảng 40 phút, chạy lại cả 53 ca): `bash scripts/run-m4.sh all`.
⚠ Bộ này dùng hậu tố cố định 01–05, sẽ ghi đè bằng chứng M4 trên B. Bản đã nộp ở `D:\BTL_ATTT\evidence\` không bị ảnh hưởng.

## 3. Thử bằng tay (trực quan nhất)

1. Mở màn hình giám sát B, để cửa sổ này chạy:
   ```bash
   ssh -t labB '~/lab/monitor.sh'
   ```
2. Bật chặn tự động (ở một cửa sổ Git Bash khác):
   ```bash
   ssh labB 'echo MODE=apply | sudo tee /etc/default/lab-analyzer && sudo systemctl restart lab-analyzer'
   ```
3. Trên **Kali** (terminal):
   ```bash
   nmap -sT -Pn -n --max-rate 20 -p 1-100 10.77.0.20
   ```
   → màn hình B: 3 dòng ⚠️ CẢNH BÁO, 🧠 PHÂN TÍCH **120/100 điểm → KHÔNG CHẶN** (toàn bằng chứng có thể bị giả IP).
4. Trên Kali, mở Firefox vào `http://10.77.0.20/robots.txt`, rồi `http://10.77.0.20/admin` → trang 403
   → màn hình B: ⚠️ CẢNH BÁO rule 1000002 (+70 điểm, bằng chứng ✓ thật), 🧠 PHÂN TÍCH **→ CHẶN WEB 60 GIÂY**, 🛡 TƯỜNG LỬA "BỊ CHẶN WEB còn 59 giây".
5. Trong 60 giây đó: Kali vào `http://10.77.0.20/` **không được**; Win10 (Edge) vào `http://10.77.0.20/` **vẫn mua hàng được**.
6. Sau 60 giây: Kali vào lại được.
7. Trả analyzer về chế độ an toàn:
   ```bash
   ssh labB 'echo MODE=recommend | sudo tee /etc/default/lab-analyzer && sudo systemctl restart lab-analyzer'
   ```

## 4. Demo 3 máy tự động (như trong video)

Yêu cầu: Kali đã đăng nhập giao diện đồ họa và đang mở sẵn terminal kẻ tấn công + Firefox; Win10 đang mở Edge.

```bash
RECORD=0 bash scripts/demo-3vm.sh
```

`RECORD=1` để quay lại toàn màn hình ra `video/public/demo-raw.mkv`. Trong khi chạy, không dùng chuột/bàn phím.

## 5. Tài liệu đối chiếu

| Nội dung | File |
|---|---|
| Tổng quan, cấu trúc, cách chạy lại | `README.md` |
| Kết quả MVP + chặn thủ công | `report/ket-qua-mvp-lan-01.md` |
| Đánh giá M4 + rule quét chậm v3 | `report/ket-qua-m4-danh-gia.md` |
| Analyzer + chặn tự động M5 | `report/ket-qua-m5-phan-ung-tu-dong.md` |
| Số liệu | `tests/results-m4.csv`, `tests/replay-*.csv`, `tests/m5-incidents.jsonl` |
| Bằng chứng gốc | `evidence/run-*/` (PCAP, EVE, access log, metadata) |
| Video | `video/out/BTL-ATTT-demo.mp4` |
