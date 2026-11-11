# Giám sát máy chủ web trong mạng lab bằng Suricata

Bài tập lớn An toàn thông tin: phát hiện hành vi xâm nhập bằng Suricata (IDS) và phản ứng có kiểm soát bằng nftables, đánh giá bằng số liệu trên mạng lab cô lập.

## Trạng thái

| Mốc | Nội dung | Trạng thái |
|---|---|---|
| M1 | Lab 3 máy, mạng cô lập, web, SSH | ✅ |
| M2 | Suricata + rule phát hiện | ✅ (6 rule, gồm rule quét chậm v3) |
| M3 | Phản ứng nftables có thời hạn, không ảnh hưởng người dùng hợp lệ | ✅ chặn thủ công |
| M4 | Đánh giá: lặp ca, baseline từ C, ca biên, phát lại PCAP | ✅ |
| M5 | Analyzer liên kết sự kiện + chặn tự động có giới hạn | ✅ ([report/ket-qua-m5-phan-ung-tu-dong.md](report/ket-qua-m5-phan-ung-tu-dong.md)) |
| M6 | **Mini-SOC**: honeypot/honeytoken + đánh lừa, bảo vệ ứng dụng web, analyzer v2 đa nguồn + ATT&CK, dashboard duyệt + báo cáo, vá IPv6 | ✅ ([report/ket-qua-nang-cap-soc.md](report/ket-qua-nang-cap-soc.md)) |
| — | ML (Isolation Forest) | để sau, bổ sung nếu có yêu cầu |

Kết quả chính (chính sách phản ứng, rule v3): **Recall 0,958 — FPR 0 — Precision 1,0 — F1 0,979** trên 56 lần chạy có nhãn. Chi tiết: [report/ket-qua-m4-danh-gia.md](report/ket-qua-m4-danh-gia.md).

## Mô hình lab

```text
Máy thật Windows 11 (VirtualBox 7.2.10, Wireshark, Git Bash)
│
├── Host-only 192.168.56.0/24 ── chỉ để quản trị (SSH, lấy bằng chứng)
│
└── Internal Network "ids-lab" 10.77.0.0/24 ── cô lập, không gateway
     ├── A  Kali Rolling      10.77.0.10   (mgmt .56.102)  máy kiểm thử: nmap, curl
     ├── B  Ubuntu 26.04 LTS  10.77.0.20   (mgmt .56.101)  Nginx, Suricata 8.0.3, nftables, dnsmasq (DHCP lab)
     └── C  Windows 10        10.77.0.30   (mgmt .56.103)  người dùng hợp lệ: Edge, curl.exe
```

- Suricata chạy chế độ IDS (AF_PACKET) trên card lab `enp0s8` của B, `HOME_NET = 10.77.0.20/32`.
- B cấp IP cố định cho A và C qua DHCP theo MAC, không cấp gateway/DNS → **luôn bật B trước**.
- Truy cập từ máy thật: `ssh labA`, `ssh labB`, `ssh labC` (khóa `~/.ssh/id_ed25519_lab`).

## Cấu trúc thư mục

```text
config/     Cấu hình đang chạy trên B
  suricata.yaml, local.rules        cảm biến và rule
  nginx-lab.conf, www/              web lab, đường dẫn mồi /lab-admin, robots.txt, gallery
  lab-response.nft, .service        firewall phản ứng (bảng riêng inet lab_response)
  dnsmasq-ids-lab.conf              DHCP cho mạng lab
  lab-nic-offload.service           tắt offload card lab
scripts/    Tự động hóa (chạy từ Git Bash trên máy thật, trừ khi ghi khác)
  run-mvp-tests.sh, run-m4.sh       bộ ca thử (điều khiển A/C, B ghi bằng chứng)
  run-block-test.sh                 ca chặn thủ công + kiểm tra C
  case-start.sh, case-stop.sh       [B] bắt đầu/kết thúc một ca: PCAP, cắt EVE/access log, tóm tắt
  replay.sh                         [B] phát lại PCAP offline với bộ rule bất kỳ (--runmode single)
  aggregate.sh, metrics.sh          [B] tổng hợp CSV, tính TP/FP/FN/TN, recall, FPR, F1
  latency.sh, check-eve.sh, check-web.sh
  c-traffic.ps1                     [C] sinh lưu lượng hợp lệ từ win10
  win10-enable-ssh.ps1              [C] bật OpenSSH Server (chỉ cho máy thật)
evidence/   run-<ca>-<lần>/: metadata.txt, traffic.pcap, eve.json, access.log, summary.txt
tests/      results-m4.csv, replay-*.csv, live-v3.csv
report/     ket-qua-mvp-lan-01.md, ket-qua-m4-danh-gia.md
logs/       log của các lần chạy bộ ca thử
```

## Mini-SOC (từ 10/11/2026)

| Thành phần | Địa chỉ / file | Ghi chú |
|---|---|---|
| **Dashboard SOC v2** | `http://192.168.56.101:9000` (máy thật hoặc Firefox trên B) | dịch vụ `lab-soc`, mã `scripts/lab-soc.py`; **thiết bị phát hiện động** (chỉ hiện IP có hoạt động trong 30 phút hoặc đang bị phản ứng), KPI, biểu đồ 30 phút, luồng sự kiện có bộ lọc, ngăn chi tiết từng IP, thông báo sự cố mới, sức khỏe dịch vụ |
| Lab Shop API | `/api/*` → 127.0.0.1:8081 | `scripts/lab-shop-api.py`, log xác thực `/var/log/lab-shop/auth.jsonl` |
| Honeypot | 127.0.0.1:8082, cổng bẫy 23/2222/3306, bản sao đánh lừa :8083 | `scripts/lab-honeypot.py`, `config/nginx-honeypot.conf`, log `/var/log/lab-honeypot/events.jsonl` |
| Analyzer v2 | đọc eve + honeypot + auth | `/etc/default/lab-analyzer`: `MODE=recommend|apply`, `RESPONSE=deceive|block` |
| Firewall | `lab-block add/del l1|l2|dec <IP>` | l1 chặn web 60 s · dec đánh lừa 10 phút · l2 chặn toàn bộ TCP 10 phút. Phạm vi phản ứng: A (10.77.0.10) **và C (10.77.0.30)**; chỉ máy chủ B không bao giờ bị chặn. C không còn đặc cách (11/11/2026): người vô tội được bảo vệ khỏi bị vu oan nhờ yêu cầu **bằng chứng không giả mạo được**, không nhờ danh sách khách hàng |
| **Tự sinh luật** | dịch vụ `lab-rulegen` (+ `lab-pcap-ring`) | `scripts/lab-rulegen.py`: học từ request của kẻ tấn công đã chạm honeytoken → rule ứng viên → 5 cửa kiểm chứng (cú pháp, bắt được khi phát lại PCAP vòng, 0 alert trên kho hợp lệ, không trùng trang thật, không trùng) → **người vận hành duyệt** trên dashboard → `scripts/lab-rule` (root) nạp nóng vào `/var/lib/lab-rule/auto.rules`. SID 5000000+ (đường dẫn), 5500000+ (User-Agent). Reset: `~/lab/rulegen-reset.sh`. Đưa cả B về sạch trước mỗi kịch bản: `~/lab/reset-lab.sh [recommend|danh-lua|chan] [--xoa-rule]` |

Tài liệu đầy đủ (cài đặt, mã nguồn, 9 kịch bản demo làm trực tiếp trên 3 máy ảo): **`BTL-ATTT-Huong-dan-chi-tiet.docx`**.

Tài khoản **thử nghiệm** của Lab Shop: `khach@labshop.vn` / `Khach@2026` (chỉ dùng trong lab). Tài khoản `admin / LabShop@2026!` trong comment HTML là **honeytoken có chủ đích**, không phải tài khoản thật.

Kiểm thử: `bash scripts/run-ipv6-test.sh before|after <n>`, `bash scripts/run-deception-test.sh <n>`, `bash scripts/run-webattack-tests.sh <n>`, `bash scripts/run-soc-scenario.sh <n>` (dọn dẹp: `bash scripts/run-soc-scenario.sh cleanup`), `ssh labB '~/lab/test-analyzer.sh'` (37 ca, gồm 4 ca rule tự sinh và 1 ca đợt tấn công mới; kiểm thử bản analyzer **đang chạy** `/usr/local/lib/lab/analyzer.py`).

## Rule phát hiện (`config/local.rules`)

| SID | Vai trò | Ý nghĩa |
|---|---|---|
| 1000001 | yếu | Tốc độ mở kết nối TCP cao (≥ 10 SYN / 10 s / nguồn) — dễ báo nhầm, chỉ ghi nhận |
| 1000003 | củng cố | B trả ≥ 10 RST/ACK / 10 s cho một máy → thử nhiều cổng đóng |
| 1000005 | củng cố | B trả ≥ 10 RST/ACK / 60 s → thăm dò cổng chậm |
| 1000002 | mạnh | Truy cập đường dẫn mồi `/lab-admin` (không giả mạo IP được) |
| 1000007 | nghiêm trọng | Đường dẫn mồi trả mã khác 403 |
| 9000001 | kiểm tra | Kiểm tra cảm biến (`/suricata-sanity-check`) |

Chính sách: chỉ tín hiệu củng cố/mạnh mới tạo incident; chỉ chặn khi có tín hiệu không giả mạo được, nguồn thuộc danh sách được phép chặn, và không thuộc danh sách bảo vệ (B, C).

## Phản ứng tự động (M5)

- `lab-analyzer.service` chạy `analyzer.py` bằng user `labresp` (không root), đọc `eve.json`, chấm điểm, ghi `/var/lib/lab-analyzer/incidents.jsonl`.
- Quyền sudo duy nhất của `labresp`: `/usr/local/sbin/lab-block` (chỉ thêm/gỡ IP được phép trong set `blocked_l1`).
- Mặc định `MODE=recommend`. Bật chặn tự động:

```bash
ssh labB 'echo MODE=apply | sudo tee /etc/default/lab-analyzer && sudo systemctl restart lab-analyzer'
```

- Xem incident: `ssh labB 'sudo tail -f /var/lib/lab-analyzer/incidents.jsonl'`
- Kiểm thử: `scripts/test-analyzer.sh` (offline, trên B), `scripts/run-m5-tests.sh` (live, từ máy thật).

## Chạy lại

```bash
# Từ thư mục dự án, trong Git Bash trên máy thật (3 VM đang chạy, B bật trước)
bash scripts/run-mvp-tests.sh 01      # 6 ca cơ bản
bash scripts/run-block-test.sh 03     # chặn A 60 s, kiểm tra C
bash scripts/run-m4.sh all            # toàn bộ M4 (~40 phút)
ssh labB '~/lab/aggregate.sh > ~/lab/results.csv && ~/lab/metrics.sh ~/lab/results.csv'
```

Phát lại PCAP với bộ rule mới (không cần chạy lại lab):

```bash
ssh labB 'sudo ~/lab/replay.sh /tmp/rule-moi.rules ten-lan-phat'
```

## Video demo

- File: `video/out/BTL-ATTT-demo.mp4` (3:24, 1920x1080, phụ đề tiếng Việt, nhạc nền tự tổng hợp — không bản quyền).
- Dựng bằng Remotion (`video/src/`): cảnh mở đầu, kiến trúc, chống giả mạo, kết quả, giới hạn là hoạt họa từ số liệu thật; cảnh demo là **quay màn hình thật** 3 máy (`scripts/demo-3vm.sh`, `RECORD=1`).
- Xuất lại: `cd video && npx remotion render src/index.ts BtlDemo out/BTL-ATTT-demo.mp4`
- Web B: **Lab Shop** (`config/www/`), trang bẫy `/admin` (lộ qua `robots.txt` và comment HTML, không có link trên giao diện).
- Từ 10/11/2026 Lab Shop có backend `scripts/lab-shop-api.py` (dịch vụ `lab-shop-api`, 127.0.0.1:8081, Nginx proxy `/api/`), giỏ hàng lưu trên máy chủ, trang có đèn trạng thái máy chủ, Nginx gửi `Cache-Control: no-cache`. Lý do: trước đó web tĩnh + cache trình duyệt làm máy bị chặn **trông như vẫn dùng được** dù firewall đã drop mọi gói (đã kiểm chứng: 0 request của A lọt tới Nginx khi bị chặn).
- Video ghi ngày 08/11 là phiên bản web tĩnh (trước khi có API).

## Snapshot VirtualBox

| Snapshot | Máy | Nội dung |
|---|---|---|
| S0-truoc-lab | cả 3 | trước khi làm bài |
| S1-mang-ok | cả 3 | mạng lab, Nginx, DHCP, SSH chạy |
| S2-sensor-ok | B | Suricata chạy, rule kiểm tra |
| S3-rule-mvp-on-dinh | B | chế độ dòng lệnh, RTC UTC, rule MVP |

Chỉ chụp snapshot khi máy **đã tắt**: chụp "live" từng làm B treo (VirtualBox chạy trên nền Hyper-V).

## Giao diện đồ họa của B

- Từ 10/11/2026 B khởi động vào giao diện GNOME (`graphical.target`). Đã theo dõi 10 phút kèm 6 ca kiểm thử: 0 lockup, 0 crash, Suricata 0 gói bị mất, gnome-shell trung bình 6,4% CPU (log: `~/lab/stability-gui.log` trên B).
- Trước đó B chạy chế độ chữ vì bị soft lockup khi đồng hồ RTC còn lệch 7 tiếng; sau khi sửa RTC (UTC) thì giao diện chạy ổn.
- Guest Additions 7.2.10 đã cài phần người dùng; **module kernel mới không nạp được vì máy ảo bật Secure Boot**, B vẫn dùng driver VirtualBox có sẵn trong kernel. Dịch vụ `vboxadd` (biên dịch module) đã tắt.
- Quay về chế độ chữ: `sudo systemctl set-default multi-user.target && sudo reboot`. Snapshot trước khi bật lại GUI: `S4-truoc-bat-GUI`.

## Lưu ý vận hành

- Không dùng `nft flush ruleset`; gỡ riêng bảng: `sudo nft delete table inet lab_response`.
- Suricata thấy cả gói đã bị firewall drop → xác minh chặn bằng counter, curl, access log.
- `eve.json` trên B có vài dòng hỏng từ lần tắt cứng; script đọc EVE dùng `jq -R 'fromjson?'`.
- Phát lại PCAP phải dùng `--runmode single`; chế độ nhiều luồng làm lệch cửa sổ threshold.
