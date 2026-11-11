# Quy trình làm nhóm — BTL ATTT (4 người)

Tài liệu này trả lời: **ai làm gì**, **chia/sửa mã nguồn thế nào**, **dựng môi trường ra sao**, và **ngày demo gom lab thế nào**.

---

## 1. Phân vai (3 phòng thủ + 1 tấn công)

Toàn bộ stack phòng thủ chạy trên **một máy B (Ubuntu)**. Kẻ tấn công ở **Kali**. Vì tất cả nằm chung một mạng, **một đòn tấn công tự chảy qua cả 3 lớp** → mỗi người đều có cái để trình bày.

| Người | Mảng | File sở hữu (ranh giới Git) | Dịch vụ | 2 kịch bản trình bày |
|---|---|---|---|---|
| **P1** | Cảm biến / Phát hiện | `config/suricata.yaml`, `config/local.rules`, `scripts/lab-rulegen.py`, `scripts/lab-rule` | suricata, lab-rulegen, lab-pcap-ring | (1) Phát hiện quét cổng chậm né ngưỡng; (2) Tự sinh luật từ honeytoken rồi người vận hành duyệt |
| **P2** | Phản ứng / Firewall | `scripts/analyzer.py`, `scripts/lab-block`, `config/lab-response.nft` | lab-analyzer, lab-response | (1) Chặn có thời hạn không hại người dùng hợp lệ; (2) Đánh lừa (deceive) thay vì chặn thẳng |
| **P3** | SOC / Ứng dụng web | `scripts/lab-soc.py`, `scripts/lab-honeypot.py`, `scripts/lab-shop-api.py`, `config/www/`, `config/nginx-*.conf` | lab-soc, lab-honeypot, lab-shop-api, nginx | (1) Honeypot/honeytoken bắt kẻ dò → hiện trên dashboard; (2) Tấn công web app (đăng nhập / endpoint thật) lên dashboard |
| **P4** | Tấn công | `scripts/kali-attacker.sh`, các script tấn công trên Kali | (chạy trên Kali) | (1) Quét + né IDS (chậm, phân mảnh, đổi User-Agent); (2) Tấn công web + thử bypass phần dò quét |

> **Ranh giới file = merge Git sạch.** Mỗi người chủ yếu sửa file trong cột "File sở hữu", nên ít khi đụng nhau. File dùng chung (ví dụ `README.md`) thì báo nhau trước khi sửa.

---

## 2. Chia & sửa mã nguồn — Git

### 2.1. Một lần (người tạo repo)
```bash
# Tạo repo private trên GitHub (hoặc GitLab), rồi:
git remote add origin git@github.com:<nhom>/btl-attt.git
git push -u origin main
```
Mời 3 người còn lại làm **collaborator** trên repo.

### 2.2. Mỗi người (sau khi được mời)
```bash
git clone git@github.com:<nhom>/btl-attt.git
cd btl-attt
git checkout -b p1-sensor        # p2-response / p3-soc / p4-attacker
```

### 2.3. Vòng làm việc hằng ngày
```bash
git pull origin main             # lấy cái mới nhất
# ... sửa file phần của mình ...
git add -A && git commit -m "P1: thêm rule phát hiện X"
git push origin p1-sensor
# Mở Pull Request p1-sensor -> main, người khác xem rồi merge
```

Quy ước: **không push thẳng vào `main`**, luôn qua PR để cả nhóm thấy thay đổi.

---

## 3. Đẩy mã nguồn lên máy B — `deploy.sh`

Repo chỉ chứa **file nguồn**. Trạng thái đang chạy nằm trên VM B. Sau khi `git pull`, đẩy phần của mình lên B rồi restart dịch vụ:

```bash
bash scripts/deploy.sh sensor      # P1
bash scripts/deploy.sh response    # P2
bash scripts/deploy.sh soc         # P3 (dashboard + honeypot)
bash scripts/deploy.sh web         # P3 (Lab Shop + nginx)
bash scripts/deploy.sh all         # đẩy hết
bash scripts/deploy.sh sensor --dry-run   # chỉ xem sẽ làm gì
```

- Tự **kiểm tra cú pháp** (`suricata -T`, `nginx -t`, `nft -c`) trước khi reload; sai thì **dừng**, không đụng dịch vụ đang chạy.
- Máy đích mặc định `labB` (alias SSH). Đổi: `--host=labB` hoặc đặt `LAB_HOST`.
- Đường dẫn nginx/web khác máy thì ghi đè trong `deploy.local.conf` (file này không lên Git).

> **Lần đầu chạy:** kiểm tra lại đường dẫn nginx trong `deploy.sh` (`NGINX_LAB_DEST`, `NGINX_HP_DEST`) có khớp máy B không. Xem bằng: `ssh labB 'ls /etc/nginx/sites-available/ /etc/nginx/conf.d/'`.

---

## 4. Môi trường: 2 VM + máy thật làm người dùng

```text
Máy thật Windows 11  = người dùng hợp lệ (10.77.0.30)  ──┐
Kali VM   (10.77.0.10) = kẻ tấn công  ───────────────────┼─ Host-only lab 10.77.0.0/24  ← Suricata nghe
Ubuntu-B  (10.77.0.20) = hệ thống phòng thủ  ────────────┘
                         + Host-only quản trị 192.168.56.0/24  (SSH)
```

### Vì sao Host-only chứ không phải Internal
Mạng **Internal Network** máy thật không vào được. Muốn máy thật đóng vai người dùng mà **Suricata thấy traffic**, mạng lab phải là **Host-only** (máy thật cũng nằm trên đó).

### Các bước đổi (một lần, trên VirtualBox)
1. Tạo card **Host-only** cho mạng lab (vd `vboxnet2`, dải `10.77.0.0/24`), **tắt DHCP của VirtualBox** trên card này.
2. Gán card đó cho **enp0s8 của B** và card tấn công của **Kali**.
3. Đặt IP card host-only trên **máy thật = `10.77.0.30`** → giữ nguyên toàn bộ config/rule/firewall (C cũ = .30).
4. Giữ card host-only quản trị `192.168.56.x` cho `ssh labB`, `ssh labA`.
5. `dnsmasq` trên B vẫn cấp IP cho Kali theo MAC như cũ.

### Máy yếu
Chỉ cần chạy **B + Kali** (~5–6 GB RAM). Traffic người dùng lành chạy bằng script trên máy thật:
`scripts/c-traffic.ps1`, `scripts/benign-tour.ps1` (PowerShell).

### Mỗi người có một bản lab
- **Cách nhẹ (khuyên dùng):** export B và Kali thành **OVA** một lần, up lên Drive, mỗi người import. Sau đó chỉ cần `git pull` + `deploy.sh` để cập nhật phần mình.
- Dev/test một mình: tự chạy script tấn công chung trong repo để thử phần của mình, không cần người thật.

---

## 5. Ngày demo — gom về một lab chạy chung

Để **P4 tấn công thật, P1/P2/P3 phản ứng thật**, tất cả phải ở **một lab đang chạy, cùng mạng**. Cách chắc nhất: chạy **cả Kali + B trên một máy** (máy thuyết trình), máy thật đó là người dùng hợp lệ.

Trình tự demo gợi ý:
1. `ssh labB '~/lab/reset-lab.sh recommend'` — đưa B về trạng thái sạch.
2. **P1**: Kali quét chậm → chỉ cảm biến ghi nhận (chưa chặn). Mở dashboard xem sự kiện.
3. **P2**: đổi `MODE=apply` → Kali tái tấn công → firewall chặn/đánh lừa có thời hạn; **máy thật mở shop vẫn chạy bình thường** (chứng minh không hại người dùng hợp lệ).
4. **P3**: Kali chạm honeytoken/trang bẫy → dashboard hiện incident, ATT&CK; rulegen đề xuất rule → người vận hành **duyệt** trên dashboard.
5. **P4**: trình bày các kỹ thuật né/bypass đã thử — cái nào lọt, cái nào bị bắt, vì sao.

---

## 6. Nhắc nhanh

- Không `git push` thẳng `main`; luôn qua PR.
- Không `nft flush ruleset`; gỡ riêng: `sudo nft delete table inet lab_response`.
- `deploy.sh ... --dry-run` trước khi đẩy nếu chưa chắc.
- Chụp snapshot VirtualBox **khi máy đã tắt**.
