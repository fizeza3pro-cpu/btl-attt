# Thành viên bắt đầu — có mã nguồn & triển khai được

Mỗi thành viên cần **2 thứ**:
- **(A) Mã nguồn** — clone từ GitHub (dễ).
- **(B) Một lab để triển khai lên** — VM B (và Kali) chạy trên máy mình.

Vì B chỉ với tới trong mạng host-only cục bộ, **không ai SSH vào B của người khác qua internet được**. Nên mỗi người chạy **một bản VM của riêng mình** (import từ OVA chung), rồi `deploy.sh` đẩy code lên B của chính mình.

---

## Phần 1 — Việc CHỦ REPO làm một lần (máy đang có lab)

### 1.1. Mời 3 thành viên vào repo
GitHub → repo `btl-attt` → **Settings → Collaborators → Add people** → nhập username/email từng người.

### 1.2. Export VM thành OVA (ảnh chụp lab để chia)
Làm khi **máy ảo đã TẮT**. VirtualBox → **File → Export Appliance** → chọn **B** và **Kali** → xuất ra `lab-B.ova`, `lab-Kali.ova`.
> Export ở trạng thái HIỆN TẠI là tốt nhất: B đã có sẵn webapp, venv, `python3.14-venv`, mọi dịch vụ chạy → thành viên import là dùng được ngay.

Up 2 file OVA lên Google Drive/OneDrive của nhóm, chia link.

### 1.3. Chia khóa SSH của lab (KHÔNG đưa lên Git)
B trong OVA đã tin khóa `id_ed25519_lab`. Gửi **file khóa riêng** `~/.ssh/id_ed25519_lab` cho thành viên qua kênh riêng (chat nhóm, Drive riêng) — **tuyệt đối không commit vào repo**. Đây là khóa chỉ dùng trong lab, lộ cũng không sao ngoài lab.
> Muốn chặt chẽ hơn: mỗi người tự tạo khóa, gửi phần `.pub` cho chủ repo thêm vào `~/.ssh/authorized_keys` trên B **trước khi export**.

---

## Phần 2 — Việc MỖI THÀNH VIÊN làm

### 2.1. Cài công cụ (máy thật, Windows)
- **Git for Windows** (có Git Bash) — https://git-scm.com
- **VirtualBox** (cùng dòng 7.x) — https://www.virtualbox.org
- **Python 3** (để dev web local) — https://python.org, tích "Add to PATH" (hoặc dùng `py`)

### 2.2. Lấy mã nguồn
```bash
git clone https://github.com/fizeza3pro-cpu/btl-attt.git
cd btl-attt
```

### 2.3. Lấy môi trường (import VM)
1. Tải `lab-B.ova`, `lab-Kali.ova` từ Drive nhóm.
2. VirtualBox → **File → Import Appliance** → chọn từng file.
3. Đảm bảo có mạng **Host-only** `192.168.56.0/24` (VirtualBox thường tự tạo `vboxnet0` = 192.168.56.1). File → Tools → Network Manager để kiểm tra.
4. **Bật B trước**, rồi Kali.

### 2.4. Đặt khóa + alias SSH
Chép khóa lab vào `~/.ssh/id_ed25519_lab` (chmod 600), rồi thêm vào `~/.ssh/config`:
```
Host labB
    HostName 192.168.56.101
    User laamf-tung
    IdentityFile ~/.ssh/id_ed25519_lab
    IdentitiesOnly yes
Host labA
    HostName 192.168.56.102
    User kali
    IdentityFile ~/.ssh/id_ed25519_lab
    IdentitiesOnly yes
```
Kiểm tra: `ssh labB 'hostname'` phải ra tên máy B.

### 2.5. Triển khai phần của mình
Sửa code trong repo → đẩy lên B của mình:
```bash
bash scripts/deploy.sh sensor      # P1
bash scripts/deploy.sh response    # P2
bash scripts/deploy.sh soc         # P3 (dashboard + honeypot)
bash scripts/deploy.sh web         # P3 (Lab Shop)
bash scripts/deploy.sh all --dry-run   # xem trước toàn bộ
```

### 2.6. Dev web KHÔNG cần VM
Riêng web (P3) có thể build/test ngay trên máy thật, không cần B:
```bash
cd webapp
.\run-local.ps1          # http://localhost:8081  (an toàn)
.\run-local.ps1 -Vuln    # bật SQLi để thử tấn công
```

---

## Phần 3 — Vòng làm việc hằng ngày (mọi người)

```bash
git pull origin main                 # lấy code mới của nhóm
git checkout -b p1-sensor            # nhánh của mình (p2/p3/p4)
# ... sửa file phần mình ...
bash scripts/deploy.sh <mảng>        # test trên B của mình
git add -A && git commit -m "P1: ..."
git push origin p1-sensor            # mở Pull Request -> main
```

Chi tiết phân vai, ranh giới file, đổi mạng, trình tự demo: [NHOM-quy-trinh.md](NHOM-quy-trinh.md).

---

## Checklist nhanh cho thành viên mới

- [ ] Được mời vào repo GitHub
- [ ] Cài Git + VirtualBox + Python
- [ ] `git clone` xong
- [ ] Import `lab-B.ova` + `lab-Kali.ova`, bật được B & Kali
- [ ] Có khóa `id_ed25519_lab`, `ssh labB 'hostname'` chạy
- [ ] `bash scripts/deploy.sh <mảng>` chạy thành công
- [ ] Mở `http://192.168.56.101` thấy Lab Shop

> **Không bao giờ** commit khóa SSH, `lab.db`, hay file OVA vào repo (đã chặn trong `.gitignore`).
