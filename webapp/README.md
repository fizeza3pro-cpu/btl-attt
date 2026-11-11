# Lab Shop — web app (FastAPI + SQLite)

Chỗ để **build / sửa / test** web ngay trên máy thật, rồi mới deploy lên B.
Thay cho bản cũ `scripts/lab-shop-api.py` (dữ liệu trong RAM, không DB).

## Chạy local (máy thật)

```powershell
cd webapp
.\run-local.ps1           # AN TOÀN, http://localhost:8081
.\run-local.ps1 -Vuln     # bật lỗ hổng SQLi để P4 thử tấn công
.\run-local.ps1 -Reseed   # tạo lại CSDL
```
Git Bash / Linux: `bash run-local.sh` (biến `LAB_VULN=1`, `RESEED=1`).

Lần đầu tự tạo `.venv`, cài `fastapi`+`uvicorn`, tạo `lab.db`. Mở:
- Trang shop: http://localhost:8081
- **Swagger (thử API trực tiếp):** http://localhost:8081/api/docs

## Vòng làm việc

```text
sửa webapp/*  →  .\run-local.ps1  →  test trên trình duyệt + /api/docs
             →  ổn  →  git commit/push  →  deploy lên B
```

## Cấu trúc

| File | Vai trò |
|---|---|
| `app.py` | Server FastAPI, các endpoint `/api/*`, phục vụ giao diện `../config/www` |
| `db/schema.sql` | Bảng products / users / orders / cart + dữ liệu mẫu |
| `seed.py` | Tạo `lab.db` từ schema, băm mật khẩu tài khoản thử |
| `requirements.txt` | fastapi, uvicorn |
| `run-local.ps1` / `.sh` | Dựng venv + chạy ở localhost |
| `lab.db` | CSDL SQLite (không commit — xem `.gitignore`) |

## Endpoint

| | Đường dẫn | Ghi chú |
|---|---|---|
| GET | `/api/health` | trạng thái, có `vuln_mode` |
| GET | `/api/products` | danh sách sản phẩm (từ DB) |
| GET | `/api/search?q=` | tìm theo tên — **bề mặt SQLi** khi `LAB_VULN=1` |
| GET/POST | `/api/cart` | giỏ hàng theo phiên (lưu DB) |
| GET | `/api/me` | tài khoản đang đăng nhập |
| POST | `/api/login` | đăng nhập — **bề mặt SQLi** khi `LAB_VULN=1`; khóa IP 5 phút sau 5 lần sai |
| POST | `/api/logout` / `/api/order` | đăng xuất / đặt hàng (bắt buộc đăng nhập) |

Tài khoản thử: `khach@labshop.vn` / `Khach@2026`.
`admin / LabShop@2026!` là **honeytoken**, không có trong DB.

## Công tắc lỗ hổng (cho P4)

`LAB_VULN=0` (mặc định): truy vấn tham số hóa, **an toàn**.
`LAB_VULN=1`: `/api/login` và `/api/search` **nối chuỗi SQL có chủ đích** → P4 khai thác được:
- Bỏ qua đăng nhập: email = `' OR 1=1 --`
- Rút dữ liệu: `q` dùng `UNION SELECT ...`

Mỗi lần đăng nhập đều ghi `auth.jsonl` (analyzer/dashboard của P2/P3 đọc để phát hiện dò mật khẩu) → tấn công của P4 **hiện lên hệ thống phòng thủ**.

> **Chỉ dùng trong lab cô lập.** Bật lỗ hổng chỉ khi demo.

## Deploy lên B

> Cần bổ sung sau: tạo venv trên B tại `/usr/local/lib/lab/webapp/venv`, sửa
> `lab-shop-api.service` chạy `uvicorn`, và `deploy.sh web` lo cài venv.
> Hiện tại mục này dùng để **dev local**; khi chốt sẽ nối vào quy trình deploy.
