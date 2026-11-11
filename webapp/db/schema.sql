-- Lab Shop — lược đồ CSDL (SQLite). Dùng cho dev local và deploy lên B.
-- seed.py đọc file này để tạo lab.db. Dữ liệu CHỈ dùng trong lab.

PRAGMA journal_mode = WAL;

DROP TABLE IF EXISTS order_items;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS cart_items;
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS products;

CREATE TABLE products (
    id      INTEGER PRIMARY KEY,
    name    TEXT    NOT NULL,
    price   INTEGER NOT NULL,          -- VND
    old     INTEGER,                    -- giá gạch, có thể NULL
    icon    TEXT,
    color   TEXT,
    rate    REAL,
    n       INTEGER,                    -- số đánh giá
    tag     TEXT
);

CREATE TABLE users (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    email    TEXT UNIQUE NOT NULL,
    name     TEXT NOT NULL,
    pw_hash  TEXT NOT NULL,             -- PBKDF2-HMAC-SHA256, hex
    role     TEXT NOT NULL DEFAULT 'customer'
);

-- Giỏ hàng lưu trên máy chủ theo phiên (sid từ cookie)
CREATE TABLE cart_items (
    sid     TEXT    NOT NULL,
    pid     INTEGER NOT NULL REFERENCES products(id),
    qty     INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (sid, pid)
);

CREATE TABLE orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    order_code TEXT UNIQUE NOT NULL,
    email      TEXT NOT NULL,
    total      INTEGER NOT NULL,
    count      INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE order_items (
    order_id INTEGER NOT NULL REFERENCES orders(id),
    pid      INTEGER NOT NULL REFERENCES products(id),
    qty      INTEGER NOT NULL,
    price    INTEGER NOT NULL
);

-- ===== Dữ liệu mẫu =====
INSERT INTO products (id,name,price,old,icon,color,rate,n,tag) VALUES
 (1,'Tai nghe không dây ANC',590000,790000,'🎧','#e0e7ff',4.8,312,'-25%'),
 (2,'Bàn phím cơ RGB',1250000,NULL,'⌨️','#ede9fe',4.7,158,'Mới'),
 (3,'Chuột gaming 26K DPI',450000,560000,'🖱️','#dcfce7',4.6,421,'-20%'),
 (4,'Màn hình 24" 165Hz',2890000,NULL,'🖥️','#fef3c7',4.9,97,NULL),
 (5,'Loa bluetooth chống nước',720000,NULL,'🔊','#ffe4e6',4.5,203,NULL),
 (6,'Webcam Full HD',650000,750000,'📷','#e0f2fe',4.4,88,'-13%'),
 (7,'Ổ cứng SSD NVMe 1TB',1690000,NULL,'💾','#f3e8ff',4.9,540,'Mới'),
 (8,'Sạc dự phòng 20.000mAh',390000,NULL,'🔋','#ecfccb',4.6,276,NULL);

-- Tài khoản khách hàng THỬ NGHIỆM của lab (không phải tài khoản thật).
-- pw_hash sẽ do seed.py điền (PBKDF2 của "Khach@2026"), nên để trống ở đây.
-- Tài khoản admin/LabShop@2026! là HONEYTOKEN — KHÔNG đưa vào bảng users.
