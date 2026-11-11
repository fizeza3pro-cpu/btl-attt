import { Cue } from './components';

/** Cac doan cat tu public/demo.mp4. from/to: giay trong file goc; rate: toc do phat (4 = tua x4). */
export type Segment = { from: number; to: number; rate: number; label?: string };

// Ban quay 08/11/2026 23:24 (scripts/demo-3vm.sh, RECORD=1). Thoi gian trong file ~= moc (demo-marks.txt) + 2 s.
export const SEGMENTS: Segment[] = [
  { from: 4, to: 21.5, rate: 1 },            // C mua hang binh thuong
  { from: 21.5, to: 58, rate: 1 },           // A quet cong -> robots.txt -> /admin -> bi chan
  { from: 58, to: 72, rate: 1 },             // kiem tra: A that bai, C dat hang thanh cong
  { from: 72, to: 107, rate: 4 },            // cho het han chan (tua nhanh)
  { from: 107, to: 117, rate: 1 },           // A phuc hoi
];

// Thoi gian tinh theo canh demo (sau khi cat, tua)
export const DEMO_CUES: Cue[] = [
  { from: 0.3, to: 8.5, text: 'Trái: máy A (Kali) của kẻ tấn công. Phải: máy C (Windows) của khách hàng. Dưới: màn hình giám sát trên máy chủ B.' },
  { from: 8.5, to: 17.5, text: 'Khách hàng C mua sắm bình thường: thêm tai nghe và chuột vào giỏ. Hệ thống không có cảnh báo nào.' },
  { from: 17.5, to: 25, text: 'Kẻ tấn công A dùng nmap quét 100 cổng của máy chủ.' },
  { from: 25, to: 35.8, text: 'Suricata phát hiện ngay. Analyzer chấm 120 điểm nhưng KHÔNG chặn: tín hiệu quét cổng có thể bị giả mạo IP.' },
  { from: 35.8, to: 41.4, text: 'A đọc robots.txt và tìm ra đường dẫn quản trị bị giấu: /admin.' },
  { from: 41.4, to: 47.5, text: 'A mở /admin bằng Firefox: máy chủ trả 403, Suricata bắt được truy cập bẫy qua một kết nối TCP thật.' },
  { from: 47.5, to: 54, text: 'Đủ 190 điểm và có tín hiệu thật → analyzer tự động chặn A trong 60 giây.' },
  { from: 54, to: 61, text: 'A không còn vào được web: kết nối thất bại (HTTP 000).' },
  { from: 61, to: 68, text: 'Cùng lúc đó, khách hàng C vẫn đặt hàng thành công — người dùng hợp lệ không bị ảnh hưởng.' },
  { from: 68, to: 76.7, text: 'Tua nhanh ×4: tường lửa tự gỡ chặn sau 60 giây, không cần người can thiệp.' },
  { from: 76.7, to: 86.6, text: 'Hết hạn chặn, A truy cập lại được (HTTP 200). Mọi bước trong đoạn này đều chạy thật trên 3 máy ảo.' },
];

// Nhan buoc hien phia tren doan demo (thoi gian theo canh demo)
export const DEMO_STEPS: { from: number; to: number; n: number; title: string; color: string }[] = [
  { from: 0, to: 17.5, n: 1, title: 'Khách hàng C mua sắm bình thường', color: '#34d399' },
  { from: 17.5, to: 35.8, n: 2, title: 'A quét cổng → Suricata cảnh báo, analyzer CHƯA chặn', color: '#fbbf24' },
  { from: 35.8, to: 54, n: 3, title: 'A dò ra trang /admin và truy cập → bị CHẶN tự động', color: '#f87171' },
  { from: 54, to: 68, n: 4, title: 'Kiểm tra: A mất kết nối, C vẫn đặt hàng được', color: '#38bdf8' },
  { from: 68, to: 87, n: 5, title: 'Hết 60 giây → tự gỡ chặn, A truy cập lại', color: '#a78bfa' },
];

export const demoSeconds = () =>
  SEGMENTS.length === 0 ? 8 : SEGMENTS.reduce((a, x) => a + (x.to - x.from) / x.rate, 0);
