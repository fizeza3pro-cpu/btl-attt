# Kịch bản video BTL ATTT — bản nháp 2

> Bản lời đọc chính thức (đã bỏ "nhóm em"): `src/reel/script.json`. File này chỉ là dàn ý tham khảo.

- Khung: dọc 4:5 (1080×1350), nền trắng, tiêu đề chữ có chân, ô phụ đề bo góc dưới cùng.
- Đầu trang: `BTL ATTT | <Tên nhóm / lớp>` · tiêu đề **"Mini-SOC với Suricata"** · dải chấm tiến độ 9 phần.
- Giọng: `vi-VN-HoaiMyNeural` (nữ) hoặc `vi-VN-NamMinhNeural` (nam).
- Ước lượng: ~1000 từ lời đọc ≈ 6–7 phút.
- Mỗi dòng `>` là một câu thoại = một ô phụ đề. `[Hình]` là phần minh họa hiện dần theo câu.

Thay đổi so với bản 1: bỏ phần Đánh giá, bỏ phần IPv6, bỏ câu hỏi cuối; thêm phần **CÔNG CỤ** sau Mô hình lab; sau Kịch bản tổng hợp là Kết luận.
Bản 3: phần Công cụ bỏ VirtualBox, tcpdump/Wireshark, jq; tách thành 3a (mã nguồn mở) và 3b (6 thành phần nhóm tự viết, giải thích từng cái).

---

## 0. MỞ ĐẦU — "Máy chủ của bạn có biết mình đang bị tấn công không?"

[Hình] Laptop đen (A) → mũi tên đỏ → máy chủ (B) có trang Lab Shop. Dấu "?" lớn.

> Một máy chủ web bị quét cổng, bị dò mật khẩu, bị thử SQL injection mỗi ngày.
> Nhưng nếu không có ai theo dõi, nó sẽ không bao giờ biết.
> Trong bài tập lớn này, hệ thống xây một hệ thống giám sát nhỏ, gọi là Mini-SOC, cho một máy chủ web trong mạng lab.
> Hệ thống phải làm được ba việc: phát hiện, phản ứng, và không làm ảnh hưởng người dùng thật.

## 1. VẤN ĐỀ — Phát hiện thôi chưa đủ

[Hình] Ba ô: "Báo nhầm → chặn nhầm khách" · "Giả mạo IP → chặn nhầm máy khác" · "Chặn vĩnh viễn → không gỡ được".

> Phát hiện tấn công thì nhiều công cụ làm được. Cái khó là phản ứng thế nào cho đúng.
> Nếu báo nhầm, ta sẽ chặn nhầm khách hàng thật.
> Nếu kẻ tấn công giả mạo địa chỉ IP, ta có thể bị lừa chặn một máy vô tội.
> Vì vậy câu hỏi của bài là: chặn khi nào, chặn ai, và chặn trong bao lâu.

## 2. MÔ HÌNH LAB — Ba máy, một mạng cô lập

[Hình] Sơ đồ 3 máy trên dải mạng `10.77.0.0/24`: A Kali `.10` (đỏ), B Ubuntu `.20` (xanh navy), C Windows 10 `.30` (xanh lá). Mạng quản trị `192.168.56.0/24` vẽ nét đứt sang máy thật.

> Lab gồm ba máy ảo nằm trong một mạng nội bộ cô lập, không ra được Internet.
> Máy A chạy Kali, đóng vai kẻ tấn công.
> Máy B chạy Ubuntu, là máy chủ web Lab Shop, nơi đặt toàn bộ hệ thống giám sát.
> Máy C chạy Windows 10, là người dùng hợp lệ. Mọi lần chặn đều phải kiểm tra C vẫn mua hàng bình thường.

## 3. CÔNG CỤ — Dùng gì, và vì sao

Phần này chia 2 trang: **3a. Mã nguồn mở có sẵn** và **3b. Phần nhóm tự viết**.

### 3a. Mã nguồn mở có sẵn

[Hình] Lần lượt hiện từng thẻ: tên + nhãn "mã nguồn mở" + một dòng "vì sao". Thẻ đang nói tới sáng lên, các thẻ trước mờ đi.
- Kali Linux (nmap, curl) · Nginx · Suricata · nftables · systemd · khung MITRE ATT&CK

> Trước khi vào chi tiết, đây là những công cụ hệ thống sử dụng, và lý do chọn từng cái.
> Kali Linux là hệ điều hành chuyên cho kiểm thử bảo mật, có sẵn nmap để quét cổng và curl để gửi yêu cầu web, giống công cụ kẻ tấn công thật hay dùng.
> Nginx là máy chủ web mã nguồn mở rất phổ biến. Hệ thống dùng nó để chạy trang Lab Shop, đồng thời giới hạn tốc độ truy cập và thêm các header bảo mật.
> Suricata là hệ thống phát hiện xâm nhập mã nguồn mở. Nó đọc từng gói tin trên card mạng và so với các luật hệ thống viết.
> Hệ thống chọn Suricata vì nó xử lý được nhiều luồng song song, và ghi cảnh báo ra định dạng JSON, nên chương trình khác đọc lại rất dễ.
> nftables là tường lửa hiện đại của Linux, thay thế cho iptables. Điểm quan trọng là nó cho phép đặt thời hạn cho từng địa chỉ bị chặn, hết hạn thì tự gỡ.
> systemd là trình quản lý dịch vụ của Linux. Hệ thống dùng nó để mỗi chương trình chạy bằng một tài khoản riêng, có ít quyền nhất có thể, và tự khởi động lại khi lỗi.
> Cuối cùng là khung MITRE ATT&CK, một bộ từ điển chung mà các đội bảo mật trên thế giới dùng để gọi tên các kỹ thuật tấn công.

### 3b. Phần nhóm tự viết

[Hình] Sơ đồ máy chủ B chia 6 khối, mỗi khối hiện ra khi được nói tới, có mũi tên dữ liệu nối giữa chúng:
1. **Trang Lab Shop + API** (`lab-shop-api.py`) → ghi `auth.jsonl`
2. **Bộ luật Suricata** (`local.rules`, 20 luật) → Suricata ghi `eve.json`
3. **Honeypot** (`lab-honeypot.py`) → ghi `events.jsonl`
4. **Bộ phân tích** (`analyzer.py`) ← đọc cả 3 file log trên
5. **Lệnh chặn** (`lab-block`) ← chỉ bộ phân tích và dashboard được gọi
6. **Dashboard SOC** (`lab-soc.py`) ← người vận hành bấm duyệt
Góc dưới: nhãn "Python · chỉ thư viện chuẩn · 0 thư viện ngoài".

> Còn đây là những phần hệ thống tự viết. Có sáu thành phần.
> Thứ nhất là trang bán hàng Lab Shop và API phía sau nó. Đây là mục tiêu để bảo vệ, có giỏ hàng, đặt hàng và đăng nhập. Mật khẩu được băm, và nếu đăng nhập sai năm lần thì địa chỉ đó bị khóa năm phút.
> Thứ hai là bộ luật cho Suricata. Suricata chỉ là bộ máy, còn nhận ra hành vi nào là tấn công thì do luật quyết định. Hệ thống viết hai mươi luật, nhận biết quét cổng nhanh và chậm, SQL injection, XSS, dò đường dẫn file, và truy cập trang bẫy.
> Thứ ba là honeypot, một chương trình giả làm các thứ hấp dẫn kẻ tấn công: trang quản trị giả, file sao lưu giả, và các cổng giả như telnet, SSH, MySQL. Nó không có chức năng thật nào, chỉ ghi lại mọi thứ kẻ tấn công làm.
> Thứ tư là bộ phân tích, phần bộ não của hệ thống. Nó đọc cùng lúc ba nguồn: cảnh báo của Suricata, log của honeypot và log đăng nhập của trang web. Sau đó nó cộng điểm cho từng địa chỉ IP, gắn mã ATT&CK, và quyết định có phản ứng hay không.
> Thứ năm là lệnh chặn, thành phần duy nhất chạy với quyền quản trị. Nó chỉ nhận đúng vài tham số, chỉ chặn được những địa chỉ nằm trong danh sách cho phép, và kiểm tra lại tường lửa sau mỗi lần chặn.
> Thứ sáu là dashboard SOC, giao diện web cho người vận hành. Ở đây ta thấy máy nào đang hoạt động, cảnh báo nào vừa xảy ra, bấm duyệt chặn, và xem báo cáo sự cố tự sinh.
> Tất cả được viết bằng Python và chỉ dùng thư viện chuẩn. Không cài thêm thư viện bên ngoài nghĩa là ít phụ thuộc hơn, và ít chỗ cho lỗ hổng đến từ mã của người khác.

## 4. PHÁT HIỆN — Tín hiệu yếu và tín hiệu mạnh

[Hình] Khối code nền tối trích `local.rules` (SID 1000002, 1000005). Bên cạnh: thang 3 mức "yếu · củng cố · mạnh". Biểu tượng ổ khóa cạnh tín hiệu "không giả mạo được".

> Không phải cảnh báo nào của Suricata cũng đáng tin như nhau.
> Gói SYN dồn dập là tín hiệu yếu, vì địa chỉ nguồn có thể bị giả mạo.
> Còn truy cập vào một đường dẫn bẫy cần bắt tay TCP đầy đủ, nên không giả mạo được. Đó là tín hiệu mạnh.
> Ngoài mạng, hệ thống còn đọc thêm log đăng nhập của trang web và log của honeypot, để phát hiện dò mật khẩu, SQL injection và XSS.
> Chỉ tín hiệu mạnh mới được phép dẫn tới hành động chặn.

## 5. PHẢN ỨNG — Chặn có thời hạn, quyền tối thiểu

[Hình] Luồng: `eve.json` → analyzer (user `labresp`, không root) → `sudo lab-block` (lệnh duy nhất) → nftables set có thời hạn. Danh sách "không bao giờ chặn: B, C".

> Bộ phân tích đọc cảnh báo, cộng điểm cho từng địa chỉ IP.
> Nó chạy bằng một tài khoản thường, chỉ được phép gọi đúng một lệnh chặn.
> Mỗi lần chặn đều tự hết hạn ngay trong nhân hệ điều hành, nên không cần nhớ để gỡ.
> Và có một danh sách không bao giờ bị chặn, gồm chính máy chủ và người dùng hợp lệ.

## 6. ĐÁNH LỪA — Gài bẫy thay vì chỉ chặn

[Hình] Mã nguồn HTML có dòng comment `admin / LabShop@2026!` được tô vàng, nhãn "honeytoken". `robots.txt` có `/backup/`. Cổng bẫy 23 · 2222 · 3306. Mũi tên: A bị chuyển sang "bản sao Lab Shop", trang admin GIẢ.

> Ở bản nâng cấp, hệ thống thêm một lớp đánh lừa.
> Trong mã nguồn trang web có gài sẵn một tài khoản quản trị giả, một khóa API giả và một thư mục sao lưu giả.
> Người dùng thật không bao giờ đụng tới chúng, nên ai dùng tới gần như chắc chắn là kẻ tấn công.
> Khi đủ bằng chứng, kẻ tấn công không bị chặn ngay mà bị chuyển sang một bản sao của trang web.
> Trang chủ trông vẫn y hệt, nhưng trang quản trị là giả, và mọi mật khẩu kẻ tấn công thử đều được ghi lại.

## 7. KỊCH BẢN TỔNG HỢP — Từ quét cổng đến bị chặn

[Hình] Dòng thời gian dọc 5 bước, mỗi bước có mã ATT&CK và điểm tăng dần: T1046 (60) → T1595 (110, đánh lừa) → T1078 → T1110.001 (310) → "Người vận hành duyệt" → A: bị chặn, C: vẫn 200. Ảnh chụp dashboard SOC nếu có.

> Hãy xem một kịch bản hoàn chỉnh.
> Máy A quét cổng và chạm vào cổng bẫy 23. Điểm tăng lên 110, A bị chuyển sang trang giả.
> A đọc mã nguồn, thấy tài khoản quản trị, đăng nhập vào trang admin giả, rồi thử thêm mật khẩu root.
> Mỗi bước được gắn một mã kỹ thuật ATT&CK. Điểm lên tới 310.
> Lúc này hệ thống không tự chặn, mà đưa ra một yêu cầu trên dashboard để người vận hành duyệt.
> Sau khi duyệt, A bị chặn toàn bộ, còn máy C vẫn mua hàng bình thường.

## 8. KẾT LUẬN

[Hình] Bốn lớp xếp chồng hiện dần: Phòng ngừa · Phát hiện · Đánh lừa · Phản ứng có người duyệt. Cuối: tên nhóm, thành viên.

> Tóm lại, hệ thống đã đi từ một hệ thống phát hiện quét cổng đơn giản tới một Mini-SOC nhiều lớp.
> Phòng ngừa ở tầng ứng dụng, phát hiện từ nhiều nguồn, đánh lừa kẻ tấn công, và phản ứng có con người duyệt.
> Mọi lần chặn đều có thời hạn, có bằng chứng, và không ảnh hưởng tới người dùng hợp lệ.
> Cảm ơn thầy cô và các bạn đã theo dõi.

---

## Cần bổ sung
- [ ] Tên nhóm, thành viên, lớp, môn — cho đầu trang và cảnh kết.
- [ ] Chọn giọng: nữ HoaiMy hay nam NamMinh (mẫu ở `video/public/voice-test/`).
- [ ] Ảnh dashboard SOC thật (cần bật 3 VM) hay vẽ mô phỏng.
