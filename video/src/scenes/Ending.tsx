import React from 'react';
import { Bg, Captions, Pop, SceneTitle } from '../components';
import { C } from '../theme';

export const END_SEC = 16;

const Item: React.FC<{ color: string; title: string; text: string; delay: number }> = ({ color, title, text, delay }) => (
  <Pop delay={delay} style={{ marginBottom: 18 }}>
    <div style={{ display: 'flex', gap: 18, alignItems: 'baseline' }}>
      <div style={{ width: 14, height: 14, borderRadius: 7, background: color, flexShrink: 0, transform: 'translateY(-4px)' }} />
      <div><span style={{ fontSize: 32, fontWeight: 700 }}>{title}</span><span style={{ fontSize: 28, color: C.mute }}> — {text}</span></div>
    </div>
  </Pop>
);

export const Ending: React.FC = () => (
  <Bg>
    <SceneTitle kicker="Giới hạn & hướng phát triển" title="Điều đã và chưa chứng minh" />
    <div style={{ position: 'absolute', top: 240, left: 120, right: 120 }}>
      <Item color={C.amber} delay={0.8} title="Quét cực chậm" text="chậm hơn 1 cổng / 6 giây vẫn lọt ngưỡng cố định" />
      <Item color={C.amber} delay={1.4} title="IPv6" text="card lab còn IPv6, có thể lách bảng chặn IPv4" />
      <Item color={C.amber} delay={2.0} title="HTTPS" text="Suricata không đọc được URL đã mã hóa" />
      <Item color={C.amber} delay={2.6} title="Giả mạo IP" text="mới kiểm chứng bằng dữ liệu giả lập" />
      <Item color={C.violet} delay={3.4} title="Hướng tiếp theo" text="Isolation Forest trên đặc trưng flow, so sánh công bằng với rule" />
    </div>
    <Pop delay={8} style={{ position: 'absolute', bottom: 170, left: 0, right: 0, textAlign: 'center' }}>
      <div style={{ fontSize: 46, fontWeight: 800, color: C.cyan }}>Cảm ơn thầy cô và các bạn đã theo dõi</div>
    </Pop>
    <Captions cues={[
      { from: 1, to: 7.5, text: 'Nhóm nêu rõ những gì hệ thống chưa làm được, kèm bằng chứng cho từng giới hạn.' },
      { from: 7.5, to: 15.6, text: 'Toàn bộ cấu hình, script, PCAP và báo cáo có trong thư mục dự án để tái lập.' },
    ]} />
  </Bg>
);
