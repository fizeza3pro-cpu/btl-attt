import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { Bg, Captions, Pop, SceneTitle } from '../components';
import { C, MONO, s } from '../theme';

export const RESULTS_SEC = 30;

// So lieu that: report/ket-qua-m4-danh-gia.md (muc 3 va 6.3)
const Bar: React.FC<{ label: string; value: number; max: number; color: string; delay: number; text: string }> = ({ label, value, max, color, delay, text }) => {
  const frame = useCurrentFrame();
  const w = interpolate(frame, [s(delay), s(delay + 1)], [0, value / max], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  return (
    <div style={{ marginBottom: 18 }}>
      <div style={{ fontSize: 24, color: C.mute, marginBottom: 6 }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ flex: 1, height: 38, background: C.panel, borderRadius: 8, overflow: 'hidden' }}>
          <div style={{ width: `${w * 100}%`, height: '100%', background: color, borderRadius: 8 }} />
        </div>
        <div style={{ width: 120, fontFamily: MONO, fontSize: 30, fontWeight: 800, color }}>{text}</div>
      </div>
    </div>
  );
};

const Metric: React.FC<{ k: string; v: string; sub: string; color: string; delay: number }> = ({ k, v, sub, color, delay }) => (
  <Pop delay={delay}>
    <div style={{ width: 396, padding: '20px 26px', borderRadius: 16, background: C.panel, border: `1px solid ${C.line}` }}>
      <div style={{ fontSize: 24, color: C.mute }}>{k}</div>
      <div style={{ fontSize: 60, fontWeight: 800, color, fontFamily: MONO }}>{v}</div>
      <div style={{ fontSize: 20, color: C.mute }}>{sub}</div>
    </div>
  </Pop>
);

export const Results: React.FC = () => (
  <Bg>
    <SceneTitle kicker="Đánh giá" title="Kết quả trên 56 lần chạy có nhãn" />
    <div style={{ position: 'absolute', top: 220, left: 120, display: 'flex', gap: 24 }}>
      <Metric k="Recall" v="0,958" sub="23/24 tấn công bị phát hiện" color={C.green} delay={1} />
      <Metric k="FPR" v="0" sub="0/32 ca bình thường bị báo nhầm" color={C.cyan} delay={1.5} />
      <Metric k="Precision" v="1,0" sub="theo chính sách" color={C.cyan} delay={2} />
      <Metric k="F1" v="0,979" sub="rule v3 + chính sách" color={C.violet} delay={2.5} />
    </div>
    <div style={{ position: 'absolute', top: 500, left: 120, width: 820 }}>
      <div style={{ fontSize: 30, fontWeight: 700, marginBottom: 14 }}>Báo nhầm: mọi alert vs. theo chính sách</div>
      <Bar label="Mọi alert (gồm tín hiệu yếu)" value={11} max={11} color={C.amber} delay={5} text="11 ca" />
      <Bar label="Theo chính sách (cần tín hiệu củng cố)" value={0} max={11} color={C.cyan} delay={6} text="0 ca" />
    </div>
    <div style={{ position: 'absolute', top: 500, right: 120, width: 760 }}>
      <div style={{ fontSize: 30, fontWeight: 700, marginBottom: 14 }}>Quét cổng chậm (1 cổng / 1,5 s)</div>
      <Bar label="Rule v2 (cửa sổ 10 s)" value={0} max={3} color={C.red} delay={15} text="0/3" />
      <Bar label="Rule v3 (thêm cửa sổ 60 s)" value={3} max={3} color={C.green} delay={16} text="3/3" />
      <Pop delay={18}>
        <div style={{ fontSize: 22, color: C.mute }}>Biến thể mới 1 cổng / 3 s: bắt được. 1 cổng / 8 s: lọt — đúng giới hạn đã tính trước.</div>
      </Pop>
    </div>
    <Captions cues={[
      { from: 1, to: 6, text: 'Chạy lặp 5 lần mỗi ca chính, thêm lưu lượng thật từ Windows và các ca biên, tổng cộng 56 lần chạy có nhãn.' },
      { from: 6, to: 14, text: 'Rule tốc độ SYN báo nhầm 11 lần với web dồn dập. Chính sách chỉ tin tín hiệu củng cố đã loại bỏ toàn bộ.' },
      { from: 14, to: 22, text: 'Quét cổng chậm từng lọt lưới. Rule cửa sổ 60 giây sửa được, kiểm chứng bằng phát lại 55 file PCAP.' },
      { from: 22, to: 29.6, text: 'Phát lại PCAP chỉ được dùng sau khi khớp 55/55 với kết quả chạy thật.' },
    ]} />
  </Bg>
);
