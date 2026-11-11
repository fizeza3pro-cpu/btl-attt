import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { Bg, Captions, Pop, SceneTitle } from '../components';
import { C, MONO, s } from '../theme';

export const SPOOF_SEC = 26;

// Du lieu that: tests/m5-incidents.jsonl, ca M5-APP-02 (08/11/2026)
const signals = [
  { sid: 1000001, name: 'Tốc độ SYN cao', pts: 20, spoof: true, at: 2 },
  { sid: 1000003, name: 'Nhiều RST/ACK (10 s)', pts: 50, spoof: true, at: 3.2 },
  { sid: 1000005, name: 'Nhiều RST/ACK (60 s)', pts: 50, spoof: true, at: 4.4 },
  { sid: 1000002, name: 'Truy cập bẫy /lab-admin', pts: 70, spoof: false, at: 12 },
];
const MAX = 200;

export const AntiSpoof: React.FC = () => {
  const frame = useCurrentFrame();
  const t = frame / 30;
  const score = signals.filter((x) => t >= x.at).reduce((a, x) => a + x.pts, 0);
  const shown = interpolate(frame, [0, s(1)], [0, 1], { extrapolateRight: 'clamp' });
  const blocked = t >= 13.2;
  const held = t >= 6 && !blocked;
  let acc = 0;
  return (
    <Bg>
      <SceneTitle kicker="Chính sách phản ứng" title="Đủ điểm chưa chắc đã chặn" />
      {/* thanh diem */}
      <div style={{ position: 'absolute', top: 230, left: 120, right: 120, opacity: shown }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 28, color: C.mute, marginBottom: 10 }}>
          <span>Điểm của nghi phạm 10.77.0.10 (cửa sổ 120 s)</span>
          <span style={{ fontFamily: MONO, color: C.text, fontSize: 40, fontWeight: 800 }}>{score}</span>
        </div>
        <div style={{ position: 'relative', height: 64, borderRadius: 12, background: C.panel, border: `1px solid ${C.line}`, overflow: 'hidden' }}>
          {signals.filter((x) => t >= x.at).map((x) => {
            const left = acc; acc += x.pts;
            return <div key={x.sid} style={{
              position: 'absolute', top: 0, bottom: 0, left: `${(left / MAX) * 100}%`, width: `${(x.pts / MAX) * 100}%`,
              background: x.spoof ? `${C.amber}cc` : `${C.green}dd`, borderRight: `2px solid ${C.bg}`,
              display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 24, fontWeight: 800, color: C.bg,
            }}>+{x.pts}</div>;
          })}
          <div style={{ position: 'absolute', top: -2, bottom: -2, left: `${(100 / MAX) * 100}%`, width: 4, background: C.red }} />
        </div>
        <div style={{ position: 'relative', height: 30 }}>
          <span style={{ position: 'absolute', left: `calc(${(100 / MAX) * 100}% - 70px)`, top: 6, fontSize: 22, color: C.red }}>ngưỡng chặn 100</span>
        </div>
      </div>
      {/* danh sach tin hieu */}
      <div style={{ position: 'absolute', top: 400, left: 120, width: 900 }}>
        {signals.map((x) => (
          <Pop key={x.sid} delay={x.at} style={{ marginBottom: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 18, padding: '14px 20px', borderRadius: 12, background: C.panel, border: `1px solid ${C.line}` }}>
              <span style={{ fontFamily: MONO, fontSize: 24, color: C.mute }}>SID {x.sid}</span>
              <span style={{ fontSize: 28, flex: 1 }}>{x.name}</span>
              <span style={{ fontSize: 22, fontWeight: 700, color: x.spoof ? C.amber : C.green }}>
                {x.spoof ? 'giả mạo IP được' : 'kết nối TCP thật'}
              </span>
            </div>
          </Pop>
        ))}
      </div>
      {/* quyet dinh */}
      <div style={{ position: 'absolute', top: 400, right: 120, width: 640 }}>
        {held && (
          <Pop delay={6}>
            <div style={{ padding: 28, borderRadius: 16, border: `2px solid ${C.amber}`, background: `${C.amber}14` }}>
              <div style={{ fontFamily: MONO, fontSize: 26, color: C.amber }}>incident_high_spoof_suspect</div>
              <div style={{ fontSize: 34, fontWeight: 800, marginTop: 10 }}>120 điểm → KHÔNG chặn</div>
              <div style={{ fontSize: 26, color: C.mute, marginTop: 10 }}>Toàn tín hiệu có thể bị giả mạo IP. Chặn lúc này có thể bị lợi dụng để chặn người dùng thật.</div>
            </div>
          </Pop>
        )}
        {blocked && (
          <Pop delay={13.2}>
            <div style={{ padding: 28, borderRadius: 16, border: `2px solid ${C.red}`, background: `${C.red}18` }}>
              <div style={{ fontFamily: MONO, fontSize: 26, color: C.red }}>block_l1 · trễ 0,097 s</div>
              <div style={{ fontSize: 34, fontWeight: 800, marginTop: 10 }}>190 điểm + tín hiệu thật → CHẶN</div>
              <div style={{ fontSize: 26, color: C.mute, marginTop: 10 }}>lab-block: "blocked (present in set)". Chỉ IP 10.77.0.10, chỉ TCP/80, tự hết hạn sau 60 s.</div>
            </div>
          </Pop>
        )}
      </div>
      <Captions cues={[
        { from: 1, to: 6, text: 'Đây là dữ liệu thật từ lần chặn tự động. Quét cổng đẩy điểm của A lên 120, vượt ngưỡng chặn.' },
        { from: 6, to: 12, text: 'Nhưng analyzer không chặn: các tín hiệu quét cổng có thể bị kẻ tấn công giả mạo IP của người khác.' },
        { from: 12, to: 19, text: 'Khi A truy cập đường dẫn bẫy qua một kết nối TCP thật, analyzer mới chặn — sau 0,097 giây.' },
        { from: 19, to: 25.6, text: 'Kiểm thử giả mạo IP của C: 120 điểm nhưng không chặn C. Bộ kiểm thử analyzer đạt 19/19 ca.' },
      ]} />
    </Bg>
  );
};
