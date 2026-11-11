import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { Bg, Captions, Pop, SceneTitle } from '../components';
import { C, MONO, s } from '../theme';

export const ARCH_SEC = 30;

const Host: React.FC<{ name: string; role: string; ip: string; color: string; items: string[] }> = ({ name, role, ip, color, items }) => (
  <div style={{ width: 400, borderRadius: 18, background: C.panel, border: `2px solid ${color}`, padding: '22px 26px', boxShadow: `0 0 40px ${color}22` }}>
    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
      <div style={{ fontSize: 46, fontWeight: 800, color }}>{name}</div>
      <div style={{ fontFamily: MONO, fontSize: 24, color: C.text }}>{ip}</div>
    </div>
    <div style={{ fontSize: 26, color: C.mute, marginTop: 4 }}>{role}</div>
    <div style={{ marginTop: 14, display: 'flex', flexWrap: 'wrap', gap: 8 }}>
      {items.map((i) => (
        <span key={i} style={{ fontSize: 21, padding: '3px 10px', borderRadius: 8, background: C.panel2, color: C.text }}>{i}</span>
      ))}
    </div>
  </div>
);

const steps = [
  { t: 'Lưu lượng', c: C.mute },
  { t: 'Suricata (IDS)', c: C.cyan },
  { t: 'EVE JSON', c: C.cyan },
  { t: 'Analyzer chấm điểm', c: C.violet },
  { t: 'lab-block', c: C.amber },
  { t: 'nftables 60 s', c: C.red },
];

export const Architecture: React.FC = () => {
  const frame = useCurrentFrame();
  const flowStart = s(14);
  const active = Math.floor(interpolate(frame, [flowStart, flowStart + s(9)], [0, steps.length], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }));
  const lineW = interpolate(frame, [s(2.5), s(4.5)], [0, 1], { extrapolateRight: 'clamp' });
  return (
    <Bg>
      <SceneTitle kicker="Mô hình lab" title="3 máy ảo trong mạng cô lập" />
      {/* duong mang lab */}
      <div style={{ position: 'absolute', top: 525, left: 160, width: 1600 * lineW, height: 6, background: C.line, borderRadius: 3 }} />
      <div style={{ position: 'absolute', top: 541, left: 160, fontFamily: MONO, fontSize: 22, color: C.mute, opacity: lineW }}>
        Internal Network "ids-lab" 10.77.0.0/24 — không gateway, không Internet
      </div>
      <div style={{ position: 'absolute', top: 200, left: 120, right: 120, display: 'flex', justifyContent: 'space-between' }}>
        <Pop delay={1}><Host name="A" role="Kẻ tấn công (Kali)" ip="10.77.0.10" color={C.red} items={['nmap', 'curl', 'Firefox']} /></Pop>
        <Pop delay={1.6}><Host name="B" role="Máy chủ được bảo vệ (Ubuntu)" ip="10.77.0.20" color={C.cyan} items={['Lab Shop (Nginx)', 'Suricata', 'nftables', 'analyzer']} /></Pop>
        <Pop delay={2.2}><Host name="C" role="Người dùng hợp lệ (Windows 10)" ip="10.77.0.30" color={C.green} items={['Edge', 'curl.exe']} /></Pop>
      </div>
      {/* chuoi xu ly */}
      <div style={{ position: 'absolute', top: 650, left: 120, right: 120, display: 'flex', alignItems: 'center', gap: 14, opacity: interpolate(frame, [s(13), s(14)], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }) }}>
        {steps.map((st, i) => (
          <React.Fragment key={st.t}>
            <div style={{
              flex: 1, textAlign: 'center', padding: '18px 8px', borderRadius: 14, fontSize: 26, fontWeight: 700,
              background: i < active ? `${st.c}22` : C.panel, border: `2px solid ${i < active ? st.c : C.line}`,
              color: i < active ? st.c : C.mute, transition: 'none',
            }}>{st.t}</div>
            {i < steps.length - 1 && <div style={{ fontSize: 34, color: i < active - 1 ? C.text : C.line }}>→</div>}
          </React.Fragment>
        ))}
      </div>
      <Captions cues={[
        { from: 1, to: 7, text: 'Máy A đóng vai kẻ tấn công, máy C là người dùng thật, máy B là máy chủ web cần bảo vệ.' },
        { from: 7, to: 13, text: 'Ba máy nằm trong một mạng ảo cô lập, không ra Internet. Suricata lắng nghe ngay trên card mạng của B.' },
        { from: 13, to: 21, text: 'Suricata chỉ phát hiện và ghi cảnh báo. Analyzer đọc cảnh báo, chấm điểm theo chính sách và quyết định.' },
        { from: 21, to: 29.6, text: 'Chỉ khi đủ điều kiện, analyzer mới gọi lab-block để nftables chặn kẻ tấn công trong 60 giây.' },
      ]} />
    </Bg>
  );
};
