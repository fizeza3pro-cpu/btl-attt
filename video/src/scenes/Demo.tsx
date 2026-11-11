import React from 'react';
import { AbsoluteFill, interpolate, OffthreadVideo, Sequence, staticFile, useCurrentFrame } from 'remotion';
import { Bg, Captions } from '../components';
import { SEGMENTS, DEMO_CUES, DEMO_STEPS } from '../demoConfig';

/** Nhan "Buoc n/5" o giua phia tren, doi theo thoi gian */
const StepBanner: React.FC = () => {
  const frame = useCurrentFrame();
  const t = frame / FPS;
  const st = DEMO_STEPS.find((x) => t >= x.from && t < x.to);
  if (!st) return null;
  const local = frame - Math.round(st.from * FPS);
  const o = interpolate(local, [0, 10], [0, 1], { extrapolateRight: 'clamp' });
  const y = interpolate(local, [0, 10], [-16, 0], { extrapolateRight: 'clamp' });
  return (
    <div style={{ position: 'absolute', top: 14, left: 0, right: 0, display: 'flex', justifyContent: 'center', opacity: o, transform: `translateY(${y}px)` }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '10px 26px 10px 12px', borderRadius: 999, background: 'rgba(5,10,20,0.92)', border: `2px solid ${st.color}`, boxShadow: '0 8px 30px rgba(0,0,0,0.5)', fontFamily: FONT }}>
        <span style={{ background: st.color, color: '#0b1220', fontWeight: 900, fontSize: 26, padding: '4px 14px', borderRadius: 999 }}>BƯỚC {st.n}/5</span>
        <span style={{ color: '#e6edf7', fontWeight: 700, fontSize: 30 }}>{st.title}</span>
      </div>
    </div>
  );
};
import { C, FONT, FPS, MONO } from '../theme';

// Ban quay 2560x1600 (16:10) dat vao khung 1920x1080: cao 940 px, phan duoi danh cho phu de.
const VH = 940;
const VW = Math.round((VH * 2560) / 1600);

const Tag: React.FC<{ color: string; children: React.ReactNode; style: React.CSSProperties }> = ({ color, children, style }) => (
  <div style={{ position: 'absolute', fontSize: 22, fontWeight: 700, color, writingMode: 'vertical-rl', transform: 'rotate(180deg)', letterSpacing: 2, ...style }}>{children}</div>
);

export const Demo: React.FC = () => {
  if (SEGMENTS.length === 0) {
    return (
      <Bg>
        <AbsoluteFill style={{ justifyContent: 'center', alignItems: 'center', fontSize: 48, color: C.mute }}>
          [Đoạn quay màn hình demo thật sẽ được ghép vào đây]
        </AbsoluteFill>
      </Bg>
    );
  }
  let at = 0;
  const left = (1920 - VW) / 2;
  return (
    <AbsoluteFill style={{ background: '#05080f', fontFamily: FONT }}>
      {SEGMENTS.map((seg, i) => {
        const len = Math.round(((seg.to - seg.from) / seg.rate) * FPS);
        const from = at; at += len;
        return (
          <Sequence key={i} from={from} durationInFrames={len}>
            <OffthreadVideo
              src={staticFile('demo.mp4')}
              trimBefore={Math.round(seg.from * FPS)}
              trimAfter={Math.round(seg.to * FPS)}
              playbackRate={seg.rate}
              muted
              style={{ position: 'absolute', top: 6, left, width: VW, height: VH, borderRadius: 8 }}
            />
            {seg.rate !== 1 && (
              <div style={{ position: 'absolute', top: 24, right: 22, fontFamily: MONO, fontSize: 30, fontWeight: 800, color: C.amber, padding: '6px 10px', border: `2px solid ${C.amber}`, borderRadius: 10, background: 'rgba(0,0,0,0.6)' }}>
                ▶▶<br />×{seg.rate}
              </div>
            )}
          </Sequence>
        );
      })}
      {/* Nhan cac khung o le trai/phai */}
      <Tag color={C.red} style={{ left: 40, top: 110 }}>A · KALI · KẺ TẤN CÔNG</Tag>
      <Tag color={C.cyan} style={{ left: 40, top: 640 }}>B · MÁY CHỦ · GIÁM SÁT</Tag>
      <Tag color={C.green} style={{ right: 40, top: 160, transform: 'none' }}>C · WIN10 · KHÁCH HÀNG</Tag>
      <div style={{ position: 'absolute', bottom: 8, right: 24, fontSize: 18, color: C.mute }}>Quay màn hình thật · 08/11/2026</div>
      <StepBanner />
      <Captions cues={DEMO_CUES} />
    </AbsoluteFill>
  );
};
