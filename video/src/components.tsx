import React from 'react';
import { AbsoluteFill, interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import { C, FONT, s } from './theme';

export type Cue = { from: number; to: number; text: string };

/** Phu de tieng Viet o cuoi man hinh. from/to tinh bang giay, tuong doi voi canh. */
export const Captions: React.FC<{ cues: Cue[] }> = ({ cues }) => {
  const frame = useCurrentFrame();
  const t = frame / 30;
  const cue = cues.find((c) => t >= c.from && t < c.to);
  if (!cue) return null;
  const local = frame - s(cue.from);
  const end = s(cue.to) - frame;
  const opacity = Math.min(interpolate(local, [0, 8], [0, 1], { extrapolateRight: 'clamp' }),
    interpolate(end, [0, 8], [0, 1], { extrapolateRight: 'clamp' }));
  return (
    <AbsoluteFill style={{ justifyContent: 'flex-end', alignItems: 'center', paddingBottom: 46, pointerEvents: 'none' }}>
      <div style={{
        opacity, maxWidth: 1500, padding: '14px 30px', borderRadius: 12,
        background: 'rgba(5, 10, 20, 0.82)', border: `1px solid ${C.line}`,
        color: C.text, fontFamily: FONT, fontSize: 34, lineHeight: 1.35, textAlign: 'center',
      }}>{cue.text}</div>
    </AbsoluteFill>
  );
};

/** Tieu de canh o goc tren trai */
export const SceneTitle: React.FC<{ kicker: string; title: string }> = ({ kicker, title }) => {
  const frame = useCurrentFrame();
  const o = interpolate(frame, [0, 15], [0, 1], { extrapolateRight: 'clamp' });
  const x = interpolate(frame, [0, 15], [-30, 0], { extrapolateRight: 'clamp' });
  return (
    <div style={{ position: 'absolute', top: 54, left: 80, opacity: o, transform: `translateX(${x}px)`, fontFamily: FONT }}>
      <div style={{ color: C.cyan, fontSize: 24, letterSpacing: 3, textTransform: 'uppercase', fontWeight: 600 }}>{kicker}</div>
      <div style={{ color: C.text, fontSize: 54, fontWeight: 700, marginTop: 6 }}>{title}</div>
    </div>
  );
};

/** Hien dan (pop) mot phan tu sau `delay` giay */
export const Pop: React.FC<{ delay: number; children: React.ReactNode; style?: React.CSSProperties }> = ({ delay, children, style }) => {
  const frame = useCurrentFrame();
  const { fps } = useVideoConfig();
  const p = spring({ frame: frame - s(delay), fps, config: { damping: 16, stiffness: 120 } });
  return (
    <div style={{ opacity: p, transform: `translateY(${(1 - p) * 24}px) scale(${0.96 + 0.04 * p})`, ...style }}>{children}</div>
  );
};

export const Bg: React.FC<{ children: React.ReactNode }> = ({ children }) => (
  <AbsoluteFill style={{
    background: `radial-gradient(1200px 700px at 20% 10%, #13213a 0%, ${C.bg} 60%)`, fontFamily: FONT, color: C.text,
  }}>{children}</AbsoluteFill>
);

export const Badge: React.FC<{ color: string; children: React.ReactNode }> = ({ color, children }) => (
  <span style={{
    display: 'inline-block', padding: '4px 12px', borderRadius: 999, fontSize: 22, fontWeight: 600,
    color, border: `1.5px solid ${color}`, background: `${color}1a`, marginRight: 8,
  }}>{children}</span>
);
