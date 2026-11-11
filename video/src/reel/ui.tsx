import React from 'react';
import { AbsoluteFill, Img, interpolate, OffthreadVideo, staticFile, useCurrentFrame } from 'remotion';
import { clamp, K, MONO, SANS, SERIF, useSec } from './core';
import media from './media.json';

export const BRAND = 'BTL An toàn thông tin';
export const TITLE = 'Mini-SOC với Suricata';

// --------------------------------- khung -----------------------------------
const Dots: React.FC<{ n: number; at: number }> = ({ n, at }) => (
  <div style={{ display: 'flex', gap: 12 }}>
    {Array.from({ length: n }).map((_, i) => (
      <div key={i} style={{
        width: 16, height: 16, borderRadius: 99,
        background: i < at ? '#9cc7b3' : i === at ? K.green : K.line,
        boxShadow: i === at ? `0 0 0 4px ${K.greenBg}` : 'none',
      }} />
    ))}
  </div>
);

export const Frame: React.FC<{ total: number; children: React.ReactNode }> = ({ total, children }) => {
  const { sec, frame, step } = useSec();
  const fadeIn = interpolate(frame, [0, 14], [0, 1], clamp);
  const fadeOut = interpolate(frame, [sec.len - 10, sec.len], [1, 0], clamp);
  const cue = step >= 0 ? sec.lines[step] : null;
  const cueIn = cue ? interpolate(frame - cue.from, [0, 8], [0, 1], clamp) : 0;
  return (
    <AbsoluteFill style={{ background: `linear-gradient(180deg, ${K.bg2} 0px, ${K.bg} 230px)`, fontFamily: SERIF, color: K.text }}>
      {/* dau trang */}
      <div style={{ position: 'absolute', top: 34, left: 90, right: 90, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, fontFamily: SANS, fontSize: 22, color: K.mute }}>
          <div style={{ width: 70, height: 40, borderRadius: 10, background: K.ink, color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center', fontWeight: 800, fontSize: 18, letterSpacing: 0.5 }}>ATTT</div>
          <span style={{ fontWeight: 600, color: K.ink }}>{BRAND}</span>
          <span style={{ color: K.faint }}>|</span>
          <span>Giám sát máy chủ web trong mạng lab</span>
        </div>
        <Dots n={total} at={sec.index} />
      </div>
      <div style={{ position: 'absolute', top: 96, left: 90, right: 90 }}>
        <div style={{ fontSize: 64, fontWeight: 700, color: K.ink, letterSpacing: -0.5 }}>{TITLE}</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 18, marginTop: 10, opacity: fadeIn }}>
          <span style={{ fontFamily: SANS, fontSize: 21, fontWeight: 700, letterSpacing: 1.5, color: K.green, background: K.greenBg, border: `2px solid ${K.green}`, borderRadius: 99, padding: '4px 18px' }}>{sec.label}</span>
          <span style={{ fontSize: 31, fontWeight: 700, color: K.text }}>{sec.tagline}</span>
        </div>
      </div>
      {/* san khau */}
      <div style={{ position: 'absolute', top: 250, left: 90, right: 90, height: 640, opacity: fadeIn * fadeOut }}>{children}</div>
      {/* phu de */}
      <div style={{ position: 'absolute', bottom: 34, left: 0, right: 0, display: 'flex', justifyContent: 'center' }}>
        <div style={{
          minHeight: 64, width: 1560, padding: '16px 36px', borderRadius: 16, background: '#fff',
          border: `1.5px solid ${K.line}`, boxShadow: '0 6px 24px rgba(20,30,60,0.07)',
          fontSize: 31, lineHeight: 1.4, textAlign: 'center', color: K.text, opacity: cue ? cueIn * fadeOut : 0,
        }}>{cue?.text}</div>
      </div>
    </AbsoluteFill>
  );
};

// ------------------------------- thanh phan --------------------------------
export const Pill: React.FC<{ c?: string; bg?: string; children: React.ReactNode; size?: number }> = ({ c = K.green, bg = K.greenBg, children, size = 20 }) => (
  <span style={{ display: 'inline-block', fontFamily: SANS, fontSize: size, fontWeight: 700, color: c, background: bg, border: `1.5px solid ${c}`, borderRadius: 99, padding: '3px 14px', whiteSpace: 'nowrap' }}>{children}</span>
);

export const Card: React.FC<{ c?: string; bg?: string; style?: React.CSSProperties; children: React.ReactNode; glow?: boolean }> = ({ c = K.line, bg = '#fff', style, children, glow }) => (
  <div style={{ background: bg, border: `2px solid ${c}`, borderRadius: 18, padding: '20px 24px', boxShadow: glow ? `0 0 0 6px ${c}22, 0 10px 30px rgba(20,30,60,0.08)` : '0 6px 20px rgba(20,30,60,0.05)', ...style }}>{children}</div>
);

export type CodeLine = { s: string; hl?: string };
export const Code: React.FC<{ title: string; lines: CodeLine[]; style?: React.CSSProperties; size?: number }> = ({ title, lines, style, size = 22 }) => (
  <div style={{ background: K.code, borderRadius: 14, overflow: 'hidden', boxShadow: '0 10px 30px rgba(10,15,30,0.18)', ...style }}>
    <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '10px 16px', background: '#2a2f3a' }}>
      {['#ef6b5e', '#f4bf4f', '#61c454'].map((c) => <div key={c} style={{ width: 13, height: 13, borderRadius: 99, background: c }} />)}
      <span style={{ marginLeft: 12, fontFamily: MONO, fontSize: 18, color: '#aab2c0' }}>{title}</span>
    </div>
    <div style={{ padding: '14px 20px', fontFamily: MONO, fontSize: size, lineHeight: 1.55, color: K.codeText, whiteSpace: 'pre' }}>
      {lines.map((l, i) => (
        <div key={i} style={{ background: l.hl ? `${l.hl}40` : 'transparent', borderLeft: l.hl ? `4px solid ${l.hl}` : '4px solid transparent', paddingLeft: 10, marginLeft: -14 }}>{l.s || ' '}</div>
      ))}
    </div>
  </div>
);

/** Mui ten ngang/doc ve dan theo p (0..1) */
export const Arrow: React.FC<{ x1: number; y1: number; x2: number; y2: number; p?: number; c?: string; dash?: boolean; w?: number }> = ({ x1, y1, x2, y2, p = 1, c = K.mute, dash, w = 3 }) => {
  const x = x1 + (x2 - x1) * p; const y = y1 + (y2 - y1) * p;
  const a = Math.atan2(y2 - y1, x2 - x1);
  const h = 14;
  return (
    <g opacity={p > 0.01 ? 1 : 0}>
      <line x1={x1} y1={y1} x2={x} y2={y} stroke={c} strokeWidth={w} strokeDasharray={dash ? '9 8' : undefined} />
      <polygon fill={c} points={`${x},${y} ${x - h * Math.cos(a - 0.45)},${y - h * Math.sin(a - 0.45)} ${x - h * Math.cos(a + 0.45)},${y - h * Math.sin(a + 0.45)}`} />
    </g>
  );
};

// --------------------------------- bieu tuong -------------------------------
export const Laptop: React.FC<{ c?: string; screen?: React.ReactNode; w?: number }> = ({ c = K.red, screen, w = 220 }) => (
  <div style={{ width: w }}>
    <div style={{ height: w * 0.6, background: '#16181d', borderRadius: '12px 12px 4px 4px', border: `6px solid #3a3d44`, overflow: 'hidden', display: 'flex', alignItems: 'center', justifyContent: 'center', color: c, fontFamily: MONO, fontSize: w * 0.075 }}>{screen}</div>
    <div style={{ height: w * 0.06, margin: '0 -6%', background: 'linear-gradient(#c8ccd3,#9aa0a8)', borderRadius: '0 0 14px 14px' }} />
  </div>
);

export const Server: React.FC<{ w?: number; c?: string }> = ({ w = 170, c = K.ink }) => (
  <div style={{ width: w, display: 'flex', flexDirection: 'column', gap: 8 }}>
    {[0, 1, 2].map((i) => (
      <div key={i} style={{ height: w * 0.26, background: c, borderRadius: 10, display: 'flex', alignItems: 'center', padding: '0 14px', gap: 8 }}>
        <div style={{ width: 10, height: 10, borderRadius: 99, background: i === 0 ? '#5fd39b' : '#7d8bb0' }} />
        <div style={{ flex: 1, height: 5, borderRadius: 3, background: '#3d4a6c' }} />
      </div>
    ))}
  </div>
);

export const Lock: React.FC<{ c?: string; s?: number }> = ({ c = K.green, s = 30 }) => (
  <svg width={s} height={s} viewBox="0 0 24 24"><rect x="4" y="10" width="16" height="11" rx="2" fill={c} /><path d="M8 10V7a4 4 0 0 1 8 0v3" stroke={c} strokeWidth="2.4" fill="none" /></svg>
);

// ---------------------------- o anh / video that -----------------------------
// media.json: { "<ten>": "reel/media/<file>" }. Chua co file -> hien o cho kem mo ta can quay/chup gi.
const M = media as Record<string, string>;
export const MediaSlot: React.FC<{ name: string; need: string; kind: 'ảnh' | 'video'; style?: React.CSSProperties; startFrom?: number }> = ({ name, need, kind, style, startFrom = 0 }) => {
  const frame = useCurrentFrame();
  const src = M[name];
  const box: React.CSSProperties = { borderRadius: 16, overflow: 'hidden', ...style };
  if (src) {
    const isVid = /\.(mp4|mkv|webm|mov)$/i.test(src);
    return (
      <div style={{ ...box, background: '#000', border: `2px solid ${K.line}`, boxShadow: '0 10px 30px rgba(20,30,60,0.12)' }}>
        {isVid
          ? <OffthreadVideo src={staticFile(src)} muted startFrom={startFrom} style={{ width: '100%', height: '100%', objectFit: 'contain' }} />
          : <Img src={staticFile(src)} style={{ width: '100%', height: '100%', objectFit: 'contain', background: '#fff' }} />}
      </div>
    );
  }
  const pulse = 0.65 + 0.35 * Math.sin(frame / 9);
  return (
    <div style={{ ...box, border: `3px dashed ${K.orange}`, background: K.orangeBg, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 14, padding: 30, textAlign: 'center' }}>
      <div style={{ fontFamily: SANS, fontSize: 22, fontWeight: 800, letterSpacing: 2, color: K.orange, opacity: pulse }}>● CHỜ {kind.toUpperCase()} THẬT · {name}</div>
      <div style={{ fontSize: 28, color: K.text, maxWidth: 640, lineHeight: 1.35 }}>{need}</div>
    </div>
  );
};
