import React, { createContext, useContext } from 'react';
import { interpolate, spring, useCurrentFrame, useVideoConfig } from 'remotion';
import script from './script.json';
import timing from './timing.json';

export const FPS = 30;
export const W = 1920;
export const H = 1080;

// Bang mau sang, giong phong cach slide giang bai: nen trang, chu co chan xanh navy, diem nhan xanh la / cam
export const K = {
  bg: '#ffffff',
  bg2: '#f4f6f9',
  ink: '#1d2a48',
  text: '#2c3138',
  mute: '#6b7280',
  faint: '#c9ced6',
  line: '#e3e6eb',
  green: '#2f7d5b',
  greenBg: '#e8f3ee',
  orange: '#c96f1c',
  orangeBg: '#fdf1e4',
  red: '#b83a32',
  redBg: '#fbeceb',
  blue: '#2f62a8',
  blueBg: '#e9f0fa',
  code: '#1e222b',
  codeText: '#d7dce4',
};
export const SERIF = '"Cambria", "Times New Roman", "Noto Serif", serif';
export const SANS = '"Segoe UI", "Noto Sans", Arial, sans-serif';
export const MONO = '"Cascadia Mono", Consolas, "Courier New", monospace';

// ------------------------------ dong thoi gian ------------------------------
type Line = { t: string; say?: string; hold?: number };
type Section = { id: string; label: string; tagline: string; lines: Line[] };
export type LineT = { key: string; text: string; from: number; dur: number };
export type SectionT = { id: string; label: string; tagline: string; index: number; from: number; len: number; lines: LineT[] };

const LEAD = 0.5; // giay im lang dau moi phan
const TAIL = 2.0; // giay giu hinh o cuoi video
const tm = timing as Record<string, { dur: number }>;

export const buildTimeline = () => {
  const secs: SectionT[] = [];
  let cur = 0;
  (script.sections as Section[]).forEach((s, index) => {
    const from = cur;
    let local = Math.round(LEAD * FPS);
    const lines = s.lines.map((l, i) => {
      const key = `${s.id}-${i}`;
      const dur = Math.round((tm[key]?.dur ?? 3) * FPS);
      const item = { key, text: l.t, from: local, dur };
      local += dur + Math.round(script.gapLine * FPS) + Math.round((l.hold ?? 0) * FPS);
      return item;
    });
    local += Math.round((script.gapSection - script.gapLine) * FPS);
    if (index === script.sections.length - 1) local += Math.round(TAIL * FPS);
    secs.push({ id: s.id, label: s.label, tagline: s.tagline, index, from, len: local, lines });
    cur += local;
  });
  return { sections: secs, total: cur };
};

// ------------------------------ ngu canh phan --------------------------------
export const SecCtx = createContext<SectionT | null>(null);
export const useSec = () => {
  const sec = useContext(SecCtx)!;
  const frame = useCurrentFrame();
  let step = -1;
  sec.lines.forEach((l, i) => { if (frame >= l.from) step = i; });
  /** so frame ke tu khi cau i bat dau (+ tre d giay) */
  const since = (i: number, d = 0) => frame - (sec.lines[Math.min(i, sec.lines.length - 1)].from + Math.round(d * FPS));
  return { sec, frame, step, since };
};

/** Hien dan khi toi cau `at` (+ `d` giay). */
export const Reveal: React.FC<{ at: number; d?: number; children: React.ReactNode; style?: React.CSSProperties; from?: 'up' | 'left' | 'right' | 'none' }> = ({ at, d = 0, children, style, from = 'up' }) => {
  const { since } = useSec();
  const { fps } = useVideoConfig();
  const p = spring({ frame: since(at, d), fps, config: { damping: 18, stiffness: 110 } });
  const off = (1 - p) * 26;
  const tr = from === 'up' ? `translateY(${off}px)` : from === 'left' ? `translateX(${-off}px)` : from === 'right' ? `translateX(${off}px)` : '';
  return <div style={{ opacity: p, transform: tr, ...style }}>{children}</div>;
};

/** do sang: dang noi toi (lit) = 1, da qua = 0.45, chua toi = 0 */
export const useFocus = (first: number, last = first) => {
  const { since, step } = useSec();
  const inP = interpolate(since(first), [0, 12], [0, 1], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' });
  const past = step > last;
  const dim = past ? interpolate(since(last + 1), [0, 12], [1, 0.42], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' }) : 1;
  return { opacity: inP * dim, active: step >= first && step <= last, seen: step >= first };
};

export const clamp = { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' } as const;
