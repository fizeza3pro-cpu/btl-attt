import React from 'react';
import { interpolate, Sequence, spring, useVideoConfig } from 'remotion';
import { clamp, K, MONO, SANS, Reveal, useFocus, useSec } from './core';
import { Arrow, Card, Code, Laptop, Lock, MediaSlot, Pill, Server } from './ui';

const SW = 1740; // be rong san khau
const SH = 640;
const PURPLE = '#7a4fb0';
const PURPLE_BG = '#f1ebf8';
const TEAL = '#1f7a8c';
const TEAL_BG = '#e6f3f5';
const abs = (l: number, t: number, w?: number, h?: number): React.CSSProperties => ({ position: 'absolute', left: l, top: t, width: w, height: h });
const H3: React.FC<{ children: React.ReactNode; c?: string; s?: number }> = ({ children, c = K.ink, s = 34 }) => <div style={{ fontSize: s, fontWeight: 700, color: c }}>{children}</div>;
const Small: React.FC<{ children: React.ReactNode; c?: string; s?: number }> = ({ children, c = K.mute, s = 24 }) => <div style={{ fontSize: s, color: c, marginTop: 6, lineHeight: 1.35 }}>{children}</div>;

/** Hien trong khoang cau [a, b] (b = -1: toi het phan), mo dan vao/ra */
const Swap: React.FC<{ a: number; b?: number; children: React.ReactNode; style?: React.CSSProperties }> = ({ a, b = -1, children, style }) => {
  const { since, sec } = useSec();
  const inO = interpolate(since(a), [0, 12], [0, 1], clamp);
  const outO = b < 0 || b >= sec.lines.length - 1 ? 1 : interpolate(since(b + 1), [0, 10], [1, 0], clamp);
  const o = inO * outO;
  if (o <= 0.001) return null;
  return <div style={{ position: 'absolute', inset: 0, opacity: o, ...style }}>{children}</div>;
};

const Spoof: React.FC<{ real?: boolean; s?: number }> = ({ real, s = 30 }) => real ? <Lock s={s} /> : <span style={{ fontSize: s, color: K.orange, lineHeight: 1 }}>⇄</span>;

// ================================ 0. MO DAU =================================
const Intro: React.FC = () => {
  const { since, step } = useSec();
  const attacks = ['quét cổng', 'dò mật khẩu', 'SQL injection'];
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      <div style={abs(120, 140)}>
        <Reveal at={0} from="left"><Laptop w={300} screen={<span>$ nmap -sT 10.77.0.20</span>} /></Reveal>
        <Reveal at={0} d={0.3}><div style={{ textAlign: 'center', marginTop: 18, fontSize: 28, color: K.red, fontWeight: 700 }}>Kẻ tấn công</div></Reveal>
      </div>
      <svg width={SW} height={SH} style={abs(0, 0)}>
        {attacks.map((a, i) => (
          <Arrow key={a} x1={470} y1={200 + i * 70} x2={1150} y2={250 + i * 30} c={K.red} p={interpolate(since(0, 0.4 + i * 0.5), [0, 20], [0, 1], clamp)} />
        ))}
      </svg>
      {attacks.map((a, i) => (
        <Reveal key={a} at={0} d={0.6 + i * 0.5} style={abs(640, 150 + i * 60)}>
          <Pill c={K.red} bg={K.redBg} size={22}>{a}</Pill>
        </Reveal>
      ))}
      <div style={abs(1200, 150)}>
        <Reveal at={0}><Server w={230} /></Reveal>
        <Reveal at={0} d={0.3}><div style={{ textAlign: 'center', marginTop: 18, fontSize: 28, color: K.ink, fontWeight: 700 }}>Máy chủ web</div></Reveal>
      </div>
      <Reveal at={1} style={abs(1460, 90)}>
        <div style={{ fontSize: 150, fontWeight: 700, color: K.orange, lineHeight: 1 }}>?</div>
      </Reveal>
      <Reveal at={2} style={abs(470, 380, 800)}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontFamily: SANS, fontSize: 22, color: K.mute, letterSpacing: 2 }}>BÀI TẬP LỚN</div>
          <div style={{ fontSize: 56, fontWeight: 700, color: K.ink }}>Mini-SOC</div>
          <div style={{ fontSize: 26, color: K.mute }}>Security Operations Center thu nhỏ</div>
        </div>
      </Reveal>
      <div style={{ ...abs(0, 575, SW), display: 'flex', justifyContent: 'center', gap: 26, opacity: step >= 3 ? 1 : 0 }}>
        {[['Phát hiện', K.blue, K.blueBg], ['Phản ứng', K.orange, K.orangeBg], ['Không ảnh hưởng người dùng thật', K.green, K.greenBg]].map(([t, c, bg], i) => (
          <Reveal key={t} at={3} d={0.4 + i * 0.7}><Pill c={c} bg={bg} size={26}>{`${i + 1}. ${t}`}</Pill></Reveal>
        ))}
      </div>
    </div>
  );
};

// ================================ 1. VAN DE =================================
const Problem: React.FC = () => {
  const cards = [
    { at: 1, t: 'Báo nhầm', d: 'chặn nhầm khách hàng thật', c: K.orange, bg: K.orangeBg, ic: '⚠' },
    { at: 2, t: 'Giả mạo IP', d: 'bị lừa chặn một máy vô tội', c: K.red, bg: K.redBg, ic: '⇄' },
  ];
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      <Reveal at={0} style={abs(0, 10, SW)}>
        <div style={{ display: 'flex', justifyContent: 'center', gap: 60, alignItems: 'center' }}>
          <Card c={K.green} bg={K.greenBg} style={{ width: 420, textAlign: 'center' }}><H3 c={K.green}>Phát hiện ✓</H3><Small>nhiều công cụ làm được</Small></Card>
          <div style={{ fontSize: 50, color: K.mute }}>→</div>
          <Card c={K.orange} bg={K.orangeBg} style={{ width: 420, textAlign: 'center' }}><H3 c={K.orange}>Phản ứng ?</H3><Small>mới là phần khó</Small></Card>
        </div>
      </Reveal>
      <div style={{ ...abs(0, 210, SW), display: 'flex', justifyContent: 'center', gap: 60 }}>
        {cards.map((x) => (
          <Reveal key={x.t} at={x.at}>
            <Card c={x.c} style={{ width: 520, display: 'flex', gap: 22, alignItems: 'center' }}>
              <div style={{ width: 76, height: 76, borderRadius: 99, background: x.bg, color: x.c, fontSize: 42, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{x.ic}</div>
              <div><H3 c={x.c}>{x.t}</H3><Small>→ {x.d}</Small></div>
            </Card>
          </Reveal>
        ))}
      </div>
      <div style={{ ...abs(0, 430, SW), display: 'flex', justifyContent: 'center', gap: 34 }}>
        {['Chặn khi nào?', 'Chặn ai?', 'Chặn bao lâu?'].map((q, i) => (
          <Reveal key={q} at={3} d={0.9 + i * 0.6}>
            <div style={{ fontSize: 44, fontWeight: 700, color: K.ink, padding: '14px 34px', borderBottom: `5px solid ${K.green}` }}>{q}</div>
          </Reveal>
        ))}
      </div>
    </div>
  );
};

// ================================ 2. MO HINH ================================
const Host: React.FC<{ n: string; ip: string; role: string; c: string; bg: string; first: number; has: string[]; job: string }> = ({ n, ip, role, c, bg, first, has, job }) => {
  const f = useFocus(first, first);
  return (
    <div style={{ opacity: f.seen ? Math.max(f.opacity, 0.55) : 0.18 }}>
      <Card c={f.active ? c : K.line} bg={f.active ? bg : '#fff'} glow={f.active} style={{ width: 500, height: 300 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline' }}>
          <div style={{ fontSize: 46, fontWeight: 700, color: c }}>Máy {n}</div>
          <div style={{ fontFamily: MONO, fontSize: 22, color: K.mute }}>{ip}</div>
        </div>
        <div style={{ fontSize: 30, color: c, fontWeight: 700, marginTop: 4 }}>{role}</div>
        <div style={{ fontSize: 24, color: K.text, marginTop: 8, lineHeight: 1.35, opacity: f.seen ? 1 : 0 }}>{job}</div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 14, opacity: f.seen ? 1 : 0 }}>{has.map((e) => <Pill key={e} c={K.ink} bg={K.bg2} size={18}>{e}</Pill>)}</div>
      </Card>
    </div>
  );
};
const Lab: React.FC = () => {
  const { since } = useSec();
  const p = interpolate(since(0), [0, 24], [0, 1], clamp);
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      <svg width={SW} height={SH} style={abs(0, 0)}>
        {[250, 870, 1490].map((x) => <line key={x} x1={x} y1={330} x2={x} y2={330 + 120 * p} stroke={K.ink} strokeWidth={4} />)}
        <rect x={140} y={450} width={(SW - 280) * p} height={14} rx={7} fill={K.ink} />
      </svg>
      <div style={{ ...abs(0, 30, SW), display: 'flex', justifyContent: 'space-between' }}>
        <Host n="A" ip="10.77.0.10" role="Kẻ tấn công" job="dò quét, gửi yêu cầu tấn công vào máy chủ" has={['nmap', 'curl']} c={K.red} bg={K.redBg} first={1} />
        <Host n="B" ip="10.77.0.20" role="Máy chủ" job="chạy web bán hàng + hệ thống giám sát, phát hiện, phản ứng" has={['Lab Shop', 'Suricata', 'tường lửa', 'honeypot', 'dashboard']} c={K.ink} bg={K.blueBg} first={2} />
        <Host n="C" ip="10.77.0.30" role="Khách hàng thật" job="vào web, thêm giỏ hàng, đặt hàng — luôn phải dùng được" has={['trình duyệt']} c={K.green} bg={K.greenBg} first={3} />
      </div>
      <div style={{ ...abs(0, 480, SW), textAlign: 'center', opacity: p }}>
        <div style={{ fontFamily: MONO, fontSize: 30, color: K.ink, fontWeight: 700 }}>Mạng nội bộ · 10.77.0.0/24</div>
        <div style={{ fontSize: 26, color: K.mute, marginTop: 6 }}>cô lập · không kết nối Internet</div>
      </div>
    </div>
  );
};

// ================================ 3. CONG CU ================================
const tools = [
  { n: 'nmap', on: 'máy A', why: 'quét cổng: dò xem máy chủ mở những cổng nào', f: 1, c: K.red },
  { n: 'curl', on: 'máy A', why: 'gửi yêu cầu web: thử đường dẫn nhạy cảm, SQL injection', f: 2, c: K.red },
  { n: 'Nginx', on: 'máy B', why: 'chạy web bán hàng, giới hạn số yêu cầu mỗi giây', f: 3, c: K.green },
  { n: 'Suricata', on: 'máy B', why: '“camera” mạng: đọc gói tin, so luật, ghi cảnh báo', f: 4, c: K.orange },
  { n: 'nftables', on: 'máy B', why: 'tường lửa: chặn / chuyển hướng IP, có thời hạn', f: 5, c: K.blue },
  { n: 'systemd', on: 'máy B', why: 'giữ chương trình luôn chạy, mỗi cái ít quyền nhất', f: 6, c: K.ink },
  { n: 'MITRE ATT&CK', on: 'báo cáo', why: 'từ điển chung gọi tên kỹ thuật tấn công', f: 7, c: PURPLE },
];
const ToolCard: React.FC<{ x: typeof tools[number] }> = ({ x }) => {
  const { step } = useSec();
  const f = useFocus(x.f, x.f);
  const o = step < 0 ? 0 : !f.seen ? 0.28 : f.active ? 1 : 0.55;
  return (
    <div style={{ opacity: o, transform: `scale(${f.active ? 1.04 : 1})` }}>
      <Card c={f.active ? x.c : K.line} glow={f.active} style={{ height: 196, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ fontSize: 38, fontWeight: 700, color: x.c }}>{x.n}</div>
          <Pill c={K.mute} bg={K.bg2} size={17}>{x.on}</Pill>
        </div>
        <div style={{ fontSize: 25, lineHeight: 1.35, color: K.text, opacity: f.seen ? 1 : 0 }}>{x.why}</div>
      </Card>
    </div>
  );
};
const Tools: React.FC = () => (
  <Reveal at={0} d={0.2}>
    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 28, width: SW, paddingTop: 30 }}>
      {tools.map((x) => <ToolCard key={x.n} x={x} />)}
    </div>
  </Reveal>
);

// ================================ 4. THANH PHAN =============================
type PartId = 'shop' | 'rules' | 'honey' | 'gen' | 'an' | 'blk' | 'soc';
const PARTS: { id: PartId; n: string; s: string; c: string; bg: string }[] = [
  { id: 'shop', n: 'Lab Shop', s: 'web mô phỏng · log đăng nhập', c: K.green, bg: K.greenBg },
  { id: 'rules', n: 'Bộ luật Suricata', s: '13 luật viết tay · cảnh báo', c: K.orange, bg: K.orangeBg },
  { id: 'honey', n: 'Honeypot', s: 'bẫy · xác nhận kẻ tấn công', c: PURPLE, bg: PURPLE_BG },
  { id: 'gen', n: 'Bộ tự sinh luật', s: 'học luật mới từ kẻ tấn công', c: TEAL, bg: TEAL_BG },
  { id: 'an', n: 'Bộ phân tích', s: 'cộng điểm · quyết định', c: K.blue, bg: K.blueBg },
  { id: 'blk', n: 'Lệnh chặn', s: 'tường lửa · có thời hạn', c: K.red, bg: K.redBg },
  { id: 'soc', n: 'Dashboard', s: 'người vận hành duyệt', c: K.ink, bg: K.bg2 },
];
const PW = 430; const PH = 118;
const PPOS: Record<PartId, [number, number]> = {
  shop: [0, 0], rules: [0, 175], honey: [0, 350], gen: [650, 500], an: [650, 175], blk: [1300, 60], soc: [1300, 300],
};
const Parts: React.FC = () => {
  const { since, step } = useSec();
  const g = (i: number, d = 0) => interpolate(since(i, d), [0, 18], [0, 1], clamp);
  const lit = (id: PartId) => (step === 1 && ['shop', 'rules', 'honey', 'an'].includes(id)) || (step === 2 && id === 'soc');
  const mid = (id: PartId, side: 'l' | 'r' | 't' | 'b') => {
    const [x, y] = PPOS[id];
    return side === 'l' ? [x, y + PH / 2] : side === 'r' ? [x + PW, y + PH / 2] : side === 't' ? [x + PW / 2, y] : [x + PW / 2, y + PH];
  };
  const A = (a: number[], b: number[], c: string, p: number, dash?: boolean) => <Arrow x1={a[0] + 6} y1={a[1]} x2={b[0] - 8} y2={b[1]} c={c} p={p} dash={dash} />;
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      <svg width={SW} height={SH} style={abs(0, 0)}>
        {(['shop', 'rules', 'honey'] as PartId[]).map((id, i) => <React.Fragment key={id}>{A(mid(id, 'r'), [PPOS.an[0], PPOS.an[1] + 30 + i * 30], K.faint, g(0, 2 + i * 0.3))}</React.Fragment>)}
        <Arrow x1={PW + 6} y1={PPOS.honey[1] + PH - 20} x2={PPOS.gen[0] - 8} y2={PPOS.gen[1] + PH / 2} c={TEAL} p={g(0, 3)} />
        <Arrow x1={PPOS.gen[0] + 60} y1={PPOS.gen[1]} x2={PW - 40} y2={PPOS.rules[1] + PH + 6} c={TEAL} p={g(0, 3.4)} dash />
        {A(mid('an', 'r'), mid('blk', 'l'), K.red, g(0, 3.8))}
        {A(mid('an', 'r'), mid('soc', 'l'), K.ink, g(0, 4.1))}
      </svg>
      <Reveal at={0} d={3.4} style={abs(PPOS.gen[0] - 150, PPOS.gen[1] - 40)}><span style={{ fontSize: 21, color: TEAL, fontFamily: SANS, fontWeight: 700 }}>luật mới</span></Reveal>
      {PARTS.map((p, i) => {
        const [x, y] = PPOS[p.id];
        const on = lit(p.id);
        return (
          <Reveal key={p.id} at={0} d={0.3 + i * 0.35} style={abs(x, y, PW)}>
            <Card c={on ? p.c : p.c + '88'} bg={on ? p.bg : '#fff'} glow={on} style={{ height: PH, padding: '14px 22px' }}>
              <H3 c={p.c} s={32}>{p.n}</H3>
              <Small s={22}>{p.s}</Small>
            </Card>
          </Reveal>
        );
      })}
      <Reveal at={0} d={2} style={abs(0, 560, PW)}><div style={{ fontSize: 22, color: K.mute, fontFamily: SANS }}>tất cả chạy trên <b style={{ color: K.ink }}>máy chủ B</b></div></Reveal>
    </div>
  );
};

/** Ban do nho ben trai: cac thanh phan, to sang phan dang trinh bay (hieu ung "quay lai" so do chung) */
const MiniMap: React.FC<{ hl: PartId[] }> = ({ hl }) => {
  const { frame } = useSec();
  const { fps } = useVideoConfig();
  return (
    <div style={{ ...abs(0, 0, 360), display: 'flex', flexDirection: 'column', gap: 12 }}>
      {PARTS.map((p, i) => {
        const on = hl.includes(p.id);
        const s = spring({ frame: frame - i * 2, fps, config: { damping: 18 } });
        return (
          <div key={p.id} style={{ opacity: s * (on ? 1 : 0.45), transform: `translateX(${(1 - s) * -40}px)` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '11px 18px', borderRadius: 14, border: `2px solid ${on ? p.c : K.line}`, background: on ? p.bg : '#fff', boxShadow: on ? `0 0 0 5px ${p.c}22` : 'none' }}>
              <div style={{ width: 14, height: 14, borderRadius: 99, background: p.c, flexShrink: 0 }} />
              <div style={{ fontSize: 26, fontWeight: 700, color: on ? p.c : K.mute }}>{p.n}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
};
const PX = 420; // le trai cua khung chi tiet
const PWID = SW - PX;
const Panel: React.FC<{ children: React.ReactNode }> = ({ children }) => <div style={abs(PX, 0, PWID, SH)}>{children}</div>;

// ---------------------------- 4a. Lab Shop & bo luat -------------------------
const ruleGroups = [
  { t: 'Dò quét cổng', c: K.orange, bg: K.orangeBg, rows: [['SYN dồn dập (10 s)', 20, false], ['nhiều RST/ACK (10 s)', 50, false], ['RST/ACK quét chậm (60 s)', 50, false]] },
  { t: 'Tấn công web', c: K.red, bg: K.redBg, rows: [['vào /admin, /lab-admin', 70, true], ['SQL injection', 50, true], ['XSS', 50, true], ['dò đường dẫn ../', 50, true]] },
  { t: 'Dò mật khẩu', c: K.blue, bg: K.blueBg, rows: [['≥ 5 lần 401 trong 60 s', 50, true]] },
] as const;
const Shop: React.FC = () => {
  const { step } = useSec();
  return (
    <>
      <MiniMap hl={step < 1 ? ['shop'] : ['rules']} />
      <Panel>
        <Swap a={0} b={0}>
          <div style={{ display: 'flex', gap: 40 }}>
            <MediaSlot name="lab-shop" kind="ảnh" need="Ảnh chụp trang chủ Lab Shop (mở từ máy C)" style={{ width: 820, height: 500 }} />
            <div style={{ display: 'flex', flexDirection: 'column', gap: 18, paddingTop: 20 }}>
              <H3 c={K.green}>Lab Shop</H3>
              <Small s={26}>web bán hàng dựng để mô phỏng cho kịch bản</Small>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>{['sản phẩm', 'giỏ hàng', 'đăng nhập', 'thanh toán'].map((x) => <Pill key={x} c={K.green} bg={K.greenBg} size={20}>{x}</Pill>)}</div>
              <Card c={K.red} bg={K.redBg} style={{ marginTop: 20 }}><H3 c={K.red} s={28}>mục tiêu của kẻ tấn công</H3></Card>
            </div>
          </div>
        </Swap>
        <Swap a={1}>
          <Reveal at={1}><div style={{ fontSize: 30, color: K.text, marginBottom: 20 }}>Suricata = bộ máy · <b style={{ color: K.orange }}>luật</b> = định nghĩa thế nào là tấn công</div></Reveal>
          <div style={{ display: 'flex', gap: 24 }}>
            {ruleGroups.map((g, gi) => (
              <Reveal key={g.t} at={2} d={gi * 0.9}>
                <Card c={g.c} style={{ width: 420, padding: '16px 20px' }}>
                  <H3 c={g.c} s={30}>{g.t}</H3>
                  {g.rows.map(([n, pts, real]) => (
                    <div key={n} style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 12, fontSize: 24 }}>
                      <div style={{ flex: 1 }}>{n}</div>
                      <Reveal at={3} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontFamily: MONO, fontWeight: 700, color: g.c }}>+{pts}</span>
                        <Spoof real={real} s={26} />
                      </Reveal>
                    </div>
                  ))}
                </Card>
              </Reveal>
            ))}
          </div>
          <Reveal at={3} d={0.8} style={{ marginTop: 26, display: 'flex', gap: 30, fontSize: 25, alignItems: 'center' }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Spoof s={28} /> địa chỉ nguồn có thể bị giả mạo</span>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8 }}><Spoof real s={28} /> cần kết nối thật, không giả mạo được</span>
          </Reveal>
        </Swap>
      </Panel>
    </>
  );
};

// ---------------------------- 4b. Honeypot (+ danh lua) ---------------------
const Honey: React.FC = () => {
  const { since } = useSec();
  const p = interpolate(since(4, 0.4), [0, 20], [0, 1], clamp);
  return (
    <>
      <MiniMap hl={['honey']} />
      <Panel>
        <Swap a={0} b={3}>
          <Reveal at={1} from="left" style={abs(0, 0, 780)}>
            <Code title="mã nguồn Lab Shop — bẫy gài sẵn" size={21} lines={[
              { s: '<!-- index.html -->' },
              { s: '<!-- TODO(dev): tai khoan quan tri tam thoi' },
              { s: '     admin / LabShop@2026!  ... -->', hl: K.orange },
              { s: '' },
              { s: '// shop.js' },
              { s: "// const ADMIN_API_KEY = 'ls_live_7f3a…';", hl: K.orange },
              { s: '' },
              { s: '# robots.txt' },
              { s: 'Disallow: /backup/', hl: K.orange },
            ]} />
          </Reveal>
          <Reveal at={0} style={abs(840, 0, 480)}>
            <Card c={PURPLE} bg={PURPLE_BG}><H3 c={PURPLE}>Honeypot</H3><Small s={25}>những cái bẫy · không có chức năng thật · chỉ ghi lại kẻ tấn công làm gì</Small></Card>
          </Reveal>
          <Reveal at={2} style={abs(840, 210, 480)}>
            <div style={{ fontSize: 24, color: K.mute, marginBottom: 10 }}>cổng giả</div>
            <div style={{ display: 'flex', gap: 12 }}>{[['23', 'telnet'], ['2222', 'SSH'], ['3306', 'MySQL']].map(([p2, n]) => (
              <Card key={p2} c={PURPLE} style={{ padding: '10px 16px', textAlign: 'center', width: 140 }}><div style={{ fontFamily: MONO, fontSize: 30, fontWeight: 700, color: PURPLE }}>{p2}</div><div style={{ fontSize: 21 }}>{n}</div></Card>
            ))}</div>
          </Reveal>
          <Reveal at={3} style={abs(0, 440, 1320)}>
            <Card c={K.green} bg={K.greenBg} style={{ display: 'flex', alignItems: 'center', gap: 24 }}>
              <div style={{ fontSize: 30, fontWeight: 700, color: K.green }}>Khách hàng thật: 0 lần chạm bẫy</div>
              <div style={{ fontSize: 26 }}>→ ai chạm bẫy gần như chắc chắn là kẻ tấn công</div>
            </Card>
          </Reveal>
        </Swap>
        <Swap a={4}>
          <div style={{ position: 'relative', height: 300 }}>
            <div style={abs(0, 20)}><Pill c={K.red} bg={K.redBg} size={24}>A · kẻ tấn công</Pill></div>
            <div style={abs(0, 210)}><Pill c={K.green} bg={K.greenBg} size={24}>C · khách hàng</Pill></div>
            <div style={abs(300, 105, 190)}><Card c={K.ink} style={{ padding: '10px 14px', textAlign: 'center' }}><div style={{ fontSize: 24, fontWeight: 700 }}>tường lửa</div></Card></div>
            <div style={abs(580, 0, 330)}><Card c={K.orange} bg={K.orangeBg} style={{ padding: '10px 16px' }}><div style={{ fontSize: 26, fontWeight: 700, color: K.orange }}>Bản sao Lab Shop</div><div style={{ fontSize: 21 }}>trang chủ y hệt · /admin là GIẢ</div></Card></div>
            <div style={abs(580, 200, 330)}><Card c={K.green} style={{ padding: '10px 16px' }}><div style={{ fontSize: 26, fontWeight: 700, color: K.green }}>Lab Shop thật</div><div style={{ fontSize: 21 }}>/admin → 403</div></Card></div>
            <svg width={920} height={300} style={abs(0, 0)}>
              <Arrow x1={215} y1={40} x2={296} y2={120} c={K.red} p={p} />
              <Arrow x1={490} y1={120} x2={576} y2={50} c={K.red} p={p} />
              <Arrow x1={215} y1={230} x2={296} y2={150} c={K.green} p={p} />
              <Arrow x1={490} y1={150} x2={576} y2={240} c={K.green} p={p} />
            </svg>
            <Reveal at={4} d={2.5} style={abs(940, 0, 380)}>
              <MediaSlot name="admin-gia" kind="ảnh" need="Trang /admin GIẢ mà máy A thấy khi đang bị đánh lừa" style={{ width: 380, height: 280 }} />
            </Reveal>
          </div>
          <Reveal at={4} d={4} style={abs(0, 320, 760)}>
            <Code title="honeypot ghi lại" size={19} lines={[
              { s: '{"src_ip":"10.77.0.10", "kind":"honeypot_admin_login",', hl: K.orange },
              { s: ' "user":"root", "password":"123456"}' },
              { s: '{"src_ip":"10.77.0.10", "kind":"honeytoken_creds"}', hl: K.red },
            ]} />
          </Reveal>
          <Reveal at={5} from="right" style={abs(800, 330, 520)}>
            <Card c={TEAL} bg={TEAL_BG}>
              <H3 c={TEAL} s={30}>10.77.0.10 = kẻ tấn công ✓</H3>
              <Small s={24}>honeypot xác nhận → dùng để học luật mới →</Small>
            </Card>
          </Reveal>
        </Swap>
      </Panel>
    </>
  );
};

// ---------------------------- 4c. Bo tu sinh luat --------------------------
const probes = ['/.env', '/.env.bak', '/.env.local', '/.git/config', '/.git/HEAD', '/wp-login.php', '/wp-admin/', '/phpmyadmin/', '/phpMyAdmin/index.php'];
const realPages = ['/index.html', '/cart.html?id=999', '/api/products?id=1'];
const families = [['/.env', 3], ['/.git/', 2], ['/wp-', 2], ['/phpmyadmin', 2]] as const;
const gates = ['Cú pháp đúng', 'Bắt được mẫu tấn công', 'Không báo nhầm khách thật', 'An toàn', 'Không trùng luật cũ'];
const variants = [['/.env.production', true], ['/.ENV.dev', true], ['/%2e%65nv', true], ['/wp-json/wp/v2/users', true], ['/about.html', false]] as const;
const RuleGen: React.FC = () => {
  const { step, since } = useSec();
  return (
    <>
      <MiniMap hl={['gen']} />
      <Panel>
        <Swap a={0} b={2}>
          <div style={abs(0, 0, 520)}>
            <div style={{ fontSize: 24, color: K.mute, marginBottom: 8 }}>yêu cầu của A</div>
            {probes.map((x, i) => (
              <Reveal key={x} at={0} d={0.3 + i * 0.25} from="left">
                <div style={{ display: 'flex', justifyContent: 'space-between', fontFamily: MONO, fontSize: 23, padding: '4px 0', borderBottom: `1px solid ${K.line}` }}>
                  <span>{x}</span><span style={{ color: K.mute, fontFamily: SANS, fontSize: 19 }}>không cảnh báo</span>
                </div>
              </Reveal>
            ))}
            <Reveal at={1} d={2}>
              {realPages.map((x) => (
                <div key={x} style={{ fontFamily: MONO, fontSize: 21, color: K.mute, textDecoration: 'line-through', padding: '3px 0' }}>{x} <span style={{ fontFamily: SANS, textDecoration: 'none' }}>· trang thật, bỏ qua</span></div>
              ))}
            </Reveal>
          </div>
          <Reveal at={1} style={abs(600, 0, 720)}>
            <Card c={TEAL} bg={TEAL_BG} style={{ display: 'flex', alignItems: 'center', gap: 18 }}>
              <Lock c={TEAL} s={36} />
              <div><H3 c={TEAL} s={28}>chỉ học từ kẻ tấn công đã bị honeypot xác nhận</H3></div>
            </Card>
          </Reveal>
          <div style={{ ...abs(600, 150, 720), display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 18 }}>
            {families.map(([f, n], i) => (
              <Reveal key={f} at={2} d={0.4 + i * 0.6}>
                <Card c={TEAL} style={{ padding: '14px 20px' }}>
                  <div style={{ fontSize: 20, color: K.mute }}>phần chung</div>
                  <div style={{ fontFamily: MONO, fontSize: 36, fontWeight: 700, color: TEAL }}>{f}</div>
                  <div style={{ fontSize: 21, color: K.mute }}>học từ {n} đường dẫn</div>
                </Card>
              </Reveal>
            ))}
          </div>
        </Swap>
        <Swap a={3} b={4}>
          <Reveal at={3}>
            <Code title="luật sinh ra từ khuôn cố định" size={20} lines={[
              { s: 'alert http any any -> $HOME_NET any (' },
              { s: '  msg:"LAB AUTO uri probe /.env";' },
              { s: '  flow:established,to_server;' },
              { s: '  http.uri; content:"/.env"; nocase; startswith;', hl: TEAL },
              { s: '  metadata:generated_by lab-rulegen;' },
              { s: '  sid:5000000; rev:1;)' },
            ]} />
          </Reveal>
          <div style={{ display: 'flex', gap: 14, marginTop: 34 }}>
            {gates.map((g, i) => {
              const ok = since(4, 0.6 + i * 0.9) > 0;
              return (
                <Reveal key={g} at={4} d={0.3 + i * 0.9} style={{ flex: 1 }}>
                  <Card c={ok ? K.green : K.line} bg={ok ? K.greenBg : '#fff'} style={{ padding: '14px 14px', textAlign: 'center', height: 150 }}>
                    <div style={{ fontFamily: SANS, fontSize: 20, color: K.mute, fontWeight: 700 }}>BƯỚC {i + 1}</div>
                    <div style={{ fontSize: 24, fontWeight: 700, marginTop: 6, lineHeight: 1.25 }}>{g}</div>
                    <div style={{ fontSize: 34, color: K.green, marginTop: 4 }}>{ok ? '✓' : ''}</div>
                  </Card>
                </Reveal>
              );
            })}
          </div>
        </Swap>
        <Swap a={5}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
            {[['Chờ duyệt', 'trên dashboard', K.orange], ['Người vận hành duyệt', 'bấm “Duyệt & nạp”', K.ink], ['Nạp vào Suricata', '~1 giây · không dừng giám sát', TEAL]].map(([t, s, c], i) => (
              <React.Fragment key={t}>
                <Reveal at={5} d={i * 1.2}><Card c={c} style={{ width: 380, textAlign: 'center' }}><H3 c={c} s={30}>{t}</H3><Small>{s}</Small></Card></Reveal>
                {i < 2 && <Reveal at={5} d={i * 1.2 + 0.6}><div style={{ fontSize: 40, color: K.mute }}>→</div></Reveal>}
              </React.Fragment>
            ))}
          </div>
          <Reveal at={5} d={3.4} style={{ marginTop: 18 }}>
            <div style={{ fontSize: 30 }}>Suricata: <b style={{ fontFamily: MONO }}>13</b> → <b style={{ fontFamily: MONO, color: TEAL }}>17</b> luật</div>
          </Reveal>
          <div style={{ marginTop: 26, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '10px 40px', width: 1200 }}>
            {variants.map(([v, hit], i) => (
              <Reveal key={v} at={6} d={0.3 + i * 0.5} from="left">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 18px', borderRadius: 12, border: `2px solid ${hit ? K.red : K.green}`, background: hit ? K.redBg : K.greenBg }}>
                  <span style={{ fontFamily: MONO, fontSize: 25 }}>{v}</span>
                  <span style={{ fontSize: 23, fontWeight: 700, color: hit ? K.red : K.green }}>{hit ? 'CẢNH BÁO' : 'trang thật · bỏ qua'}</span>
                </div>
              </Reveal>
            ))}
          </div>
        </Swap>
      </Panel>
      {step < 0 ? null : null}
    </>
  );
};

// ---------------------------- 4d. Bo phan tich (hoat anh rieng) -------------
const ladder = [
  { t: 'dưới 50', d: 'chỉ ghi log', c: K.mute },
  { t: '50 – 99', d: 'ghi thành sự cố', c: K.blue },
  { t: '≥ 100, toàn tín hiệu ⇄', d: 'nghi giả mạo · không phản ứng', c: K.orange },
  { t: '≥ 100, có tín hiệu thật', d: 'tự động ĐÁNH LỪA', c: PURPLE },
  { t: 'bị đánh lừa vẫn cắn câu', d: 'chờ người duyệt CHẶN TOÀN BỘ', c: K.red },
];
const events = [
  { at: 2, d: 0.3, t: 'SYN dồn dập (quét nhanh)', pts: 20, real: false },
  { at: 2, d: 3.2, t: 'máy chủ trả nhiều RST/ACK', pts: 50, real: false },
  { at: 4, d: 0.8, t: 'kết nối cổng bẫy 23', pts: 40, real: true },
  { at: 6, d: 1.5, t: 'đăng nhập bằng tài khoản bẫy', pts: 100, real: true },
];
const Analyzer: React.FC = () => {
  const { since, step } = useSec();
  const MAX = 240;
  let score = 0;
  events.forEach((e) => { score += e.pts * interpolate(since(e.at, e.d), [0, 15], [0, 1], clamp); });
  const active = step >= 6 && since(6, 2.5) > 0 ? 4 : step >= 5 ? 3 : step >= 3 ? 1 : -1;
  const barH = 470;
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      {/* nguon vao */}
      <Reveal at={0} style={abs(0, 0, 1000)}>
        <div style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
          <Pill c={K.orange} bg={K.orangeBg} size={21}>Suricata</Pill>
          <Pill c={PURPLE} bg={PURPLE_BG} size={21}>honeypot</Pill>
          <Pill c={K.green} bg={K.greenBg} size={21}>log đăng nhập</Pill>
          <span style={{ fontSize: 30, color: K.mute }}>→</span>
          <Pill c={K.blue} bg={K.blueBg} size={21}>Bộ phân tích</Pill>
        </div>
      </Reveal>
      {/* nhat ky su kien */}
      <Reveal at={1} style={abs(0, 80, 600)}>
        <div style={{ fontSize: 24, color: K.mute }}>sự kiện của <b style={{ fontFamily: MONO, color: K.ink }}>10.77.0.10</b> · cửa sổ 120 giây</div>
      </Reveal>
      <div style={{ ...abs(0, 130, 600), display: 'flex', flexDirection: 'column', gap: 14 }}>
        {events.map((e) => (
          <Reveal key={e.t} at={e.at} d={e.d} from="left">
            <Card c={e.real ? K.green : K.orange} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '12px 18px' }}>
              <div style={{ fontFamily: MONO, fontSize: 32, fontWeight: 700, color: e.real ? K.green : K.orange, width: 90 }}>+{e.pts}</div>
              <div style={{ flex: 1, fontSize: 26 }}>{e.t}</div>
              <Spoof real={e.real} s={30} />
            </Card>
          </Reveal>
        ))}
      </div>
      {/* thanh diem */}
      <Reveal at={1} style={abs(680, 60, 260, 560)}>
        <div style={{ position: 'relative', width: 260, height: 560 }}>
          <div style={{ ...abs(80, 20, 90, barH), background: K.bg2, border: `2px solid ${K.line}`, borderRadius: 16, overflow: 'hidden' }}>
            <div style={{ position: 'absolute', bottom: 0, left: 0, right: 0, height: `${(score / MAX) * 100}%`, background: score >= 100 ? (step >= 6 ? K.red : PURPLE) : score >= 50 ? K.blue : K.mute }} />
          </div>
          {[50, 100].map((m) => (
            <div key={m} style={{ ...abs(60, 20 + barH - (m / MAX) * barH, 200), borderTop: `3px dashed ${m === 100 ? K.red : K.blue}` }}>
              <span style={{ position: 'absolute', left: 205, top: -16, fontFamily: MONO, fontSize: 22, color: m === 100 ? K.red : K.blue, fontWeight: 700 }}>{m}</span>
            </div>
          ))}
          <div style={{ ...abs(0, 20 + barH + 10, 250), textAlign: 'center' }}>
            <span style={{ fontFamily: MONO, fontSize: 48, fontWeight: 700, color: K.ink }}>{Math.round(score)}</span>
            <span style={{ fontSize: 24, color: K.mute }}> điểm</span>
          </div>
        </div>
      </Reveal>
      {/* bac thang quyet dinh */}
      <div style={{ ...abs(1000, 60, 740), display: 'flex', flexDirection: 'column', gap: 14 }}>
        {ladder.map((l, i) => {
          const on = i === active;
          return (
            <Reveal key={l.t} at={1} d={0.5 + i * 0.25} from="right">
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '14px 20px', borderRadius: 14, border: `2px solid ${on ? l.c : K.line}`, background: on ? `${l.c}18` : '#fff', boxShadow: on ? `0 0 0 6px ${l.c}22` : 'none', transform: `scale(${on ? 1.03 : 1})` }}>
                <div style={{ width: 300, fontSize: 25, fontWeight: 700, color: l.c }}>{l.t}</div>
                <div style={{ fontSize: 25, color: K.text }}>{l.d}</div>
              </div>
            </Reveal>
          );
        })}
      </div>
    </div>
  );
};

// ---------------------------- 4e. Chan ---------------------------------------
const sets = [
  { n: 'Đánh lừa', how: 'cổng 80 của IP → bản sao', ttl: '10 phút', sec: 600, c: PURPLE, bg: PURPLE_BG, who: 'tự động' },
  { n: 'Chặn web', how: 'chặn cổng 80', ttl: '60 giây', sec: 60, c: K.orange, bg: K.orangeBg, who: 'tự động' },
  { n: 'Chặn toàn bộ', how: 'chặn mọi kết nối TCP', ttl: '10 phút', sec: 600, c: K.red, bg: K.redBg, who: 'chỉ khi người duyệt' },
];
const Block: React.FC = () => {
  const { since } = useSec();
  const run = interpolate(since(4, 0.3), [0, 120], [0, 1], clamp);
  return (
    <>
      <MiniMap hl={['an', 'blk']} />
      <Panel>
        <div style={{ display: 'flex', alignItems: 'stretch', gap: 18 }}>
          <Reveal at={0} style={{ width: 380 }}>
            <Card c={K.blue} style={{ height: 170 }}>
              <H3 c={K.blue} s={30}>Bộ phân tích</H3>
              <Small s={23}>tài khoản thường</Small>
              <div style={{ fontSize: 23, color: K.red, marginTop: 6 }}>✗ không được sửa tường lửa</div>
            </Card>
          </Reveal>
          <Reveal at={1} d={0.2}><div style={{ fontSize: 44, color: K.mute, marginTop: 50 }}>→</div></Reveal>
          <Reveal at={1} style={{ width: 400 }}>
            <Card c={K.red} style={{ height: 170 }}>
              <H3 c={K.red} s={30}>Lệnh chặn</H3>
              <Small s={23}>duy nhất có quyền quản trị</Small>
              <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>{['đánh lừa', 'chặn web', 'chặn toàn bộ'].map((x) => <Pill key={x} c={K.red} bg={K.redBg} size={18}>{x}</Pill>)}</div>
            </Card>
          </Reveal>
          <Reveal at={2} d={0.2}><div style={{ fontSize: 44, color: K.mute, marginTop: 50 }}>→</div></Reveal>
          <Reveal at={2} style={{ width: 380 }}>
            <Card c={K.ink} style={{ height: 170 }}>
              <H3 s={30}>Tường lửa</H3>
              <Small s={23}>danh sách IP, mỗi IP kèm thời hạn</Small>
              <div style={{ fontFamily: MONO, fontSize: 21, marginTop: 8, color: K.ink }}>10.77.0.10 · timeout</div>
            </Card>
          </Reveal>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12, marginTop: 28 }}>
          {sets.map((s, i) => {
            const left = Math.max(0, s.sec === 60 ? 1 - run : 1 - run * 0.1);
            return (
              <Reveal key={s.n} at={3} d={i * 2.3} from="left">
                <div style={{ display: 'flex', alignItems: 'center', gap: 20, padding: '12px 22px', borderRadius: 14, border: `2px solid ${s.c}`, background: s.bg }}>
                  <div style={{ width: 230, fontSize: 28, fontWeight: 700, color: s.c }}>{s.n}</div>
                  <div style={{ width: 360, fontSize: 24 }}>{s.how}</div>
                  <div style={{ width: 130, fontFamily: MONO, fontSize: 24, fontWeight: 700 }}>{s.ttl}</div>
                  <div style={{ flex: 1, height: 16, background: '#fff', borderRadius: 8, overflow: 'hidden', border: `1px solid ${K.line}` }}>
                    <div style={{ width: `${left * 100}%`, height: '100%', background: s.c }} />
                  </div>
                  <div style={{ width: 210, fontSize: 21, color: K.mute, textAlign: 'right' }}>{left <= 0.001 ? <b style={{ color: K.green }}>đã tự gỡ ✓</b> : s.who}</div>
                </div>
              </Reveal>
            );
          })}
        </div>
        <div style={{ display: 'flex', gap: 20, marginTop: 24 }}>
          <Reveal at={4} d={1.5} style={{ flex: 1 }}>
            <Card c={K.green} bg={K.greenBg} style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 20px' }}>
              <Lock s={34} /><div style={{ fontSize: 26 }}><b style={{ color: K.green }}>Luôn được bảo vệ:</b> máy chủ B · khách hàng C</div>
            </Card>
          </Reveal>
          <Reveal at={5} style={{ flex: 1 }}>
            <Card c={K.ink} style={{ padding: '14px 20px', fontSize: 25 }}>
              Bộ phân tích bị chiếm quyền → <b>vẫn không xóa được tường lửa</b>, không chặn được B, C
            </Card>
          </Reveal>
        </div>
      </Panel>
    </>
  );
};

// ---------------------------- 4f. Dashboard ---------------------------------
const Dash: React.FC = () => (
  <>
    <MiniMap hl={['soc']} />
    <Panel>
      <Reveal at={0} style={abs(0, 0, 860, 560)}>
        <MediaSlot name="dashboard" kind="ảnh" need="Ảnh chụp dashboard SOC (http://192.168.56.101:9000) lúc có cảnh báo và thẻ chờ duyệt" style={{ width: 860, height: 520 }} />
      </Reveal>
      <div style={{ ...abs(900, 0, 420), display: 'flex', flexDirection: 'column', gap: 16 }}>
        <Reveal at={0} d={0.5}><Card c={K.ink} style={{ padding: '14px 18px' }}><div style={{ fontSize: 25 }}>chỉ mở được từ <b>mạng quản trị</b></div></Card></Reveal>
        {['các máy đang hoạt động', 'luồng cảnh báo thời gian thực', 'yêu cầu cần xử lý'].map((x, i) => (
          <Reveal key={x} at={1} d={0.4 + i * 0.8} from="right"><div style={{ fontSize: 27, padding: '6px 0', borderBottom: `1px solid ${K.line}` }}>• {x}</div></Reveal>
        ))}
        <Reveal at={2} d={0.3} from="right">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, marginTop: 10 }}>
            <Pill c={K.red} bg={K.redBg} size={21}>Duyệt chặn</Pill>
            <Pill c={TEAL} bg={TEAL_BG} size={21}>Duyệt luật mới</Pill>
            <Pill c={K.ink} bg={K.bg2} size={21}>Báo cáo sự cố</Pill>
          </div>
        </Reveal>
      </div>
    </Panel>
  </>
);

// ================================ KICH BAN ==================================
type Who = 'A' | 'B' | 'C';
const WHO: Record<Who, [string, string]> = { A: [K.red, K.redBg], B: [K.ink, K.blueBg], C: [K.green, K.greenBg] };
const scen: { at: number; who: Who; t: string; slot?: { name: string; kind: 'ảnh' | 'video'; need: string } }[] = [
  { at: 1, who: 'A', t: 'Quét cổng bằng nmap', slot: { name: 's-nmap', kind: 'video', need: 'Máy A chạy: nmap -sT -p 1-100 10.77.0.20 (thấy cổng 23, 80…)' } },
  { at: 2, who: 'B', t: 'Cảnh báo quét · chạm cổng bẫy → đánh lừa', slot: { name: 's-canh-bao', kind: 'video', need: 'Máy B (dashboard hoặc monitor): cảnh báo quét cổng, sự kiện cổng bẫy 23, A chuyển sang đánh lừa' } },
  { at: 3, who: 'A', t: 'Đọc robots.txt, xem mã nguồn', slot: { name: 's-robots', kind: 'video', need: 'Máy A: xem /robots.txt (thấy /admin, /backup/), rồi xem mã nguồn trang chủ (thấy comment admin / LabShop@2026!)' } },
  { at: 4, who: 'A', t: 'Đăng nhập trang admin giả', slot: { name: 's-admin-login', kind: 'video', need: 'Máy A: mở /admin (trang giả), đăng nhập bằng admin / LabShop@2026!' } },
  { at: 5, who: 'B', t: 'Honeypot ghi nhận · chờ duyệt', slot: { name: 's-cho-duyet', kind: 'video', need: 'Dashboard trên B: sự cố “cắn câu”, điểm 310, thẻ chờ duyệt chặn toàn bộ' } },
  { at: 6, who: 'A', t: 'Dò /.env, /.git/, WordPress · thử SQLi', slot: { name: 's-do-file', kind: 'video', need: 'Máy A: dò /.env, /.git/config, /wp-login.php, /phpmyadmin/… và gửi một yêu cầu SQL injection' } },
  { at: 7, who: 'B', t: 'SQLi bị bắt · /.env chưa có luật', slot: { name: 's-sqli', kind: 'video', need: 'Monitor trên B: có ALERT SQL injection, còn /.env… chỉ là dòng WEB 404, không có ALERT' } },
  { at: 8, who: 'B', t: 'Tự sinh 4 luật · qua đủ 5 bước', slot: { name: 's-luat-moi', kind: 'video', need: 'Dashboard mục “Rule tự sinh”: 4 phiếu chờ duyệt (/.env, /wp-, /phpmyadmin, /.git/), 5 bước đều ✓' } },
  { at: 9, who: 'B', t: 'Duyệt & nạp · 13 → 17 luật', slot: { name: 's-nap-luat', kind: 'video', need: 'Bấm “Duyệt & nạp” 4 phiếu; phần Rule đang chạy hiện 4 rule (hoặc ruleset-stats: 17)' } },
  { at: 10, who: 'B', t: 'Biến thể mới bị phát hiện', slot: { name: 's-bien-the', kind: 'video', need: 'Máy A dò /.env.production, /.ENV.dev…; monitor trên B hiện ALERT “LAB AUTO uri probe”' } },
  { at: 11, who: 'B', t: 'Duyệt chặn toàn bộ', slot: { name: 's-chan', kind: 'video', need: 'Dashboard: bấm “Duyệt chặn toàn bộ” cho 10.77.0.10' } },
  { at: 12, who: 'C', t: 'A mất kết nối · C vẫn mua hàng', slot: { name: 's-ket-qua', kind: 'video', need: 'Hai cửa sổ cạnh nhau: A chạy curl bị treo / 000 · C (trình duyệt) vẫn thêm giỏ hàng, đặt hàng' } },
];
const Scenario: React.FC = () => {
  const { step } = useSec();
  const cur = [...scen].reverse().find((s) => step >= s.at) ?? scen[0];
  const score = step >= 5 ? 260 : step >= 2 ? 160 : 0; // so lieu that cua lan quay 11/11
  const { sec } = useSec();
  const slotFrom = (i: number) => (i === 0 ? 0 : sec.lines[scen[i].at].from);
  const slotTo = (i: number) => (i + 1 < scen.length ? sec.lines[scen[i + 1].at].from : sec.len);
  const rules = step >= 9 ? 17 : 13;
  const [wc, wbg] = WHO[cur.who];
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      <div style={{ ...abs(0, 0, 640), display: 'flex', flexDirection: 'column', gap: 6 }}>
        {scen.map((s) => {
          const [c, bg] = WHO[s.who];
          const on = step === s.at;
          const seen = step >= s.at;
          return (
            <div key={s.at} style={{ display: 'flex', alignItems: 'center', gap: 12, opacity: seen ? (on ? 1 : 0.6) : 0.18, padding: '4px 10px', borderRadius: 10, background: on ? bg : 'transparent' }}>
              <div style={{ width: 34, height: 34, borderRadius: 8, background: c, color: '#fff', fontFamily: SANS, fontWeight: 800, fontSize: 19, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>{s.who}</div>
              <div style={{ fontSize: 24, fontWeight: on ? 700 : 400, color: on ? c : K.text }}>{s.t}</div>
            </div>
          );
        })}
      </div>
      <Reveal at={0} from="right" style={abs(680, 0, 1060, 600)}>
        <div style={{ position: 'relative' }}>
          <div style={{ position: 'relative', width: 1060, height: 540 }}>
            {scen.map((s, i) => s.slot && (
              <Sequence key={s.slot.name} from={slotFrom(i)} durationInFrames={slotTo(i) - slotFrom(i)} layout="none">
                <div style={{ position: 'absolute', inset: 0 }}>
                  <MediaSlot name={s.slot.name} kind={s.slot.kind} need={s.slot.need} style={{ width: 1060, height: 540 }} />
                </div>
              </Sequence>
            ))}
          </div>
          <div style={{ position: 'absolute', top: 14, left: 14 }}><Pill c={wc} bg={wbg} size={22}>{cur.who === 'C' ? 'MÁY A + C' : `MÁY ${cur.who}`}</Pill></div>
          <div style={{ display: 'flex', gap: 30, marginTop: 14, fontSize: 25, justifyContent: 'flex-end' }}>
            <span>điểm của A: <b style={{ fontFamily: MONO, color: score >= 300 ? K.red : K.ink }}>{score}</b></span>
            <span>luật Suricata: <b style={{ fontFamily: MONO, color: rules > 13 ? TEAL : K.ink }}>{rules}</b></span>
          </div>
        </div>
      </Reveal>
    </div>
  );
};

// ================================ KET LUAN ==================================
const End: React.FC = () => {
  const layers = [
    { t: 'Phát hiện đa nguồn', s: 'Suricata · log đăng nhập · honeypot', c: K.orange, bg: K.orangeBg },
    { t: 'Gài bẫy & đánh lừa', s: 'honeytoken · cổng bẫy · trang admin giả', c: PURPLE, bg: PURPLE_BG },
    { t: 'Tự học luật mới', s: 'học từ kẻ tấn công · 5 bước kiểm tra · người duyệt', c: TEAL, bg: TEAL_BG },
    { t: 'Phản ứng có người duyệt', s: 'có thời hạn · có bằng chứng · không chặn nhầm', c: K.red, bg: K.redBg },
  ];
  return (
    <div style={{ position: 'relative', width: SW, height: SH }}>
      <div style={{ ...abs(170, 10, 1400), display: 'flex', flexDirection: 'column', gap: 16 }}>
        {layers.map((l, i) => (
          <Reveal key={l.t} at={i < 1 ? 0 : 1} d={i < 1 ? 0.5 : (i - 1) * 1.4} from="left">
            <div style={{ marginLeft: i * 50, display: 'flex', alignItems: 'center', gap: 24, background: l.bg, border: `2px solid ${l.c}`, borderRadius: 16, padding: '16px 28px' }}>
              <div style={{ fontSize: 34, fontWeight: 700, color: l.c, width: 430 }}>{l.t}</div>
              <div style={{ fontSize: 26, color: K.text }}>{l.s}</div>
            </div>
          </Reveal>
        ))}
      </div>
      <Reveal at={3} style={abs(0, 470, SW)}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 52, fontWeight: 700, color: K.ink }}>Cảm ơn thầy cô và các bạn đã theo dõi</div>
        </div>
      </Reveal>
    </div>
  );
};

export const SCENES: Record<string, React.FC> = {
  intro: Intro, problem: Problem, lab: Lab, tools: Tools, parts: Parts, shop: Shop, honey: Honey,
  rulegen: RuleGen, analyzer: Analyzer, block: Block, dash: Dash, scenario: Scenario, end: End,
};
