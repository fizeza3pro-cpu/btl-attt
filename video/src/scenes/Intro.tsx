import React from 'react';
import { interpolate, useCurrentFrame } from 'remotion';
import { Bg, Badge, Captions, Pop } from '../components';
import { C } from '../theme';

export const INTRO_SEC = 15;

export const Intro: React.FC = () => {
  const frame = useCurrentFrame();
  const glow = interpolate(frame % 90, [0, 45, 90], [0.35, 0.8, 0.35]);
  return (
    <Bg>
      <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', justifyContent: 'center', padding: '0 140px' }}>
        <Pop delay={0.2}>
          <div style={{ color: C.cyan, fontSize: 28, letterSpacing: 4, fontWeight: 600 }}>BÀI TẬP LỚN AN TOÀN THÔNG TIN</div>
        </Pop>
        <Pop delay={0.6}>
          <div style={{ fontSize: 84, fontWeight: 800, lineHeight: 1.12, marginTop: 18, maxWidth: 1500 }}>
            Giám sát máy chủ web trong mạng lab bằng <span style={{ color: C.cyan, textShadow: `0 0 ${30 * glow}px ${C.cyan}` }}>Suricata</span>
          </div>
        </Pop>
        <Pop delay={1.2}>
          <div style={{ fontSize: 38, color: C.mute, marginTop: 24 }}>
            Phát hiện hành vi xâm nhập và phản ứng có kiểm soát
          </div>
        </Pop>
        <Pop delay={1.9} style={{ marginTop: 44 }}>
          <Badge color={C.cyan}>Suricata 8.0.3 IDS</Badge>
          <Badge color={C.amber}>nftables</Badge>
          <Badge color={C.violet}>Analyzer chấm điểm</Badge>
          <Badge color={C.green}>3 máy ảo VirtualBox</Badge>
        </Pop>
      </div>
      <Captions cues={[
        { from: 3, to: 8.5, text: 'Đề tài: xây dựng hệ thống phát hiện xâm nhập mạng cho một máy chủ web và phản ứng có kiểm soát.' },
        { from: 8.5, to: 14.6, text: 'Mục tiêu: chặn đúng kẻ tấn công, không ảnh hưởng người dùng hợp lệ, và đo hiệu quả bằng số liệu.' },
      ]} />
    </Bg>
  );
};
