import React from 'react';
import { Audio, interpolate, Sequence, staticFile } from 'remotion';
import { buildTimeline, SecCtx } from './core';
import { SCENES } from './scenes';
import { Frame } from './ui';

export const timeline = buildTimeline();

export const Reel: React.FC = () => {
  const { sections, total } = timeline;
  return (
    <>
      {/* Nhac nen tu tong hop (public/music.wav, khong ban quyen) - de rat nho duoi giong doc */}
      <Audio src={staticFile('music.wav')} loop
        volume={(f) => 0.07 * interpolate(f, [0, 60, total - 90, total], [0, 1, 1, 0], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' })} />
      {sections.map((s) => {
        const Scene = SCENES[s.id];
        return (
          <Sequence key={s.id} from={s.from} durationInFrames={s.len} name={s.label}>
            <SecCtx.Provider value={s}>
              <Frame total={sections.length}><Scene /></Frame>
            </SecCtx.Provider>
            {s.lines.map((l) => (
              <Sequence key={l.key} from={l.from} durationInFrames={l.dur + 6} name={l.key}>
                <Audio src={staticFile(`reel/voice/${l.key}.mp3`)} />
              </Sequence>
            ))}
          </Sequence>
        );
      })}
    </>
  );
};
