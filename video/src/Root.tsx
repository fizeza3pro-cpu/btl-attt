import React from 'react';
import { Audio, Composition, interpolate, Sequence, staticFile } from 'remotion';
import { s } from './theme';
import { demoSeconds } from './demoConfig';
import { Intro, INTRO_SEC } from './scenes/Intro';
import { Architecture, ARCH_SEC } from './scenes/Architecture';
import { Demo } from './scenes/Demo';
import { AntiSpoof, SPOOF_SEC } from './scenes/AntiSpoof';
import { Results, RESULTS_SEC } from './scenes/Results';
import { Ending, END_SEC } from './scenes/Ending';
import { Reel, timeline } from './reel/Reel';

const scenes = () => [
  { C: Intro, sec: INTRO_SEC },
  { C: Architecture, sec: ARCH_SEC },
  { C: Demo, sec: demoSeconds() },
  { C: AntiSpoof, sec: SPOOF_SEC },
  { C: Results, sec: RESULTS_SEC },
  { C: Ending, sec: END_SEC },
];

const Full: React.FC = () => {
  let at = 0;
  const total = scenes().reduce((a, x) => a + s(x.sec), 0);
  return (
    <>
      {/* Nhac nen tu tong hop bang ffmpeg (public/music.wav) - khong ban quyen; nho dan o 3 giay cuoi */}
      <Audio
        src={staticFile('music.wav')}
        volume={(f) => interpolate(f, [0, s(2), total - s(3), total], [0, 1, 1, 0], { extrapolateLeft: 'clamp', extrapolateRight: 'clamp' })}
      />
      {scenes().map(({ C, sec }, i) => {
        const from = at; const len = s(sec); at += len;
        return <Sequence key={i} from={from} durationInFrames={len}><C /></Sequence>;
      })}
    </>
  );
};

export const RemotionRoot: React.FC = () => {
  const total = scenes().reduce((a, x) => a + s(x.sec), 0);
  return (
    <>
      <Composition id="BtlReel" component={Reel} durationInFrames={timeline.total} fps={30} width={1920} height={1080} />
      <Composition id="BtlDemo" component={Full} durationInFrames={total} fps={30} width={1920} height={1080} />
      <Composition id="Intro" component={Intro} durationInFrames={s(INTRO_SEC)} fps={30} width={1920} height={1080} />
      <Composition id="Architecture" component={Architecture} durationInFrames={s(ARCH_SEC)} fps={30} width={1920} height={1080} />
      <Composition id="AntiSpoof" component={AntiSpoof} durationInFrames={s(SPOOF_SEC)} fps={30} width={1920} height={1080} />
      <Composition id="Results" component={Results} durationInFrames={s(RESULTS_SEC)} fps={30} width={1920} height={1080} />
      <Composition id="Ending" component={Ending} durationInFrames={s(END_SEC)} fps={30} width={1920} height={1080} />
    </>
  );
};
