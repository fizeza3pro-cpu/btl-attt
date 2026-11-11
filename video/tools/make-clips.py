"""Cat cac doan quay that (video/raw/scen-*.mp4) thanh clip khop dung thoi luong tung o trong phan KICH BAN.

Thoi luong o = tu dau cau cua o do toi dau cau cua o ke tiep (giong scenes.tsx). Clip duoc tang/giam toc
cho vua (toi da ~3x), neu ngan hon thi giu khung cuoi. Ket qua: public/reel/media/<ten>.mp4 + media.json.
Chay: py -I video/tools/make-clips.py
"""
import json
import math
import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
RAW = ROOT / "raw"
OUT = ROOT / "public" / "reel" / "media"
FPS = 30


def jr(x):  # Math.round cua JS
    return math.floor(x + 0.5)


script = json.loads((ROOT / "src/reel/script.json").read_text(encoding="utf-8"))
timing = json.loads((ROOT / "src/reel/timing.json").read_text(encoding="utf-8"))
sec = next(s for s in script["sections"] if s["id"] == "scenario")
starts, local = [], jr(0.5 * FPS)
for i, l in enumerate(sec["lines"]):
    starts.append(local)
    local += jr(timing[f"scenario-{i}"]["dur"] * FPS) + jr(script["gapLine"] * FPS) + jr(l.get("hold", 0) * FPS)
local += jr((script["gapSection"] - script["gapLine"]) * FPS)
sec_len = local

# o: (ten, cau bat dau, [(file, tu giay, toi giay)], kieu ghep)
SLOTS = [
    ("s-nmap", 1, [("A", 3.0, 16.0)], None),
    ("s-canh-bao", 2, [("B", 6.0, 30.0)], None),
    ("s-robots", 3, [("A", 69.0, 82.0)], None),
    ("s-admin-login", 4, [("A", 222.0, 238.0)], None),
    ("s-cho-duyet", 5, [("B", 283.0, 301.0)], None),
    ("s-do-file", 6, [("A", 311.0, 338.0)], None),
    ("s-sqli", 7, [("B", 318.0, 348.0)], None),
    ("s-luat-moi", 8, [("B", 356.0, 372.0)], None),
    ("s-nap-luat", 9, [("B", 372.0, 388.0), ("B", 418.0, 428.0)], None),
    ("s-bien-the", 10, [("B", 429.0, 452.0)], None),
    ("s-chan", 11, [("B", 562.0, 590.0)], None),
    ("s-ket-qua", 12, [("C", 80.0, 95.0), ("A", 640.0, 655.0)], "pip"),
]
order = [s[1] for s in SLOTS]
OUT.mkdir(parents=True, exist_ok=True)
media = json.loads((ROOT / "src/reel/media.json").read_text(encoding="utf-8"))

for k, (name, at, parts, mode) in enumerate(SLOTS):
    f0 = 0 if k == 0 else starts[at]
    f1 = starts[order[k + 1]] if k + 1 < len(SLOTS) else sec_len
    target = (f1 - f0) / FPS
    dst = OUT / f"{name}.mp4"
    inputs, filt = [], []
    if mode == "pip":  # may thu nhat lam nen, may thu hai thu nho o goc tren phai (cung thoi diem)
        src_len = max(b - a for _, a, b in parts)
        for j, (m, a, b) in enumerate(parts):
            inputs += ["-ss", str(a), "-t", str(b - a), "-i", str(RAW / f"scen-{m}.mp4")]
        filt.append("[1:v]scale=1000:-2,pad=iw+12:ih+12:6:6:color=0xb83a32[small]")
        filt.append("[0:v][small]overlay=W-w-24:24[cat]")
    else:
        src_len = sum(b - a for _, a, b in parts)
        for j, (m, a, b) in enumerate(parts):
            inputs += ["-ss", str(a), "-t", str(b - a), "-i", str(RAW / f"scen-{m}.mp4")]
            filt.append(f"[{j}:v]setpts=PTS-STARTPTS[v{j}]")
        filt.append("".join(f"[v{j}]" for j in range(len(parts))) + f"concat=n={len(parts)}:v=1:a=0[cat]")
    speed = max(src_len / target, 1.0)
    pad = max(target - src_len / speed, 0)
    filt.append(f"[cat]setpts=PTS/{speed:.4f},fps={FPS},tpad=stop_mode=clone:stop_duration={pad + 0.5:.3f},trim=duration={target:.3f}[out]")
    cmd = ["ffmpeg", "-v", "error", "-y", *inputs, "-filter_complex", ";".join(filt), "-map", "[out]",
           "-c:v", "libx264", "-preset", "veryfast", "-crf", "20", "-pix_fmt", "yuv420p", str(dst)]
    subprocess.run(cmd, check=True)
    media[name] = f"reel/media/{name}.mp4"
    print(f"{name:15s} o {target:5.1f}s  nguon {src_len:5.1f}s  toc do x{speed:.2f}")

(ROOT / "src/reel/media.json").write_text(json.dumps(media, ensure_ascii=False, indent=1), encoding="utf-8")
