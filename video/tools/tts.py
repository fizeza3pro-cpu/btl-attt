"""Tao giong doc cho video reel tu src/reel/script.json bang edge-tts.

Moi cau -> public/reel/voice/<section>-<i>.mp3. Do dai -> src/reel/timing.json.
Chi tao lai cau nao thay doi noi dung (so theo hash), thu lai khi edge-tts tra rong.
Chay:  py video/tools/tts.py
"""
import asyncio
import hashlib
import json
import pathlib
import subprocess
import sys

import edge_tts

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "src" / "reel" / "script.json"
TIMING = ROOT / "src" / "reel" / "timing.json"
OUT = ROOT / "public" / "reel" / "voice"


def duration(path: pathlib.Path) -> float:
    r = subprocess.run(
        ["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(path)],
        capture_output=True, text=True, check=True,
    )
    return float(r.stdout.strip())


async def synth(text: str, voice: str, rate: str, dest: pathlib.Path) -> None:
    for attempt in range(12):
        try:
            await edge_tts.Communicate(text, voice, rate=rate).save(str(dest))
            if dest.exists() and dest.stat().st_size > 1000:
                return
        except Exception as e:  # edge-tts thinh thoang tra NoAudioReceived
            print(f"  thu lai {attempt + 1}: {e}", file=sys.stderr)
        await asyncio.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"khong tao duoc giong: {dest.name}")


async def main() -> None:
    data = json.loads(SCRIPT.read_text(encoding="utf-8"))
    old = json.loads(TIMING.read_text(encoding="utf-8")) if TIMING.exists() else {}
    OUT.mkdir(parents=True, exist_ok=True)
    timing = {}
    for sec in data["sections"]:
        for i, line in enumerate(sec["lines"]):
            key = f"{sec['id']}-{i}"
            say = line.get("say", line["t"])
            h = hashlib.sha1(f"{data['voice']}|{data['rate']}|{say}".encode()).hexdigest()[:12]
            dest = OUT / f"{key}.mp3"
            if old.get(key, {}).get("hash") == h and dest.exists():
                timing[key] = old[key]
                continue
            print("tao", key)
            await synth(say, data["voice"], data["rate"], dest)
            timing[key] = {"hash": h, "dur": round(duration(dest), 3)}
            TIMING.write_text(json.dumps({**old, **timing}, ensure_ascii=False, indent=1), encoding="utf-8")
    TIMING.write_text(json.dumps(timing, ensure_ascii=False, indent=1), encoding="utf-8")
    total = sum(v["dur"] for v in timing.values())
    print(f"xong {len(timing)} cau, tong giong {total:.1f} s")


asyncio.run(main())
