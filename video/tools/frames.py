import json, sys
s = json.load(open('src/reel/script.json', encoding='utf-8')); t = json.load(open('src/reel/timing.json', encoding='utf-8'))
F = 30; cur = 0; out = []
for si, sec in enumerate(s['sections']):
    loc = round(0.5 * F); starts = []
    for i, l in enumerate(sec['lines']):
        d = round(t.get(f"{sec['id']}-{i}", {}).get('dur', 3) * F); starts.append((cur + loc, d)); loc += d + round(s['gapLine'] * F)
    loc += round((s['gapSection'] - s['gapLine']) * F)
    if si == len(s['sections']) - 1: loc += 60
    for i, (a, d) in enumerate(starts): out.append(f"{sec['id']}-{i} {a + d - 5}")
    cur += loc
print('\n'.join(out)); print('total', cur, cur / F, file=sys.stderr)
