#!/usr/bin/env python3
"""Last step of build.sh: cut the four recorded videos along timeline.json, add narration and captions.

Usage: assemble.py OUT_DIR NAME      -> OUT_DIR/final/NAME.mp4 and NAME.srt
Narration comes from OUT_DIR/narration/ (narrate.py scenes ...): scene-<id>.wav and narration.json ({id: {duration, cues:[{text,start,end}]}});
the cues are the captions, timed by the neural voice itself.
Each scene of timeline.json lists `cuts` (which browser context is on screen from when); the segments are trimmed from the matching
webm (video offset = timeline offsets[role]), concatenated in scene order, and the narration of scene N starts with scene N.
"""
import json
import pathlib
import re
import subprocess
import sys

out = pathlib.Path(sys.argv[1])
name = sys.argv[2]
tl = json.loads((out / "timeline.json").read_text())
narr = out / "narration"
nj = json.loads((narr / "narration.json").read_text())
dur = {int(k): v["duration"] for k, v in nj.items()}
work = out / "final" / "parts"
work.mkdir(parents=True, exist_ok=True)
FPS = 30


def ff(*args):
    subprocess.run(["ffmpeg", "-y", "-v", "error", "-nostdin", *map(str, args)], check=True)


parts, starts, pos, srcdur = [], {}, 0.0, {}
for sc in tl["scenes"]:
    n, s, e = sc["scene"], sc["video"]["start_s"], sc["video"]["end_s"]
    starts[n] = sum(float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(q)], text=True)) for q in parts)   # real length of what precedes
    cuts = sc["cuts"]
    assert cuts, f"scene {n} has no cuts"
    for i, c in enumerate(cuts):
        t0 = s if i == 0 else c["at_s"]
        t1 = e if i == len(cuts) - 1 else cuts[i + 1]["at_s"]
        if t1 - t0 < 0.05:
            continue
        # the scene starts exactly at its first cut; the previous scene ends exactly where this one starts
        seg = work / f"s{n:02d}-{i}.mp4"
        src = out / "videos" / f"{c['role']}.webm"
        if src not in srcdur:   # Playwright only writes frames while the page changes: a still page's video ends early, so hold its last frame
            srcdur[src] = float(subprocess.check_output(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", str(src)], text=True))
        last_use = max(k for k, sc2 in enumerate(tl["scenes"]) for cc in sc2["cuts"] if cc["role"] == c["role"])   # a page that is still at the end (a JSON page) writes no more frames: its last frame is held
        assert tl["scenes"].index(sc) == last_use or srcdur[src] >= t1 - tl["offsets"][c["role"]] - 1.5, f"{src.name} is {srcdur[src]:.1f}s but scene {n} needs it until {t1 - tl['offsets'][c['role']]:.1f}s"
        ss = min(t0 - tl["offsets"][c["role"]], srcdur[src] - 0.3)
        ff("-ss", f"{max(ss, 0):.3f}", "-i", src, "-t", f"{t1 - t0:.3f}",
           "-vf", f"fps={FPS},tpad=stop_mode=clone:stop_duration=600,scale=1920:1080:out_range=tv,format=yuv420p", "-c:v", "libx264", "-preset", "veryfast", "-crf", "18", "-an", seg)
        parts.append(seg)
    pos += e - s
    # narration must fit its scene with at least 0.7 s to spare
    assert e - s >= dur[n] + 0.7 - 0.15, f"scene {n}: {e - s:.1f}s is shorter than narration {dur[n]:.1f}s + 0.7"
(work / "list.txt").write_text("".join(f"file '{p.name}'\n" for p in parts))
ff("-f", "concat", "-i", work / "list.txt", "-c", "copy", work / "video.mp4")

# narration: every scene's wav delayed to its start
inputs, filt = [], []
for i, n in enumerate(sorted(starts)):
    inputs += ["-i", narr / f"scene-{n}.wav"]
    filt.append(f"[{i}:a]adelay={int(starts[n] * 1000)}:all=1[a{i}]")
mix = "".join(f"[a{i}]" for i in range(len(starts))) + f"amix=inputs={len(starts)}:normalize=0:dropout_transition=0,volume=1.0[m]"
ff(*inputs, "-filter_complex", ";".join(filt + [mix]), "-map", "[m]", "-ar", "44100", "-ac", "1", work / "narration.wav")

final = out / "final"
ff("-i", work / "video.mp4", "-i", work / "narration.wav", "-map", "0:v", "-map", "1:a", "-c:v", "copy", "-af", "apad", "-c:a", "aac", "-b:a", "160k",
   "-movflags", "+faststart", "-shortest", final / f"{name}.mp4")


# captions: one per spoken sentence, timed by the voice (narration.json); a long sentence is split at a comma near its middle
def stamp(t):
    ms = int(round(t * 1000))
    return f"{ms // 3600000:02d}:{ms // 60000 % 60:02d}:{ms // 1000 % 60:02d},{ms % 1000:03d}"


cues = []
for n in sorted(starts):
    for c in nj[str(n)]["cues"]:
        text, a, b = c["text"].strip(), c["start"], c["end"]
        chunks = [text]
        if len(text) > 90:
            cands = [m.end() for m in re.finditer(r", ", text) if 25 < m.end() < len(text) - 25]
            if cands:
                k = min(cands, key=lambda x: abs(x - len(text) / 2))
                chunks = [text[:k].strip(), text[k:].strip()]
        tot, t = sum(len(x) for x in chunks), a
        for x in chunks:
            d = (b - a) * len(x) / tot
            cues.append((starts[n] + t, starts[n] + t + d, x))
            t += d
final.joinpath(f"{name}.srt").write_text("".join(f"{i}\n{stamp(a)} --> {stamp(b)}\n{c}\n\n" for i, (a, b, c) in enumerate(cues, 1)))
print(f"{final / name}.mp4: {pos:.1f}s, {len(cues)} captions")

# soft subtitles: the same SRT as a selectable mov_text track inside the mp4 (video and audio are copied)
tmp = final / f"{name}.sub.mp4"
ff("-i", final / f"{name}.mp4", "-i", final / f"{name}.srt", "-map", "0:v", "-map", "0:a", "-map", "1:0", "-c:v", "copy", "-c:a", "copy", "-c:s", "mov_text",
   "-metadata:s:s:0", "language=eng", "-movflags", "+faststart", tmp)
tmp.replace(final / f"{name}.mp4")
