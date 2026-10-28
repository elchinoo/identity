#!/usr/bin/env python3
"""Checks narration.json against narration.txt: no silence longer than 3.5 s inside a scene unless it is a deliberate [pause N] over
something happening on screen, and nothing but a short tail after the last sentence.

Usage: check_gaps.py NARRATION_DIR      (the folder narrate.py scenes wrote; narration.txt is read from next to this file)
"""
import json
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
nj = json.loads((pathlib.Path(sys.argv[1]) / "narration.json").read_text())
parts = re.split(r"(?m)^##[ \t]+(\S+)(?:[ \t]+[a-z]{2}_[a-z]+)?[ \t]*$", (here / "narration.txt").read_text())
pauses = {sid: [float(x) for x in re.findall(r"(?m)^\[pause\s+([\d.]+)\]\s*$", body)] for sid, body in zip(parts[1::2], parts[2::2])}
bad = []
for sid, v in nj.items():
    cues = v["cues"]
    for a, b in zip(cues, cues[1:]):
        gap = b["start"] - a["end"]
        if gap > 3.5 and not any(gap <= p + 1.6 for p in pauses.get(sid, [])):
            bad.append(f"scene {sid}: {gap:.1f}s of silence after '{a['text'][:40]}'")
    if v["duration"] - cues[-1]["end"] > 0.5:
        bad.append(f"scene {sid}: {v['duration'] - cues[-1]['end']:.1f}s of silence at the end")
    print(f"scene {sid}: {v['duration']:.1f}s, longest gap {max([b['start'] - a['end'] for a, b in zip(cues, cues[1:])] or [0]):.1f}s, pauses {pauses.get(sid, [])}")
if bad:
    print("\n".join(bad), file=sys.stderr)
    sys.exit(1)
