#!/usr/bin/env python3
"""Keeps the NARRATION column of ../VIDEO-SCRIPT.md identical to narration.txt (the spoken text).

  script_sync.py check   exit 1 if the table and narration.txt differ (build.sh runs this first)
  script_sync.py write   rewrite the table column from narration.txt

Pause markers (`...`, `[pause N]`) are not part of the column; paragraphs are joined with a space.
"""
import pathlib
import re
import sys

here = pathlib.Path(__file__).resolve().parent
script = here.parent / "VIDEO-SCRIPT.md"


def spoken() -> dict[str, str]:
    out = {}
    parts = re.split(r"(?m)^##[ \t]+(\S+)(?:[ \t]+[a-z]{2}_[a-z]+)?[ \t]*$", (here / "narration.txt").read_text())
    for sid, body in zip(parts[1::2], parts[2::2]):
        lines = [l.strip() for l in body.splitlines() if l.strip() and l.strip() != "..." and not re.fullmatch(r"\[pause\s+[\d.]+\]", l.strip())]
        out[sid] = " ".join(lines)
    return out


def main(mode: str) -> int:
    want = spoken()
    lines = script.read_text().split("\n")
    bad = []
    for i, line in enumerate(lines):
        cells = re.split(r"(?<!\\)\|", line)
        if len(cells) == 7 and cells[1].strip().isdigit():
            sid = cells[1].strip()
            text = want[sid].replace("|", "\\|")
            if cells[4].strip() != text:
                bad.append(sid)
                cells[4] = f" {text} "
                lines[i] = "|".join(cells)
    assert sorted(want, key=int) == [str(n) for n in range(1, len(want) + 1)], "narration.txt scenes must be 1..N"
    if mode == "write":
        script.write_text("\n".join(lines))
        print("updated scenes:", ", ".join(bad) or "none")
        return 0
    if bad:
        print(f"VIDEO-SCRIPT.md narration differs from narration.txt for scenes {', '.join(bad)}; run script_sync.py write", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "check"))
