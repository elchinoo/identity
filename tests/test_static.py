"""Static-asset guards."""
import re
from pathlib import Path

STATIC = Path(__file__).resolve().parents[1] / "src" / "identity" / "static"


def test_no_native_dialogs_in_static_js():
    """Native confirm()/alert()/prompt() freeze browser automation and cannot be styled: use confirmDialog/promptDialog from /kit/ui.js."""
    native = re.compile(r"(?<![\w.$])(?:window\.)?(?:confirm|alert|prompt)\s*\(")
    offenders = []
    for f in sorted([*STATIC.rglob("*.js"), *STATIC.rglob("*.html")]):
        for n, line in enumerate(f.read_text().splitlines(), 1):
            if native.search(line):
                offenders.append(f"{f.name}:{n}")
    assert not offenders, f"native dialogs in {offenders}"
