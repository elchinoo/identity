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


def test_admin_console_accessibility_guards():
    """Findings of the axe run: no empty column headers, no h3 straight after the h1, a name on the per-row group select, a labelled scrollable <pre>."""
    js = (STATIC / "admin.js").read_text()
    assert 'h("h3"' not in js, "use h2 under the page h1 (heading-order); style it in identity.css"
    assert 'h("th", {}, t)' not in js, "an empty header cell needs <span class=\"sr-only\">Actions</span>"
    assert "aria-label" in js and "App for group" in js, "the per-row app select needs an accessible name"
    assert 'h("pre"' not in re.sub(r"scrollRegion\(h\(\"pre\"", "", js), "wrap every <pre> in scrollRegion(el, label)"
    assert "confirm-overlay" not in (STATIC / "identity.css").read_text(), "the kit modal is a native <dialog> now"
