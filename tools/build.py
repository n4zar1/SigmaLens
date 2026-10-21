"""Inlines src/ into a single self-contained dist/sigmalens.html (works from file://, no network).

    python tools/build.py          # app only
    python tools/build.py --demo   # also embeds demo/demo-events.jsonl and demo/rules/*.yml
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src"


def script(text):
    # A literal "</script" inside inline JS would end the tag early.
    return "<script>\n" + text.replace("</script", "<\\/script") + "\n</script>"


html = (SRC / "index.html").read_text(encoding="utf-8")
html = html.replace('<link rel="stylesheet" href="style.css">\n', "")
html = html.replace("<!--INLINE_CSS-->", "<style>\n" + (SRC / "style.css").read_text(encoding="utf-8") + "\n</style>")
html = html.replace('<script src="engine.js"></script>', script((SRC / "engine.js").read_text(encoding="utf-8")))
html = html.replace('<script src="app.js"></script>', script((SRC / "app.js").read_text(encoding="utf-8")))

demo = ""
if "--demo" in sys.argv:
    rules = [{"name": p.name, "text": p.read_text(encoding="utf-8")} for p in sorted((ROOT / "demo" / "rules").glob("*.yml"))]
    payload = {"events": (ROOT / "demo" / "demo-events.jsonl").read_text(encoding="utf-8"), "rules": rules}
    demo = script("window.SIGMALENS_DEMO = " + json.dumps(payload, ensure_ascii=False) + ";")
html = html.replace("<!--INLINE_DEMO-->", demo)

for marker in ("<!--INLINE_CSS-->", "<!--INLINE_DEMO-->", 'src="engine.js"', 'src="app.js"', 'href="style.css"'):
    assert marker not in html, f"build left {marker} in the output"

out = ROOT / "dist" / ("sigmalens-demo.html" if demo else "sigmalens.html")
out.parent.mkdir(exist_ok=True)
out.write_text(html, encoding="utf-8")
print(f"{out} ({out.stat().st_size // 1024} KB)")
if demo:
    # GitHub Pages (sigmalens.n4zar1.com) serves the demo build from the repo root.
    (ROOT / "index.html").write_text(html, encoding="utf-8")
    print(f"{ROOT / 'index.html'} (GitHub Pages)")
