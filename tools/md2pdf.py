#!/usr/bin/env python3
"""md2pdf.py SPEC.md docs/SPEC.pdf - minimal Markdown -> print HTML -> PDF
(via headless Chrome). Handles just what SPEC.md uses: headings, paragraphs,
lists, tables, code fences, `code`, **bold**, *italic*, [links](x)."""
import html
import os
import re
import subprocess
import sys
import tempfile

CHROME = [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "google-chrome", "chromium", "chromium-browser",
]

CSS = """
@page { size: A4; margin: 11mm 13mm; }
body { font: 9pt/1.38 -apple-system, "Helvetica Neue", Arial, sans-serif; color: #111; }
h1 { font-size: 15pt; margin: 0 0 3pt; }
h2 { font-size: 10.5pt; margin: 8pt 0 2pt; border-bottom: 1px solid #ccc; }
p, ul { margin: 3pt 0; }
ul { padding-left: 14pt; }
li { margin: 1pt 0; }
pre { font: 7.6pt/1.25 Menlo, monospace; background: #f5f5f5; padding: 4pt 6pt;
      margin: 3pt 0; white-space: pre; }
code { font: 8pt Menlo, monospace; background: #f2f2f2; padding: 0 1.5pt; }
pre code { background: none; padding: 0; }
table { break-inside: avoid; border-collapse: collapse; margin: 3pt 0; font-size: 8.4pt; }
td, th { border: 1px solid #ccc; padding: 1pt 5pt; vertical-align: top; text-align: left; }
th { background: #f0f0f0; }
a { color: inherit; }
"""


def inline(s):
    parts = re.split(r"(`[^`]+`)", s)
    out = []
    for p in parts:
        if p.startswith("`") and p.endswith("`") and len(p) > 1:
            out.append("<code>%s</code>" % html.escape(p[1:-1]))
            continue
        p = html.escape(p, quote=False).replace("\\`", "`")
        p = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", p)
        p = re.sub(r"(?<![\w*])\*(?!\s)(.+?)(?<!\s)\*(?![\w*])", r"<i>\1</i>", p)
        p = re.sub(r"\[([^\]]+)\]\(([^)]+)\)", r'<a href="\2">\1</a>', p)
        out.append(p)
    return "".join(out)


def convert(md):
    lines, out, i = md.splitlines(), [], 0
    while i < len(lines):
        l = lines[i]
        if l.startswith("```"):
            j = i + 1
            while not lines[j].startswith("```"):
                j += 1
            out.append("<pre><code>%s</code></pre>" % html.escape("\n".join(lines[i + 1:j])))
            i = j + 1
        elif l.startswith("#"):
            n = len(l) - len(l.lstrip("#"))
            out.append("<h%d>%s</h%d>" % (n, inline(l[n:].strip()), n))
            i += 1
        elif l.startswith("|"):
            rows = []
            while i < len(lines) and lines[i].startswith("|"):
                cells = [c.strip() for c in re.split(r"(?<!\\)\|", lines[i].strip())[1:-1]]
                if not all(re.fullmatch(r":?-+:?", c) for c in cells if c):
                    rows.append(cells)
                i += 1
            t = ["<table>"]
            for r, cells in enumerate(rows):
                tag = "th" if r == 0 else "td"
                t.append("<tr>%s</tr>" % "".join(
                    "<%s>%s</%s>" % (tag, inline(c.replace("\\|", "|")), tag) for c in cells))
            out.append("".join(t) + "</table>")
        elif re.match(r"^\s*[*-] ", l):
            items = []
            while i < len(lines) and re.match(r"^\s*[*-] ", lines[i]):
                items.append(inline(re.sub(r"^\s*[*-] ", "", lines[i])))
                i += 1
            out.append("<ul>%s</ul>" % "".join("<li>%s</li>" % x for x in items))
        elif not l.strip():
            i += 1
        else:
            para = []
            while i < len(lines) and lines[i].strip() and not re.match(r"^(#|\||```|\s*[*-] )", lines[i]):
                para.append(lines[i])
                i += 1
            out.append("<p>%s</p>" % inline(" ".join(para)))
    return "<!doctype html><meta charset=utf-8><style>%s</style>%s" % (CSS, "\n".join(out))


def main(src, dst):
    page = convert(open(src, encoding="utf-8").read())
    with tempfile.NamedTemporaryFile("w", suffix=".html", delete=False, encoding="utf-8") as f:
        f.write(page)
    chrome = next((c for c in CHROME if os.path.exists(c) or subprocess.run(
        ["which", c], capture_output=True).returncode == 0), None)
    if not chrome:
        sys.exit("no Chrome/Chromium found; HTML left at " + f.name)
    subprocess.run([chrome, "--headless", "--disable-gpu", "--no-pdf-header-footer",
                    "--print-to-pdf=" + os.path.abspath(dst), "file://" + f.name],
                   check=True, capture_output=True)
    os.unlink(f.name)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
