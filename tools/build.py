#!/usr/bin/env python3
"""Build the deployable site tree: site/ -> dist/.

Standard library only. What it does, in order:
  1. refuses dotfiles and anything outside site/;
  2. fingerprints every .css file by content hash (styles.css -> styles.<hash>.css)
     and rewrites the references in HTML, so assets can be cached immutably;
  3. stamps <meta name="helmet-duck-revision" content="<git sha>"> into every HTML
     page, which the deploy workflow reads back from the live edge;
  4. writes sitemap.xml and, if absent, robots.txt.

    python3 tools/build.py            # writes dist/
    python3 tools/build.py --out DIR  # elsewhere (the checker uses a temp dir)
"""
import argparse
import hashlib
import pathlib
import re
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
SITE_URL = "https://helmetduck.com/"
MARKER = '<meta name="helmet-duck-revision" content="%s">'


def revision():
    try:
        r = subprocess.run(["git", "rev-parse", "--short=12", "HEAD"], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=10)
        return r.stdout.strip() or "unversioned"
    except (OSError, subprocess.TimeoutExpired):
        return "unversioned"


def build(out):
    out = pathlib.Path(out)
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    files = [p for p in SITE.rglob("*") if p.is_file()]
    for p in files:
        rel = p.relative_to(SITE)
        if any(part.startswith(".") for part in rel.parts):
            raise SystemExit("refusing dotfile in site/: %s" % rel)
    # fingerprint css
    renames = {}
    for p in files:
        if p.suffix == ".css":
            digest = hashlib.sha256(p.read_bytes()).hexdigest()[:10]
            rel = p.relative_to(SITE)
            new = rel.with_name("%s.%s%s" % (rel.stem, digest, rel.suffix))
            renames[str(rel).replace("\\", "/")] = str(new).replace("\\", "/")
    rev = revision()
    pages = []
    for p in files:
        rel = str(p.relative_to(SITE)).replace("\\", "/")
        target = out / renames.get(rel, rel)
        target.parent.mkdir(parents=True, exist_ok=True)
        if p.suffix == ".html":
            text = p.read_text(encoding="utf-8")
            for old, new in renames.items():
                text = text.replace('"/%s"' % old, '"/%s"' % new).replace('"%s"' % old, '"%s"' % new)
            if "helmet-duck-revision" in text:
                text = re.sub(r'<meta name="helmet-duck-revision" content="[^"]*">', MARKER % rev, text)
            else:
                text = text.replace("</head>", "  %s\n</head>" % (MARKER % rev), 1)
            target.write_text(text, encoding="utf-8")
            pages.append(rel)
        else:
            shutil.copyfile(p, target)
    urls = [SITE_URL + ("" if page == "index.html" else page) for page in sorted(pages) if page != "404.html"]
    (out / "sitemap.xml").write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "".join("  <url><loc>%s</loc></url>\n" % u for u in urls) + "</urlset>\n", encoding="utf-8")
    if not (out / "robots.txt").exists():
        (out / "robots.txt").write_text("User-agent: *\nAllow: /\nSitemap: %ssitemap.xml\n" % SITE_URL, encoding="utf-8")
    return rev, pages, renames


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=str(ROOT / "dist"))
    a = ap.parse_args()
    rev, pages, renames = build(a.out)
    print("built %s: revision %s, %d page(s), %d fingerprinted asset(s)" % (a.out, rev, len(pages), len(renames)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
