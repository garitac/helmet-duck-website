#!/usr/bin/env python3
"""The gate CI and the deploy run before anything else: standard library only.

This repository is the brand's storefront: helmetduck.com, its infrastructure and its
watchers. The products live in their own repositories with their own gates
(garitac/helmet-duck-bushido, garitac/helmet-duck-eyes), and the marketplace that lists
them is garitac/helmet-duck, with its own gate. Nothing of theirs is checked here.

  1. the site must build; every internal href/src must resolve inside dist/; no
     <script> tag and no external stylesheet or image may appear (the CSP forbids
     them); the whole dist/ must stay under the weight budget; no dotfile may
     reach dist/; every page must carry the revision marker.
  2. every tools/*.py and tools/console/*.py must compile, the sentry and the console
     must pass their selftests, and every workflow must pin its actions to a commit SHA
     and declare its permissions.
  3. English is the only language of code, comments and copy.

Exit 0 only when everything holds. Findings are printed as a table.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUDGET_BYTES = 300 * 1024
sys.path.insert(0, str(ROOT / "tools"))
import build as sitebuild  # noqa: E402


# Cyrillic, Hebrew and Arabic, Indic, Thai, Japanese kana, CJK ideographs, Hangul and
# full-width forms, built from code points so this file stays ASCII and passes its own check.
NON_LATIN_RANGES = ((0x0400, 0x04FF), (0x0590, 0x06FF), (0x0900, 0x0DFF), (0x0E00, 0x0E7F),
                    (0x3040, 0x30FF), (0x3400, 0x4DBF), (0x4E00, 0x9FFF), (0xAC00, 0xD7AF),
                    (0xFF00, 0xFFEF))
NON_LATIN = re.compile("[" + "".join("%s-%s" % (chr(a), chr(b)) for a, b in NON_LATIN_RANGES) + "]")
TEXT_SUFFIXES = {".py", ".md", ".html", ".json", ".yml", ".yaml", ".css", ".txt", ".sh", ".svg"}


def check_english_only(rows):
    """English is the only language of code, comments and copy: no letters from
    non-Latin scripts anywhere a user or an agent reads."""
    hits = []
    for p in ROOT.rglob("*"):
        if not p.is_file() or p.suffix not in TEXT_SUFFIXES:
            continue
        rel = p.relative_to(ROOT)
        if rel.parts[0] in (".git", "dist", "node_modules", "__pycache__", ".console-cache"):
            continue
        try:
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if NON_LATIN.search(line):
                    hits.append("%s:%d" % (rel, n))
        except (OSError, UnicodeDecodeError):
            continue
    rows.append(("english only (no non-Latin scripts)", not hits, ", ".join(hits[:6]) + (" ..." if len(hits) > 6 else "")))


def check_site(rows):
    with tempfile.TemporaryDirectory() as d:
        try:
            rev, pages, _ = sitebuild.build(d)
        except SystemExit as exc:
            rows.append(("site builds", False, str(exc)))
            return
        dist = pathlib.Path(d)
        rows.append(("site builds", True, "%d page(s), revision %s" % (len(pages), rev)))
        files = [p for p in dist.rglob("*") if p.is_file()]
        total = sum(p.stat().st_size for p in files)
        rows.append(("weight under %d KB" % (BUDGET_BYTES // 1024), total <= BUDGET_BYTES, "%d KB" % (total // 1024)))
        dots = [str(p.relative_to(dist)) for p in files if any(part.startswith(".") for part in p.relative_to(dist).parts)]
        rows.append(("no dotfiles in dist", not dots, ", ".join(dots)))
        broken, scripts, external, unmarked = [], [], [], []
        for p in files:
            if p.suffix != ".html":
                continue
            html = p.read_text(encoding="utf-8")
            if "helmet-duck-revision" not in html:
                unmarked.append(p.name)
            if re.search(r"<script\b", html, re.I):
                scripts.append(p.name)
            for m in re.finditer(r'(?:href|src)="([^"#]+)"', html):
                url = m.group(1)
                if url.startswith(("mailto:", "https://", "http://")):
                    # only a stylesheet or an image fetched from elsewhere violates the CSP;
                    # canonical links, og tags and ordinary anchors may point anywhere
                    if re.search(r'<link[^>]+rel="stylesheet"[^>]+href="%s"' % re.escape(url), html) \
                            or re.search(r'<link[^>]+href="%s"[^>]+rel="stylesheet"' % re.escape(url), html) \
                            or re.search(r'<img[^>]+src="%s"' % re.escape(url), html):
                        external.append("%s -> %s" % (p.name, url))
                    continue
                target = dist / url.lstrip("/") if url.startswith("/") else p.parent / url
                if url.endswith("/"):
                    target = target / "index.html"
                if not target.exists():
                    broken.append("%s -> %s" % (p.name, url))
        rows.append(("internal links resolve", not broken, ", ".join(broken)[:120]))
        rows.append(("no scripts", not scripts, ", ".join(scripts)))
        rows.append(("no external stylesheet or image", not external, ", ".join(external)[:120]))
        rows.append(("revision marker on every page", not unmarked, ", ".join(unmarked)))


def check_tools(rows):
    """The watchers and the build must compile; the sentry and the console prove
    themselves on synthetic input; every workflow pins its actions to a commit SHA and
    declares its permissions, as the repository's Actions settings require."""
    bad = []
    for p in sorted(list((ROOT / "tools").glob("*.py")) + list((ROOT / "tools" / "console").glob("*.py"))):
        try:
            compile(p.read_text(encoding="utf-8"), str(p), "exec")
        except SyntaxError as exc:
            bad.append("%s:%s" % (p.name, exc.lineno))
    rows.append(("tools compile", not bad, ", ".join(bad)))
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "sentry.py"), "--selftest"], capture_output=True, text=True)
    ok = r.returncode == 0 and r.stdout.strip().endswith("PASS")
    rows.append(("sentry selftest", ok, "" if ok else (r.stdout.strip().splitlines() or [r.stderr[-120:]])[-1]))
    r = subprocess.run([sys.executable, str(ROOT / "tools" / "console" / "analytics.py"), "--selftest"], capture_output=True, text=True)
    ok = r.returncode == 0 and r.stdout.strip().endswith("PASS")
    rows.append(("console selftest", ok, "" if ok else (r.stdout.strip().splitlines() or [r.stderr[-120:]])[-1]))
    unpinned, unscoped = [], []
    for wf in sorted((ROOT / ".github" / "workflows").glob("*.yml")):
        text = wf.read_text(encoding="utf-8")
        for m in re.finditer(r"^\s*-?\s*uses:\s*(\S+)", text, re.M):
            if not re.search(r"@[0-9a-f]{40}$", m.group(1)):
                unpinned.append("%s: %s" % (wf.name, m.group(1)))
        if not re.search(r"^permissions:", text, re.M):
            unscoped.append(wf.name)
    rows.append(("workflow actions pinned to a commit SHA", not unpinned, ", ".join(unpinned)))
    rows.append(("workflows declare permissions", not unscoped, ", ".join(unscoped)))


def main():
    rows = []
    check_tools(rows)
    check_english_only(rows)
    check_site(rows)
    width = max(len(r[0]) for r in rows)
    for name, ok, note in rows:
        print("  %-5s %-*s %s" % ("ok" if ok else "FAIL", width, name, note))
    failed = [r for r in rows if not r[1]]
    print("\n%s" % ("CHECK PASS" if not failed else "CHECK FAIL (%d)" % len(failed)))
    return 0 if not failed else 1


if __name__ == "__main__":
    sys.exit(main())
