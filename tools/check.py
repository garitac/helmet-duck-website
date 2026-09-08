#!/usr/bin/env python3
"""The gate CI and the deploy run before anything else: standard library only.

  1. products/duck/duck.py selftest must PASS.
  2. the marketplace at the root must parse, every entry whose source is a folder of
     this repository must hold a plugin.json that agrees on the version, and the duck's
     own manifests, hooks and fixtures under products/duck must parse; hooks may
     reference only files that exist under that plugin root; the root LICENSE and the
     copy the plugin ships must be the same text.
  3. every skills/*/SKILL.md must carry frontmatter whose description is a quoted
     string (an unquoted colon silently empties the metadata at runtime).
  4. the site must build; every internal href/src must resolve inside dist/; no
     <script> tag and no external stylesheet or image may appear (the CSP forbids
     them); the whole dist/ must stay under the weight budget; no dotfile may
     reach dist/; every page must carry the revision marker.
  5. every tools/*.py and tools/console/*.py must compile, the sentry and the console
     must pass their selftests, and every workflow must pin its actions to a commit SHA
     and declare its permissions.

Exit 0 only when everything holds. Findings are printed as a table.
"""
import json
import pathlib
import re
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "products" / "duck"          # the duck: exactly what the plugin ships
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
BUDGET_BYTES = 300 * 1024
sys.path.insert(0, str(ROOT / "tools"))
import build as sitebuild  # noqa: E402


def check_selftest(rows):
    r = subprocess.run([sys.executable, str(PLUGIN / "duck.py"), "selftest"], capture_output=True, text=True)
    ok = r.returncode == 0 and r.stdout.strip().endswith("PASS")
    rows.append(("duck selftest", ok, "" if ok else r.stdout.strip().splitlines()[-1] if r.stdout.strip() else r.stderr[-200:]))


def check_marketplace(rows):
    """The marketplace at the root lists every product. An entry whose source is a
    folder of this repository must hold that plugin's manifest, and the two must agree
    on the version; an entry that points at another repository is listed as such."""
    try:
        market = json.loads(MARKETPLACE.read_text(encoding="utf-8"))
        rows.append((".claude-plugin/marketplace.json", True, "%d product(s)" % len(market.get("plugins", []))))
    except (OSError, ValueError) as exc:
        rows.append((".claude-plugin/marketplace.json", False, str(exc)[:80]))
        return
    bad = []
    for entry in market.get("plugins", []):
        name, src = entry.get("name"), entry.get("source")
        if not isinstance(src, str):
            continue  # another repository: nothing to resolve here
        manifest = ROOT / src / ".claude-plugin" / "plugin.json"
        if not manifest.exists():
            bad.append("%s: %s has no .claude-plugin/plugin.json" % (name, src))
            continue
        try:
            version = json.loads(manifest.read_text(encoding="utf-8")).get("version")
        except ValueError:
            bad.append("%s: plugin.json unreadable" % name)
            continue
        if version != entry.get("version"):
            bad.append("%s: marketplace says %s, plugin.json says %s" % (name, entry.get("version"), version))
    rows.append(("marketplace entries resolve and agree on versions", not bad, ", ".join(bad)[:120]))


def check_manifests(rows):
    """The duck's own manifests, under its plugin root."""
    for rel in (".claude-plugin/plugin.json", "hooks/hooks.json", ".codex-plugin/plugin.json", "codex/hooks.json",
                "fixtures/gates.json", "fixtures/dissent.json", "MANIFEST.json"):
        try:
            json.loads((PLUGIN / rel).read_text(encoding="utf-8"))
            rows.append(("products/duck/%s" % rel, True, ""))
        except (OSError, ValueError) as exc:
            rows.append(("products/duck/%s" % rel, False, str(exc)[:80]))
    try:
        versions = {}
        m = re.search(r'^VERSION = "([^"]+)"$', (PLUGIN / "duck.py").read_text(encoding="utf-8"), re.M)
        versions["duck.py"] = m.group(1) if m else None
        for rel in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json", "MANIFEST.json"):
            versions[rel] = json.loads((PLUGIN / rel).read_text(encoding="utf-8")).get("version")
        agree = len(set(versions.values())) == 1 and None not in versions.values()
        rows.append(("duck version agrees across duck.py, manifests and seal", agree,
                     ", ".join("%s %s" % kv for kv in versions.items()) if not agree else versions["duck.py"]))
        missing = []
        for rel in ("hooks/hooks.json", "codex/hooks.json"):
            hooks = json.loads((PLUGIN / rel).read_text())["hooks"]
            for event, groups in hooks.items():
                for g in groups:
                    for h in g["hooks"]:
                        for m in re.finditer(r'\$\{?(?:CLAUDE_)?PLUGIN_ROOT\}?/([\w./-]+)', h["command"]):
                            if not (PLUGIN / m.group(1)).exists():
                                missing.append("%s %s: %s" % (rel, event, m.group(1)))
        rows.append(("hooks reference existing files under the plugin root", not missing, ", ".join(missing)))
        codex = json.loads((PLUGIN / ".codex-plugin/plugin.json").read_text())
        refs = [codex.get("hooks", ""), codex.get("skills", ""), (codex.get("interface") or {}).get("logo", "")]
        bad = [r for r in refs if r and not (PLUGIN / r).exists()]
        rows.append(("codex manifest paths exist under the plugin root", not bad, ", ".join(bad)))
    except (OSError, ValueError, KeyError) as exc:
        rows.append(("hooks reference existing files under the plugin root", False, str(exc)[:80]))
    same = (ROOT / "LICENSE").read_bytes() == (PLUGIN / "LICENSE").read_bytes()
    rows.append(("root LICENSE and the plugin's LICENSE are the same text", same, "" if same else "they differ"))


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
        if rel.parts[0] in (".git", "dist", "node_modules", "__pycache__"):
            continue
        try:
            for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
                if NON_LATIN.search(line):
                    hits.append("%s:%d" % (rel, n))
        except (OSError, UnicodeDecodeError):
            continue
    rows.append(("english only (no non-Latin scripts)", not hits, ", ".join(hits[:6]) + (" ..." if len(hits) > 6 else "")))


def check_skills(rows):
    for skill in sorted((PLUGIN / "skills").glob("*/SKILL.md")):
        text = skill.read_text(encoding="utf-8")
        m = re.match(r"---\n(.*?)\n---\n", text, re.S)
        ok = bool(m) and bool(re.search(r'^description: "[^"\n]+"$', m.group(1), re.M))
        rows.append(("skill %s frontmatter" % skill.parent.name, ok, "" if ok else "description must be a quoted string"))


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
    """The watchers and the build must compile; the sentry proves itself on a
    synthetic log; every workflow pins its actions to a commit SHA and declares
    its permissions, as the repository's Actions settings require."""
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
    check_selftest(rows)
    check_marketplace(rows)
    check_manifests(rows)
    check_skills(rows)
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
