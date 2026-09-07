#!/usr/bin/env python3
"""Helmet Duck: the rules an AI coding agent cannot skip, because the harness refuses.

Everything an agent is told is advice, and advice is exactly what an agent skips
when it decides it already knows. Helmet Duck is not advice. A script, never the
model, evaluates a predicate at each hook event, and the harness refuses the
action or refuses to let the turn end. Thinking cannot be gated. Its
consequences can.

THE GATES (PreToolUse / Stop)
  G0  known-bad forms    --no-verify; a heredoc through ssh; a force-push; rm -rf
                         on a root; the canary literal.
  G1  overwrite unread   a Bash overwrite (>, >>, tee, sed -i, cp, mv, open(..'w'))
                         of an existing file not read this session is refused.
                         Edit/Write already refuse this in the harness; G1 closes
                         the Bash routes around that.
  G2  commit unevidenced `git commit` in a project that declares an evidence
                         command is refused unless `duck evidence` ran that same
                         command and recorded PASS within max_age_minutes against
                         the same tree (HEAD, tracked changes, untracked files).
                         `git -C dir commit` and `cd dir && git commit` are seen.
                         Opt-in per project.
  G3  stop unfinished    the turn cannot end with open dissent claims, or (opt-in)
                         a dirty worktree. Capped at two blocks in a row, then
                         allowed and logged: a gate that can loop is a spend.
  G4  self-protection    writes to the duck's own root, its state, the harness
                         settings and hooks, the override file and the project's
                         own .helmet-duck.json are refused, and so are the owner's
                         commands (override, accept, seal, licence) when an agent
                         tries to run them. A project file may tighten the gates,
                         never loosen them.
                         A duck whose sha differs from its sealed manifest fails
                         CLOSED. A gate the agent can edit is advice.
  OV  owner override     the OWNER runs `duck override` (or touches the OVERRIDE
                         file) from a terminal: every gate opens for 30 minutes,
                         logged. The agent can neither create it nor run
                         the command (G4): a person at a terminal does.

THE DISSENT CHAIR (PreToolUse, advisory, never denies)
  A deterministic classifier over the text of a pending call recognises four
  defect classes an agent repeats: judging a measurement against a cruder
  reference, certifying a sorted head as a sample, a grep or pkill that matches
  its own command line, and a text-range edit that swallows a definition. It
  prints the ONE question a check that caught the real error would have asked,
  with that class's measured default rate. Claims made in prose are opened by
  hand (`duck claim`) and closed with `repay` or `default`; the rate learns.

THE MIRROR (SessionStart)
  Sweeps the harness's own transcripts for the moments the machine caught the
  agent (gate refusals, hook denials, failed assertions, syntax errors) and
  opens every session with the count. The agent's inside view is not consulted,
  because its inside view is the problem.

WHAT IT DOES NOT DO, STATED RATHER THAN PRETENDED
  It does not see a claim made from memory in prose; no event fires when the
  model thinks. It does not see writes whose path is assembled at runtime inside
  another program. The mirror's recall is partial: a wrong claim spoken fluently
  leaves no error signature.

    duck status | selftest | evidence | seal | override
    duck claim CLASS "text" | repay ID "why" | default ID "why" | void ID "why"
    duck pending | rates | report | mirror-sweep | mirror-report | brief
    duck licence activate KEY | licence status | licence deactivate
    duck accept                              (record acceptance of RISKS.md; arms the gates)
    duck pre | post | stop | dissent          (hook entry points; event on stdin)

ACCEPTANCE OF RISK
  Until the user runs `duck accept`, the duck is installed but unarmed: every
  hook returns allow, nothing is refused, and each session and prompt carries a
  one-line notice saying so. Acceptance records the version, the time and the
  hash of the RISKS.md the user accepted, under the state directory.

TWO HARNESSES
  Claude Code and Codex send the same hook events with the same field names and
  accept the same JSON answer. Claude edits files through Write and Edit; Codex
  edits through apply_patch, whose patch text arrives in tool_input.command, so
  the duck reads the file paths out of the patch headers and applies G4 and G1
  to them exactly as it does to Write and Edit. The mirror sweeps both harnesses'
  transcripts. hooks/hooks.json is for Claude Code, codex/hooks.json for Codex.

THE LICENCE (the only network call the duck ever makes, and only when asked)
  `duck licence activate KEY` sends the key and a label for this machine to the
  licence vendor's public License API once, records the answer under the state
  directory, and shows the tier in `duck status`. Nothing is gated
  behind it yet: the record is the beginning of the paid tier, not a lock.
"""
import argparse
import hashlib
import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import tempfile
import time
from collections import Counter
from datetime import datetime, timedelta, timezone

VERSION = "0.4.0"
HOME = pathlib.Path.home()
ROOT = pathlib.Path(__file__).resolve().parent
STATE = pathlib.Path(os.environ.get("HELMET_DUCK_STATE", str(HOME / ".helmet-duck")))
OVERRIDE = pathlib.Path(os.environ.get("HELMET_DUCK_OVERRIDE", str(STATE / "OVERRIDE")))
# Which harness is calling: Claude Code or Codex. Both understand the same hook JSON, so
# this is recorded for the log and the status line rather than used to change behavior.
HARNESS = os.environ.get("HELMET_DUCK_HARNESS") or (
    "codex" if os.environ.get("PLUGIN_ROOT") and not os.environ.get("CLAUDE_PLUGIN_ROOT") else "claude")
USER_CONFIG = STATE / "config.json"
PROJECT_CONFIG = ".helmet-duck.json"
CLAIMS = STATE / "claims.jsonl"
LOG = STATE / "log.jsonl"
MANIFEST = ROOT / "MANIFEST.json"
FIXTURES_DIR = ROOT / "fixtures"
TRANSCRIPTS = HOME / ".claude" / "projects"
CANARY = "HELMET-DUCK-CANARY-DENY"
OVERRIDE_SECONDS = 30 * 60
BUDGET_MS = 150
MAX_BLOCKS_IN_ROW = 2

DEFAULTS = {
    "gates": {"G0": True, "G1": True, "G2": True, "G3": True, "G4": True},
    "exempt_roots": ["/tmp", "/private/tmp", tempfile.gettempdir(), "/dev"],
    "forbidden": [
        {"id": "no-verify", "pattern": r"--no-verify\b",
         "reason": "--no-verify skips the repository's own pre-commit guard. Never."},
        {"id": "ssh-heredoc", "pattern": r"\bssh\s+\S+[^\n]*<<",
         "reason": "heredoc through ssh: the local shell mangles it. Write the file "
                   "locally, scp it, run it."},
        {"id": "force-push", "pattern": r"\bgit\s+push\b[^\n]*(--force(?!-with-lease)\b|\s-f\b|\s\+\S)",
         "reason": "a force-push rewrites history others may hold (--force-with-lease is allowed). "
                   "If it is wanted, the owner does it from a terminal."},
        {"id": "rm-rf-root", "pattern": r"\brm\s+-[a-zA-Z]*r[a-zA-Z]*\s+(/|~|\$HOME|\.|\*)(\s|$)",
         "reason": "rm -r on a root, the home or the working directory. Never from an agent."},
    ],
    "evidence": {"command": None, "max_age_minutes": 30},
    "stop": {"require_clean_worktree": False, "require_no_open_claims": True},
    "dissent": {"floor": 0.5, "min_closures": 3},
    "licence": {"vendor": "lemonsqueezy", "api": "https://api.lemonsqueezy.com/v1/licenses"},
}
LICENCE_FILE = STATE / "licence.json"
ACCEPTED_FILE = STATE / "accepted.json"
RISKS_FILE = ROOT / "RISKS.md"
RISKS_URL = "https://helmetduck.com/risks.html"
UNARMED_NOTICE = ("HELMET DUCK is installed but not armed: it refuses nothing until the risks at %s "
                  "are accepted with `duck accept`." % RISKS_URL)

PROTECTED_ALWAYS = [str(ROOT), str(STATE), str(OVERRIDE), str(HOME / ".claude" / "settings.json"),
                    str(HOME / ".claude" / "hooks"), str(HOME / ".codex" / "hooks.json"),
                    str(HOME / ".codex" / "config.toml")]


# ------------------------------------------------------------------ plumbing
def _sha(path):
    return hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest()


def _log(rec):
    STATE.mkdir(parents=True, exist_ok=True)
    rec = dict(rec, at=int(time.time()))
    with LOG.open("a") as fh:
        fh.write(json.dumps(rec, sort_keys=True) + "\n")


def _deep_merge(a, b):
    out = dict(a)
    for k, v in (b or {}).items():
        out[k] = _deep_merge(out[k], v) if isinstance(v, dict) and isinstance(out.get(k), dict) else v
    return out


def _project_root(cwd):
    """The nearest ancestor holding a project config or a .git, else None."""
    here = pathlib.Path(cwd or os.getcwd()).resolve()
    for p in [here, *here.parents]:
        if p == HOME:
            break
        if (p / PROJECT_CONFIG).is_file() or (p / ".git").exists():
            return p
    return None


def _config(cwd):
    cfg = DEFAULTS
    try:
        if USER_CONFIG.is_file():
            cfg = _deep_merge(cfg, json.loads(USER_CONFIG.read_text()))
    except (OSError, ValueError):
        pass
    root = _project_root(cwd)
    if root and (root / PROJECT_CONFIG).is_file():
        try:
            cfg = _deep_merge(cfg, _project_allowed(json.loads((root / PROJECT_CONFIG).read_text()), cfg))
        except (OSError, ValueError):
            pass
    return cfg, root


PROJECT_MAY_SET = ("evidence", "stop", "dissent")


def _project_allowed(proj, base):
    """A project's .helmet-duck.json may tighten, never loosen. It declares its evidence
    command, its stop rules and its dissent floor, and may ADD forbidden patterns.
    Gates, exempt roots and the licence vendor come only from the defaults and the
    owner's protected user config, so a file the agent can write cannot disarm it."""
    out = {k: v for k, v in (proj or {}).items() if k in PROJECT_MAY_SET}
    extra = [r for r in (proj or {}).get("forbidden", []) or [] if isinstance(r, dict) and r.get("pattern")]
    if extra:
        out["forbidden"] = list(base.get("forbidden", [])) + extra
    return out


def _state_path(sid):
    return STATE / "sessions" / ("%s.json" % re.sub(r"[^A-Za-z0-9_.-]", "_", sid or "nosession"))


def _state(sid):
    p = _state_path(sid)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except ValueError:
            pass
    return {"created": int(time.time()), "reads": [], "blocks_in_row": 0}


def _save_state(sid, st):
    _state_path(sid).parent.mkdir(parents=True, exist_ok=True)
    _state_path(sid).write_text(json.dumps(st))


def _override_open():
    try:
        return time.time() - OVERRIDE.stat().st_mtime < OVERRIDE_SECONDS
    except FileNotFoundError:
        return False


def _accepted():
    """True only when the user has recorded acceptance of the risks with `duck accept`."""
    try:
        return json.loads(ACCEPTED_FILE.read_text()).get("accepted") is True
    except (OSError, ValueError):
        return False


def _drifted():
    """Fail closed: a sealed manifest that exists and disagrees with this file."""
    if not MANIFEST.exists():
        return None
    try:
        want = json.loads(MANIFEST.read_text()).get("duck_sha256")
    except ValueError:
        return True
    return want != _sha(pathlib.Path(__file__).resolve())


def _norm(tok, cwd):
    t = tok.strip("'\"`;|&(){}")
    if not t or t.startswith("-"):
        return None
    t = t.replace("${HOME}", str(HOME)).replace("$HOME", str(HOME))
    if t.startswith("~"):
        t = str(HOME) + t[1:]
    if not t.startswith("/"):
        t = os.path.join(cwd or os.getcwd(), t)
    return os.path.normpath(t)


def _under(path, roots):
    """Containment in either spelling: as given, and with symlinks resolved, because a
    macOS temp path arrives as /var/... and resolves to /private/var/..."""
    forms = {path, os.path.realpath(path)}
    for r in roots:
        for root in {r, os.path.realpath(r)}:
            for c in forms:
                if c == root or c.startswith(root.rstrip("/") + "/"):
                    return True
    return False


_REDIRECT = re.compile(r"(?<![<>0-9&])>{1,2}\s*([^\s;|&)]+)")
_TEE = re.compile(r"\btee\s+(?:-a\s+)?([^\s;|&]+)")
_SED_I = re.compile(r"\bsed\s+-i\S*\s+(.*)")
_CP_MV = re.compile(r"\b(?:cp|mv)\s+(?:-\S+\s+)*(\S+)\s+([^\s;|&]+)")
_OPEN_W = re.compile(r"open\(\s*['\"]([^'\"]+)['\"]\s*,\s*['\"][wa]")
_WRITE_VERB = re.compile(r"(?<![<>0-9&])>{1,2}|\btee\b|\bsed\s+-i|\bcp\s|\bmv\s|\brm\s|\btouch\s|\bchmod\s|['\"][wa]['\"]\s*\)|\.write\(")
# Verbs that put a file's content in front of the agent. wc, ls, stat, file, du and
# checksums say something about a file without showing it, so they do not count.
_READ_VERB = re.compile(r"\b(cat|head|tail|sed\s+-n|grep|less|more|bat|diff|awk|cut|sort|jq)\b")
_TOKENS = re.compile(r"[^\s;|&()<>]+")
# The owner's commands. They open, arm, seal or license the duck; an agent never runs
# them. A person runs them in a terminal, where no hook fires.
_OWNER_CMD = re.compile(r"(?:^|[\s;&|(/])duck(?:\.py)?\s+(override|accept|seal|licence)\b")
# git's global options: those that take a separate argument, and the rest as flags.
_GIT_WITH_ARG = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--exec-path", "--super-prefix",
                 "--config-env", "--list-cmds", "--attr-source"}
_SEGMENT = re.compile(r"\s*(?:;|&&|\|\||\||\n)\s*")


def _git_commit_dirs(cmd, cwd):
    """Every directory in which the command would run `git commit`, honouring `cd` in
    earlier segments and git's -C. Tokenised, not pattern-matched, so `git -C repo
    commit` and `git -c key=value commit` are seen."""
    here = cwd or os.getcwd()
    dirs = []
    for seg in _SEGMENT.split(cmd):
        try:
            toks = shlex.split(seg)
        except ValueError:
            toks = seg.split()
        if not toks:
            continue
        if toks[0] == "cd" and len(toks) > 1:
            here = os.path.normpath(os.path.join(here, os.path.expanduser(toks[1])))
            continue
        gi = next((i for i, t in enumerate(toks) if t == "git" or t.endswith("/git")), None)
        if gi is None:
            continue
        target, i = here, gi + 1
        while i < len(toks):
            t = toks[i]
            if t in _GIT_WITH_ARG:
                if t == "-C" and i + 1 < len(toks):
                    target = os.path.normpath(os.path.join(target, os.path.expanduser(toks[i + 1])))
                i += 2
            elif t.startswith("-"):
                i += 1
            else:
                break
        if i < len(toks) and toks[i] == "commit":
            dirs.append(target)
    return dirs


def _read_candidates(cmd, cwd):
    """Every token of a reading command that names an existing file, bare names
    included, so `cat README.md` counts as reading README.md."""
    out = []
    for tok in _TOKENS.findall(cmd):
        if tok.startswith("-"):
            continue
        p = _norm(tok, cwd)
        if p and os.path.isfile(p):
            out.append(p)
    return out


def _tree_fingerprint(root):
    """What the evidence ran against: HEAD, every tracked change (staged or not) and
    every untracked file's name and content. Staging alone does not change it;
    editing anything does, so evidence cannot vouch for a tree it never saw."""
    h = hashlib.sha256()

    def git(*args):
        try:
            r = subprocess.run(["git", *args], cwd=str(root), capture_output=True, timeout=30)
            return r.stdout if r.returncode == 0 else b""
        except (OSError, subprocess.TimeoutExpired):
            return b""
    h.update(git("rev-parse", "HEAD"))
    h.update(git("diff", "HEAD", "--binary", "--no-ext-diff"))
    for name in git("ls-files", "--others", "--exclude-standard", "-z").split(b"\0"):
        if not name:
            continue
        h.update(name)
        f = pathlib.Path(root, name.decode("utf-8", "replace"))
        try:
            if f.is_file():
                h.update(hashlib.sha256(f.read_bytes()).digest())
        except OSError:
            pass
    return h.hexdigest()


def _overwrite_targets(cmd, cwd):
    out = []
    for m in _REDIRECT.finditer(cmd):
        out.append(m.group(1))
    for m in _TEE.finditer(cmd):
        out.append(m.group(1))
    for m in _CP_MV.finditer(cmd):
        out.append(m.group(2))
    for m in _OPEN_W.finditer(cmd):
        out.append(m.group(1))
    for m in _SED_I.finditer(cmd):
        out.extend(_TOKENS.findall(m.group(1)))
    paths = []
    for tok in out:
        p = _norm(tok, cwd)
        if p and not p.startswith("/dev/"):
            paths.append(p)
    return paths


def _mentioned_paths(cmd, cwd):
    paths = []
    for tok in _TOKENS.findall(cmd):
        if "/" in tok or tok.startswith("~"):
            p = _norm(tok, cwd)
            if p:
                paths.append(p)
    return paths


def _deny(gate, reason):
    # One answer for both harnesses: Claude Code and Codex both read this JSON.
    print(json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse",
        "permissionDecision": "deny",
        "permissionDecisionReason": "GATE %s: %s" % (gate, reason)}}))


_PATCH_FILE = re.compile(r"^\*\*\* (Add|Update|Delete) File: (.+?)\s*$", re.M)
_PATCH_MOVE = re.compile(r"^\*\*\* Move to: (.+?)\s*$", re.M)
PATCH_TOOLS = ("apply_patch", "ApplyPatch")


def _patch_paths(text, cwd):
    """(operation, absolute path) for every file a Codex apply_patch touches."""
    out = []
    for m in _PATCH_FILE.finditer(text):
        p = _norm(m.group(2), cwd)
        if p:
            out.append((m.group(1), p))
    for m in _PATCH_MOVE.finditer(text):
        p = _norm(m.group(1), cwd)
        if p:
            out.append(("Move", p))
    return out


# --------------------------------------------------------------------- gates
def gate_pre(ev, cfg, root):
    """Return (gate, reason) to deny, or (None, None) to allow."""
    gates = cfg["gates"]
    tool = ev.get("tool_name", "")
    ti = ev.get("tool_input", {}) or {}
    cwd = ev.get("cwd")
    sid = ev.get("session_id")
    protected = PROTECTED_ALWAYS + ([str(root / PROJECT_CONFIG)] if root is not None else [])

    if tool in ("Write", "Edit", "MultiEdit"):
        p = _norm(str(ti.get("file_path", "")), cwd)
        if gates.get("G4") and p and _under(p, protected):
            return "G4", ("%s is protected: the duck, its state, the harness settings and the "
                          "override are edited only by the owner. If this change is wanted, "
                          "the owner runs `duck override` from a terminal." % p)
        return None, None

    if tool in PATCH_TOOLS:
        # Codex edits files through a patch; its headers name every file touched.
        text = str(ti.get("command") or ti.get("patch") or ti.get("input") or "")
        paths = _patch_paths(text, cwd)
        if gates.get("G4"):
            for _, p in paths:
                if _under(p, protected):
                    return "G4", ("%s is protected: the duck, its state, the harness settings and "
                                  "the override are edited only by the owner (`duck override` opens "
                                  "them for 30 minutes)." % p)
        if gates.get("G1"):
            reads = set(_state(sid).get("reads", []))
            for op, p in paths:
                if op == "Update" and not _under(p, cfg["exempt_roots"]) and os.path.isfile(p) and p not in reads:
                    return "G1", ("patch to %s, which was not read this session. Read it first "
                                  "(cat, sed -n or grep it), then patch. Blind edits of existing "
                                  "files are how notes get appended unread." % p)
        return None, None

    cmd = str(ti.get("command", ""))
    if not cmd:
        return None, None
    if gates.get("G0"):
        if CANARY in cmd:
            return "G0", "canary: the deny channel is live"
        for rule in cfg["forbidden"]:
            try:
                if re.search(rule["pattern"], cmd):
                    return "G0", rule["reason"]
            except re.error:
                continue

    if gates.get("G4"):
        m = _OWNER_CMD.search(cmd)
        if m:
            return "G4", ("`duck %s` is the owner's command. An agent never runs it; a person runs it "
                          "from a terminal, where no hook fires. Ask the owner." % m.group(1))
    if gates.get("G4") and _WRITE_VERB.search(cmd):
        # paths named with a slash anywhere in the command, and the resolved targets of
        # redirects, tee, cp, mv and sed -i, so a bare `> .helmet-duck.json` is seen too
        for p in _mentioned_paths(cmd, cwd) + _overwrite_targets(cmd, cwd):
            if _under(p, protected):
                return "G4", ("%s is protected: the duck, its state, the harness settings and "
                              "the override are written only by the owner (`duck override` "
                              "opens them for 30 minutes)." % p)

    if gates.get("G2"):
        for target in _git_commit_dirs(cmd, cwd):
            cfg2, root2 = _config(target)
            if root2 is None or not cfg2["evidence"].get("command"):
                continue
            ok, why = _evidence_fresh(root2, cfg2)
            if not ok:
                return "G2", ("commit without evidence in %s: %s. Run `duck evidence` (it runs the "
                              "project's declared check and records the result) and commit within "
                              "%d minutes, without changing the tree in between."
                              % (root2, why, int(cfg2["evidence"].get("max_age_minutes", 30))))

    if gates.get("G1"):
        st = _state(sid)
        reads = set(st.get("reads", []))
        for p in _overwrite_targets(cmd, cwd):
            if _under(p, cfg["exempt_roots"]):
                continue
            if os.path.isfile(p) and p not in reads:
                return "G1", ("overwrite of %s, which was not read this session. Read it first "
                              "(Read tool, or cat/sed -n/grep it), then write. Blind edits of "
                              "existing files are how notes get appended unread." % p)
    return None, None


def _evidence_path(root):
    return STATE / "evidence" / (hashlib.sha1(str(root).encode()).hexdigest()[:16] + ".json")


def _evidence_fresh(root, cfg):
    p = _evidence_path(root)
    if not p.exists():
        return False, "no evidence recorded for this project"
    try:
        e = json.loads(p.read_text())
    except ValueError:
        return False, "evidence record unreadable"
    age = time.time() - e.get("at", 0)
    if not e.get("ok"):
        return False, "last evidence run FAILED"
    limit = 60 * float(cfg["evidence"].get("max_age_minutes", 30))
    if age > limit:
        return False, "evidence is %d minutes old" % (age / 60)
    if e.get("command") != cfg["evidence"].get("command"):
        return False, "the evidence was recorded for a different check command"
    if e.get("tree") != _tree_fingerprint(root):
        return False, "the tree changed after the evidence run"
    return True, "fresh, for this command and this tree"


def cmd_pre(ev):
    sid = ev.get("session_id")
    if not _accepted():
        _log({"event": "pre", "session": sid, "tool": ev.get("tool_name"), "decision": "unarmed"})
        return 0
    if _override_open():
        _log({"event": "pre", "session": sid, "tool": ev.get("tool_name"), "decision": "override"})
        return 0
    if _drifted():
        _deny("G4", "the installed duck differs from its sealed manifest; failing closed. "
                    "The owner re-installs or re-seals under override.")
        _log({"event": "pre", "session": sid, "decision": "deny", "gate": "G4-drift"})
        return 0
    cfg, root = _config(ev.get("cwd"))
    gate, reason = gate_pre(ev, cfg, root)
    ti = ev.get("tool_input") or {}
    shown = str(ti.get("command", ti.get("file_path", "")))
    _log({"event": "pre", "session": sid, "tool": ev.get("tool_name"),
          "decision": "deny" if gate else "allow", "gate": gate,
          "reason": (reason or "")[:200], "cmd": shown[:200]})
    if gate:
        _deny(gate, reason)
    return 0


def cmd_post(ev):
    """Record what was read, so G1 can tell a read edit from a blind one."""
    sid = ev.get("session_id")
    tool = ev.get("tool_name", "")
    ti = ev.get("tool_input", {}) or {}
    cwd = ev.get("cwd")
    st = _state(sid)
    reads = set(st.get("reads", []))
    before = len(reads)
    if tool in ("Read", "Write", "Edit", "MultiEdit"):
        # a file the agent just read, wrote or edited through the harness is a
        # file it knows; a later shell append to it is not a blind edit
        p = _norm(str(ti.get("file_path", "")), cwd)
        if p:
            reads.add(p)
    elif tool == "Grep":
        p = _norm(str(ti.get("path", "")), cwd)
        if p and os.path.isfile(p):
            reads.add(p)
    elif tool in PATCH_TOOLS:
        text = str(ti.get("command") or ti.get("patch") or ti.get("input") or "")
        for _, p in _patch_paths(text, cwd):
            reads.add(p)
    elif tool == "Bash":
        cmd = str(ti.get("command", ""))
        if _READ_VERB.search(cmd):
            for p in _read_candidates(cmd, cwd):
                reads.add(p)
    if len(reads) != before:
        st["reads"] = sorted(reads)
        _save_state(sid, st)
    return 0


def _worktree_dirty(root):
    try:
        r = subprocess.run(["git", "status", "--porcelain"], cwd=str(root),
                           capture_output=True, text=True, timeout=20)
        return r.stdout.count("\n") if r.returncode == 0 else 0
    except (OSError, subprocess.TimeoutExpired):
        return 0


def _problems(cfg, root):
    problems = []
    if cfg["stop"].get("require_no_open_claims", True):
        n = len(_open_claims())
        if n:
            problems.append("%d open dissent claim(s): close each with `duck repay|default|void ID \"why\"`" % n)
    if cfg["stop"].get("require_clean_worktree") and root is not None:
        d = _worktree_dirty(root)
        if d:
            problems.append("worktree dirty in %s (%d path(s)): commit or restore" % (root, d))
    return problems


def cmd_stop(ev):
    sid = ev.get("session_id")
    if not _accepted():
        return 0
    if _override_open():
        _log({"event": "stop", "session": sid, "decision": "override"})
        return 0
    cfg, root = _config(ev.get("cwd"))
    st = _state(sid)
    if not cfg["gates"].get("G3"):
        return 0
    problems = ["installed duck differs from its sealed manifest (fail closed)"] if _drifted() else _problems(cfg, root)
    if not problems:
        st["blocks_in_row"] = 0
        _save_state(sid, st)
        _log({"event": "stop", "session": sid, "decision": "allow"})
        return 0
    st["blocks_in_row"] = st.get("blocks_in_row", 0) + 1
    _save_state(sid, st)
    if st["blocks_in_row"] > MAX_BLOCKS_IN_ROW:
        _log({"event": "stop", "session": sid, "decision": "cap", "problems": problems})
        return 0
    _log({"event": "stop", "session": sid, "decision": "block", "problems": problems})
    sys.stderr.write("GATE G3: the turn cannot end yet (%d of %d blocks):\n  - %s\n"
                     % (st["blocks_in_row"], MAX_BLOCKS_IN_ROW, "\n  - ".join(problems)))
    return 2


# ------------------------------------------------------------- dissent chair
CLASSES = {
    "reference-vs-measurement": {
        "question": "What is the reference's own uncertainty, and is it smaller than this "
                    "tolerance? A check judged by a cruder ruler measures the ruler.",
    },
    "convenient-sample": {
        "question": "Does this sample cover the range the downstream use covers? The head of "
                    "a sorted file certifies the head of a sorted file.",
    },
    "self-match": {
        "question": "Does this pattern appear in the command that runs it? pkill, pgrep and "
                    "grep -c on a name match their own command line.",
    },
    "edit-by-text-range": {
        "question": "Are both anchors present, and is there a definition between them that "
                    "this slice will swallow?",
    },
    "existence-from-memory": {
        "question": "Named location checked, or is this from memory?",
    },
    "diagnosis-stated-as-certain": {
        "question": "Recorded as a prediction before the fix, so it can be wrong?",
    },
}
_GATE_FN = re.compile(r"def\s+(gate_|monitor|check_|selftest|test_)\w*\s*\(")
_TOL = re.compile(r"(<|<=)\s*[0-9.]*e-\d+|\btol\s*=\s*[0-9.]*e-\d+")
_MONITOR_WORD = re.compile(r"MONITORS?\b|\bmonitor\w*\s*=|\bworst\w*\s*=|\breturn\s+0\s+if\b")
_SAMPLE = re.compile(r"\b_load\([^)]*limit\s*=|\brows\[\s*:\s*\d+\s*\]|\.head\(\s*\d*\s*\)|\bLIMIT\s+\d+\b")
_TABLE_WORD = re.compile(r"\b(_load|loadtxt|readlines|read_csv|\.tsv|\.csv|DATA|rows|SELECT)\b")
_PROC = re.compile(r"\b(pkill|pgrep)\s+-f\s+([\"']?)([^\"'\s;|&]+)|grep\s+-c\s+([\"'])([^\"']+)\4")
_SLICE = re.compile(r"\w+\[\s*\w+\.index\([^)]*\)\s*:\s*\w+\.index\([^)]*\)\s*\]")


def _text_of(event):
    ti = event.get("tool_input", {}) or {}
    return "\n".join(v for k in ("command", "content", "new_string", "old_string")
                     for v in [ti.get(k)] if isinstance(v, str))


def classify(text):
    hits = []
    if _TOL.search(text) and (_GATE_FN.search(text) or _MONITOR_WORD.search(text)):
        hits.append("reference-vs-measurement")
    if _SAMPLE.search(text) and _TABLE_WORD.search(text):
        hits.append("convenient-sample")
    for m in _PROC.finditer(text):
        pat = m.group(3) or m.group(5) or ""
        literal = re.sub(r"\[(.)\]", r"\1", pat)
        if literal and text.count(literal) >= (2 if pat == literal else 1):
            hits.append("self-match")
            break
    if _SLICE.search(text):
        hits.append("edit-by-text-range")
    return hits


def _append_claim(record):
    CLAIMS.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(CLAIMS, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, (json.dumps(record, sort_keys=True) + "\n").encode())
    finally:
        os.close(fd)


def _read_claims():
    if not CLAIMS.exists():
        return []
    out = []
    for l in CLAIMS.read_text().splitlines():
        if l.strip():
            try:
                out.append(json.loads(l))
            except ValueError:
                continue
    return out


def _open_claims():
    recs = _read_claims()
    closed = {r["id"] for r in recs if r.get("kind") in ("repay", "default", "void")}
    return [r for r in recs if r.get("kind") in ("claim", "card") and r.get("id") not in closed]


def rates(records=None):
    records = _read_claims() if records is None else records
    tally = {c: [0, 0] for c in CLASSES}
    for r in records:
        c = r.get("class")
        if c in tally:
            if r.get("kind") == "repay":
                tally[c][0] += 1
            elif r.get("kind") == "default":
                tally[c][1] += 1
    return {c: {"repaid": a, "defaulted": b, "rate": (b / (a + b)) if (a + b) else None}
            for c, (a, b) in tally.items()}


def _card(cls, r):
    if r["rate"] is None:
        head = "DISSENT [%s] no record yet" % cls
    else:
        head = "DISSENT [%s] default rate %.2f (%d repaid / %d defaulted)" % (
            cls, r["rate"], r["repaid"], r["defaulted"])
    return "%s: %s" % (head, CLASSES[cls]["question"])


def dissent_cards(event, cfg):
    text = _text_of(event)
    hits = classify(text)
    if not hits:
        return []
    rt = rates()
    floor = float(cfg["dissent"].get("floor", 0.5))
    min_closures = int(cfg["dissent"].get("min_closures", 3))
    cards = []
    for cls in hits:
        r = rt[cls]
        closures = r["repaid"] + r["defaulted"]
        if closures >= min_closures and r["rate"] is not None and r["rate"] < floor:
            continue                        # measured harmless for this user: stay quiet
        cid = hashlib.sha1(("card|%s|%s|%.6f" % (cls, text[:200], time.time())).encode()).hexdigest()[:10]
        _append_claim({"kind": "card", "id": cid, "class": cls, "tool": event.get("tool_name"),
                       "at": int(time.time()), "excerpt": text[:240]})
        cards.append(_card(cls, r))
    return cards


def cmd_dissent(ev):
    if not _accepted():
        return 0
    cfg, _ = _config(ev.get("cwd"))
    try:
        cards = dissent_cards(ev, cfg)
    except Exception:
        cards = []                          # advisory never breaks a call
    if cards:
        # additionalContext is read by both harnesses
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                                 "additionalContext": "\n".join(cards)}}))
    return 0


# -------------------------------------------------------------------- mirror
MIRROR_STATE = STATE / "mirror"
SIGNATURES = [
    ("gate-refusal", re.compile(r"GATE (G\d)\b")),
    ("gate-refusal", re.compile(r"REFUSED ([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)")),
    ("hook-deny", re.compile(r"(?:blocked by|denied by).{0,40}hook", re.I)),
    ("permission-denied", re.compile(r"[Pp]ermission denied: (/[\w./-]{4,120})")),
    ("assertion-failed", re.compile(r"AssertionError(?:: (.{0,100}))?")),
    ("syntax-error", re.compile(r"SyntaxError: (.{0,100})")),
]
TEST_MARKERS = re.compile(r"selftest|self-test|PASS|passed|pytest|unittest|expect_exit|fixture", re.I)
TS_RE = re.compile(r'"timestamp"\s*:\s*"([0-9T:.\-+Z]{19,35})"')


# (root, the marker a line must carry to be a TOOL RESULT rather than the agent's own words, lane label)
TRANSCRIPT_ROOTS = (
    (TRANSCRIPTS, '"tool_result"', None),                                  # Claude Code: one dir per project
    (HOME / ".codex" / "sessions", '"function_call_output"', "codex"),      # Codex rollouts
    (HOME / ".codex" / "archived_sessions", '"function_call_output"', "codex"),
)


def mirror_sweep(days):
    cutoff = datetime.now(timezone.utc) - timedelta(days=days)
    events, files = [], 0
    roots = [(r, m, l) for r, m, l in TRANSCRIPT_ROOTS if r.exists()]
    if not roots:
        print("mirror: no transcripts found under %s" % ", ".join(str(r) for r, _, _ in TRANSCRIPT_ROOTS))
        return
    for root, marker, label in roots:
        for f in root.rglob("*.jsonl"):
            try:
                mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            except OSError:
                continue
            if mtime < cutoff:
                continue
            lane = label or f.relative_to(root).parts[0]
            files += 1
            try:
                with open(f, errors="replace") as handle:
                    for line in handle:
                        if marker not in line:
                            continue        # what the MACHINE said, never what the agent wrote
                        for kind, sig in SIGNATURES:
                            m = sig.search(line)
                            if not m:
                                continue
                            ts = TS_RE.search(line)
                            at = ts.group(1) if ts else mtime.isoformat(timespec="seconds")
                            if at[:10] < cutoff.isoformat()[:10]:
                                break
                            events.append({"at": at, "lane": lane, "kind": kind,
                                           "detail": (m.group(1) or "").strip()[:120] if m.groups() else "",
                                           "in_test": bool(TEST_MARKERS.search(line)),
                                           "transcript": f.name})
                            break
            except OSError:
                continue
    MIRROR_STATE.mkdir(parents=True, exist_ok=True)
    with (MIRROR_STATE / "events.jsonl").open("w") as fh:
        for e in sorted(events, key=lambda x: x["at"]):
            fh.write(json.dumps(e, sort_keys=True) + "\n")
    print("mirror: swept %d transcripts (%dd window) -> %d events" % (files, days, len(events)))


def _mirror_events():
    p = MIRROR_STATE / "events.jsonl"
    return [json.loads(l) for l in p.read_text().splitlines() if l] if p.exists() else []


def mirror_report():
    events = _mirror_events()
    if not events:
        print("mirror: no events swept yet; run `duck mirror-sweep`")
        return 0
    live = [e for e in events if not e["in_test"]]
    lines = ["# Mirror report - %s" % datetime.now(timezone.utc).date(), "",
             "%d events where a gate, guard or check caught the agent (+%d raised inside test "
             "suites, counted apart: a gate proving itself is not a catch)." % (len(live), len(events) - len(live)),
             "", "## By kind"]
    lines += ["- %s: %d" % (k, n) for k, n in Counter(e["kind"] for e in live).most_common()]
    lines += ["", "## By day"] + ["- %s: %d" % (d, n) for d, n in sorted(Counter(e["at"][:10] for e in live).items())]
    lines += ["", "## By project"] + ["- %s: %d" % (l[:60], n) for l, n in Counter(e["lane"] for e in live).most_common()]
    lines += ["", "## Latest five"] + ["- %s [%s] %s" % (e["at"], e["kind"], e["detail"] or "(no detail)") for e in live[-5:]]
    lines += ["", "## Limits",
              "- Recall is partial: a wrong claim in fluent prose leaves no error signature.",
              "- Signatures are text-level; an unfamiliar failure shape is missed.",
              "- assertion-failed includes deliberate red-first test runs. Read the samples before the totals."]
    text = "\n".join(lines)
    MIRROR_STATE.mkdir(parents=True, exist_ok=True)
    (MIRROR_STATE / "REPORT.md").write_text(text + "\n")
    print(text)
    return 0


def mirror_brief():
    if not _accepted():
        print(UNARMED_NOTICE)
    events = [e for e in _mirror_events() if not e["in_test"]]
    week = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    recent = [e for e in events if e["at"] >= week]
    if not recent:
        print("HELMET DUCK (7d): no recorded catches. Recall is partial; absence is not innocence.")
        return 0
    tally = ", ".join("%d %s" % (n, k) for k, n in Counter(e["kind"] for e in recent).most_common())
    last = recent[-1]
    print("HELMET DUCK (7d): the machinery caught this agent %d times - %s." % (len(recent), tally))
    print(("Latest: %s [%s] %s" % (last["at"][:16], last["kind"], last["detail"] or "")).rstrip())
    print("Before asserting from memory, remember these were all spoken with full confidence.")
    return 0


# --------------------------------------------------------------- maintenance
def cmd_evidence(cwd=None):
    cfg, root = _config(cwd)
    command = cfg["evidence"].get("command")
    if root is None or not command:
        print("no evidence command declared. Put {\"evidence\": {\"command\": \"<your test command>\"}} "
              "in %s at the project root to arm G2." % PROJECT_CONFIG)
        return 1
    t0 = time.time()
    r = subprocess.run(command, shell=True, cwd=str(root), capture_output=True, text=True)
    ok = r.returncode == 0
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True).stdout.strip() or None
    p = _evidence_path(root)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"at": int(time.time()), "ok": ok, "command": command, "root": str(root),
                             "head": head, "tree": _tree_fingerprint(root), "seconds": round(time.time() - t0, 1),
                             "tail": (r.stdout + r.stderr)[-2000:]}, indent=1))
    _log({"event": "evidence", "decision": "PASS" if ok else "FAIL", "root": str(root)})
    print((r.stdout + r.stderr).strip()[-1500:])
    print("\nEVIDENCE %s -- commits in %s %s for %d minutes" % (
        "PASS" if ok else "FAIL", root, "open" if ok else "refused", int(cfg["evidence"].get("max_age_minutes", 30))))
    return 0 if ok else 1


def cmd_seal():
    """Write MANIFEST.json beside the duck: after this, an edited duck fails closed."""
    fixtures = {f.name: _sha(f) for f in sorted(FIXTURES_DIR.glob("*.json"))} if FIXTURES_DIR.exists() else {}
    MANIFEST.write_text(json.dumps({"duck_sha256": _sha(pathlib.Path(__file__).resolve()),
                                    "fixtures_sha256": fixtures, "version": VERSION,
                                    "sealed_at": int(time.time())}, indent=1) + "\n")
    print("sealed %s (%s)" % (MANIFEST, _sha(pathlib.Path(__file__).resolve())[:16]))
    return 0


def cmd_accept():
    """Record that the user has read RISKS.md and accepts it; this arms the gates."""
    STATE.mkdir(parents=True, exist_ok=True)
    record = {"accepted": True, "version": VERSION, "risks_url": RISKS_URL,
              "risks_sha256": _sha(RISKS_FILE) if RISKS_FILE.exists() else None,
              "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
              "user": os.environ.get("USER", "")}
    ACCEPTED_FILE.write_text(json.dumps(record, indent=1))
    _log({"event": "accept", "decision": "accepted", "version": VERSION})
    print("accepted: Helmet Duck %s is armed for this user. Risks: %s" % (VERSION, RISKS_URL))
    print("Withdraw at any time by uninstalling the plugin or deleting %s" % ACCEPTED_FILE)
    return 0


def cmd_override():
    STATE.mkdir(parents=True, exist_ok=True)
    OVERRIDE.touch()
    _log({"event": "override", "decision": "opened"})
    print("override open: every gate allows for %d minutes (%s)" % (OVERRIDE_SECONDS // 60, OVERRIDE))
    return 0


# ------------------------------------------------------------------ licence
def _licence_call(cfg, action, fields):
    """One POST to the vendor's License API (form-encoded, JSON back). Lemon Squeezy's
    endpoints are /activate (license_key, instance_name), /validate and /deactivate
    (license_key, instance_id); the answer carries activated/valid/deactivated, an
    error string or null, license_key, instance and meta (product, variant, customer)."""
    import urllib.error
    import urllib.parse
    import urllib.request
    url = "%s/%s" % (cfg["licence"]["api"].rstrip("/"), action)
    req = urllib.request.Request(url, data=urllib.parse.urlencode(fields).encode(),
                                 headers={"Accept": "application/json",
                                          "User-Agent": "helmet-duck/%s" % VERSION}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.loads(r.read().decode("utf-8") or "{}")
    except urllib.error.HTTPError as exc:
        try:
            return json.loads(exc.read().decode("utf-8") or "{}")
        except ValueError:
            return {"error": "HTTP %s from the licence vendor" % exc.code}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"error": "could not reach the licence vendor: %s" % exc}


def _licence_record():
    if not LICENCE_FILE.exists():
        return None
    try:
        return json.loads(LICENCE_FILE.read_text())
    except ValueError:
        return None


def cmd_licence(action, key=None):
    cfg, _ = _config(None)
    if cfg["licence"].get("vendor") != "lemonsqueezy":
        print("unknown licence vendor %r; only lemonsqueezy is implemented" % cfg["licence"].get("vendor"))
        return 1
    rec = _licence_record()
    if action == "status":
        if not rec:
            print("tier: free (no licence activated)")
            return 0
        print("tier: %s" % rec.get("tier", "personal"))
        print("product: %s / %s" % (rec.get("product"), rec.get("variant")))
        print("instance: %s (%s)" % (rec.get("instance_id"), rec.get("instance_name")))
        print("activated: %s" % rec.get("activated_at"))
        print("key: %s" % (rec.get("key", "")[:8] + "..." if rec.get("key") else "?"))
        return 0
    if action == "activate":
        if not key:
            print("usage: duck licence activate KEY")
            return 1
        instance_name = "%s@%s" % (os.environ.get("USER", "user"), os.uname().nodename) if hasattr(os, "uname") else "helmet-duck"
        ans = _licence_call(cfg, "activate", {"license_key": key, "instance_name": instance_name})
        if not ans.get("activated"):
            print("activation refused: %s" % (ans.get("error") or "no reason given"))
            _log({"event": "licence", "decision": "refused", "reason": str(ans.get("error"))[:120]})
            return 1
        meta = ans.get("meta") or {}
        lk = ans.get("license_key") or {}
        rec = {"vendor": "lemonsqueezy", "tier": "personal", "key": key,
               "instance_id": (ans.get("instance") or {}).get("id"), "instance_name": instance_name,
               "product": meta.get("product_name"), "variant": meta.get("variant_name"),
               "customer_email": meta.get("customer_email"), "status": lk.get("status"),
               "activation_usage": lk.get("activation_usage"), "activation_limit": lk.get("activation_limit"),
               "activated_at": datetime.now(timezone.utc).isoformat(timespec="seconds")}
        STATE.mkdir(parents=True, exist_ok=True)
        LICENCE_FILE.write_text(json.dumps(rec, indent=1))
        try:
            os.chmod(LICENCE_FILE, 0o600)
        except OSError:
            pass
        _log({"event": "licence", "decision": "activated", "instance": rec["instance_id"]})
        print("activated: %s / %s for %s (%s of %s activations used)" % (
            rec["product"], rec["variant"], instance_name, rec["activation_usage"], rec["activation_limit"]))
        return 0
    if action == "deactivate":
        if not rec:
            print("nothing to deactivate")
            return 1
        ans = _licence_call(cfg, "deactivate", {"license_key": rec["key"], "instance_id": rec.get("instance_id") or ""})
        if not ans.get("deactivated"):
            print("deactivation refused: %s" % (ans.get("error") or "no reason given"))
            return 1
        LICENCE_FILE.unlink()
        _log({"event": "licence", "decision": "deactivated"})
        print("deactivated; this machine is back on the free tier")
        return 0
    print("usage: duck licence activate KEY | status | deactivate")
    return 1


def cmd_status(cwd=None):
    cfg, root = _config(cwd)
    recs = [json.loads(l) for l in LOG.read_text().splitlines() if l.strip()] if LOG.exists() else []
    now = time.time()
    day = [r for r in recs if now - r.get("at", 0) < 86400]
    by = Counter((r.get("event"), r.get("decision")) for r in day)
    last = max((r.get("at", 0) for r in recs), default=0)
    d = _drifted()
    print("helmet-duck %s -- status" % VERSION)
    print("  harness                  : %s" % HARNESS)
    print("  risks accepted (armed)   : %s" % ("yes" if _accepted() else "NO, run `duck accept` after reading %s" % RISKS_URL))
    print("  project                  : %s" % (root or "(none found from %s)" % (cwd or os.getcwd())))
    print("  evidence command         : %s" % (cfg["evidence"].get("command") or "(not declared; G2 inactive)"))
    if root and cfg["evidence"].get("command"):
        print("  evidence                 : %s" % _evidence_fresh(root, cfg)[1])
    print("  override open            : %s" % _override_open())
    print("  sealed                   : %s" % ("no manifest (unarmed)" if d is None else ("DRIFT, failing closed" if d else "yes")))
    print("  last decision            : %s" % ("never" if not last else "%d min ago" % ((now - last) / 60)))
    for (e, dec), n in sorted(by.items()):
        print("  last 24h  %-9s %-9s: %d" % (e, dec, n))
    print("  open dissent claims      : %d" % len(_open_claims()))
    rec = _licence_record()
    print("  tier                     : %s" % ("free" if not rec else "%s (%s)" % (rec.get("tier", "personal"), rec.get("instance_name"))))
    caps = [r for r in day if r.get("decision") == "cap"]
    if caps:
        print("  FLAG: %d stop-cap event(s) in 24h: a block was ignored after %d tries; read the log" % (len(caps), MAX_BLOCKS_IN_ROW))
    return 0


# ----------------------------------------------------------------- selftest
def _expand(obj, subs):
    if isinstance(obj, str):
        for k, v in subs.items():
            obj = obj.replace("{%s}" % k, v)
        return obj
    if isinstance(obj, dict):
        return {k: _expand(v, subs) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_expand(v, subs) for v in obj]
    return obj


def _run_hook(sub, ev, env):
    me = str(pathlib.Path(__file__).resolve())
    t0 = time.perf_counter()
    r = subprocess.run([sys.executable, me, sub], input=json.dumps(ev), capture_output=True, text=True, env=env)
    ms = 1000 * (time.perf_counter() - t0)
    decision = "allow"
    if r.stdout.strip():
        try:
            decision = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"]
        except (ValueError, KeyError):
            decision = "MALFORMED"
    return decision, r.returncode, ms, r


def cmd_selftest():
    gates_fx = json.loads((FIXTURES_DIR / "gates.json").read_text())
    dissent_fx = json.loads((FIXTURES_DIR / "dissent.json").read_text())
    with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as proj:
        # a fake project that declares an evidence command, so G2 has something to guard
        pathlib.Path(proj, PROJECT_CONFIG).write_text(json.dumps({"evidence": {"command": "true"}}))
        subprocess.run(["git", "init", "-q"], cwd=proj, capture_output=True)
        # the scratch project lives under the system temp root, which G1 exempts by
        # default; the selftest's own user config removes that exemption so the
        # read-ledger check measures the ledger and not the exemption
        pathlib.Path(d, "config.json").write_text(json.dumps({"exempt_roots": ["/dev"]}))
        subs = {"HOME": str(HOME), "PROJECT": proj, "STATE": d, "ROOT": str(ROOT)}
        env = dict(os.environ, HELMET_DUCK_STATE=d, HELMET_DUCK_OVERRIDE=os.path.join(d, "no-override"),
                   HELMET_DUCK_HARNESS="claude")
        sid = "selftest"
        # unarmed until accepted: before acceptance the canary must pass, after it must be denied
        canary_ev = {"session_id": sid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "echo " + CANARY}}
        d_unarmed, _, _, _ = _run_hook("pre", canary_ev, env)
        pathlib.Path(d, "accepted.json").write_text(json.dumps({"accepted": True, "version": VERSION}))
        d_armed, _, _, _ = _run_hook("pre", canary_ev, env)
        acceptance_arms = (d_unarmed, d_armed) == ("allow", "deny")
        bad_exit, malformed, slow, missed, false_pos = [], [], [], [], []
        for f in gates_fx["deny"]:
            ev = _expand(f["event"], subs)
            ev.setdefault("session_id", sid)
            dec, rc, ms, _ = _run_hook("pre", ev, env)
            if rc != 0:
                bad_exit.append(f["name"])
            if dec == "MALFORMED":
                malformed.append(f["name"])
            if ms > BUDGET_MS:
                slow.append((f["name"], int(ms)))
            if dec != "deny":
                missed.append(f["name"])
        for f in gates_fx["allow"]:
            ev = _expand(f["event"], subs)
            ev.setdefault("session_id", sid)
            dec, rc, ms, _ = _run_hook("pre", ev, env)
            if rc != 0:
                bad_exit.append(f["name"])
            if dec != "allow":
                false_pos.append((f["name"], dec))

        # the read-ledger must flip G1
        tmp = pathlib.Path(proj) / "existing.txt"
        tmp.write_text("x")
        ow = {"session_id": sid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "echo y > %s" % tmp}}
        d1, _, _, _ = _run_hook("pre", ow, env)
        _run_hook("post", {"session_id": sid, "tool_name": "Read", "tool_input": {"file_path": str(tmp)}}, env)
        d2, _, _, _ = _run_hook("pre", ow, env)
        read_ledger_flips = (d1, d2) == ("deny", "allow")

        # evidence age must flip G2
        commit = {"session_id": sid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "git commit -q -m x"}}
        ep = pathlib.Path(d) / "evidence" / (hashlib.sha1(str(pathlib.Path(proj).resolve()).encode()).hexdigest()[:16] + ".json")
        ep.parent.mkdir(parents=True, exist_ok=True)
        fp = _tree_fingerprint(pathlib.Path(proj))
        ep.write_text(json.dumps({"at": int(time.time()), "ok": True, "command": "true", "tree": fp}))
        d_fresh, _, _, _ = _run_hook("pre", commit, env)
        ep.write_text(json.dumps({"at": int(time.time()) - 3 * 3600, "ok": True, "command": "true", "tree": fp}))
        d_stale, _, _, _ = _run_hook("pre", commit, env)
        evidence_flips = (d_fresh, d_stale) == ("allow", "deny")
        # evidence is bound to the command it ran and the tree it saw
        ep.write_text(json.dumps({"at": int(time.time()), "ok": True, "command": "false", "tree": fp}))
        d_other_cmd, _, _, _ = _run_hook("pre", commit, env)
        ep.write_text(json.dumps({"at": int(time.time()), "ok": True, "command": "true", "tree": "0" * 64}))
        d_other_tree, _, _, _ = _run_hook("pre", commit, env)
        ep.unlink()
        evidence_bound = (d_other_cmd, d_other_tree) == ("deny", "deny")

        # a project file that switches gates off does not switch them off
        pc = pathlib.Path(proj, PROJECT_CONFIG)
        pc.write_text(json.dumps({"evidence": {"command": "true"}, "gates": {"G0": False, "G1": False, "G4": False}}))
        d_disarm, _, _, _ = _run_hook("pre", canary_ev, env)
        pc.write_text(json.dumps({"evidence": {"command": "true"}}))
        config_holds = d_disarm == "deny"

        # reads mean reading: wc is not a read, a bare filename after cat is
        rsid = "selftest-reads"
        ow_r = {"session_id": rsid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "echo y >> existing.txt"}}
        _run_hook("post", {"session_id": rsid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "wc -l ./existing.txt"}}, env)
        d_wc, _, _, _ = _run_hook("pre", ow_r, env)
        _run_hook("post", {"session_id": rsid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "cat existing.txt"}}, env)
        d_cat, _, _, _ = _run_hook("pre", ow_r, env)
        reads_mean_reading = (d_wc, d_cat) == ("deny", "allow")

        # the project's own configuration stays protected even after it was read
        _run_hook("post", {"session_id": rsid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "cat .helmet-duck.json"}}, env)
        d_cfg, _, _, _ = _run_hook("pre", {"session_id": rsid, "tool_name": "Bash", "cwd": proj,
                                            "tool_input": {"command": "echo '{}' > .helmet-duck.json"}}, env)
        config_write_refused = d_cfg == "deny"

        # the override must open a gate, and only while fresh
        ov = pathlib.Path(env["HELMET_DUCK_OVERRIDE"])
        ov.write_text("")
        canary = {"session_id": sid, "tool_name": "Bash", "cwd": proj, "tool_input": {"command": "echo " + CANARY}}
        d_ov, _, _, _ = _run_hook("pre", canary, env)
        old = time.time() - 2 * OVERRIDE_SECONDS
        os.utime(ov, (old, old))
        d_ov_stale, _, _, _ = _run_hook("pre", canary, env)
        ov.unlink()
        override_works = (d_ov, d_ov_stale) == ("allow", "deny")

        # the test can fail: a deny fixture with its trigger removed must not deny
        f0 = gates_fx["deny"][0]
        mut = _expand(json.loads(json.dumps(f0["event"])), subs)
        mut["tool_input"]["command"] = mut["tool_input"]["command"].replace(f0["trigger"], "")
        mut.setdefault("session_id", sid)
        d_mut, _, _, _ = _run_hook("pre", mut, env)
        can_fail = d_mut != "deny"

        # drift fails closed: a copy of the duck beside a wrong manifest
        copy_dir = pathlib.Path(d) / "drift"
        copy_dir.mkdir()
        (copy_dir / "duck.py").write_bytes(pathlib.Path(__file__).resolve().read_bytes())
        (copy_dir / "MANIFEST.json").write_text(json.dumps({"duck_sha256": "0" * 64}))
        r = subprocess.run([sys.executable, str(copy_dir / "duck.py"), "pre"],
                           input=json.dumps({"session_id": sid, "tool_name": "Bash", "cwd": proj,
                                             "tool_input": {"command": "ls"}}),
                           capture_output=True, text=True, env=env)
        try:
            drift_closes = json.loads(r.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
        except (ValueError, KeyError):
            drift_closes = False

        # dissent: defect fixtures fire, clean ones stay silent, hook never denies, fast
        d_missed = [f["name"] for f in dissent_fx["defects"] if f["class"] not in classify(f["text"])]
        d_false = [f["name"] for f in dissent_fx["clean"] if classify(f["text"])]
        heavy = max(dissent_fx["defects"], key=lambda f: len(f["text"]))
        t0 = time.perf_counter()
        r = subprocess.run([sys.executable, str(pathlib.Path(__file__).resolve()), "dissent"],
                           input=json.dumps({"tool_name": "Bash", "cwd": proj, "tool_input": {"command": heavy["text"]}}),
                           capture_output=True, text=True, env=env)
        d_ms = 1000 * (time.perf_counter() - t0)
        never_denies = r.returncode == 0 and "permissionDecision" not in r.stdout and "DISSENT [" in r.stdout

    ok = (not missed and not false_pos and not bad_exit and not malformed and not slow
          and read_ledger_flips and evidence_flips and evidence_bound and config_holds and reads_mean_reading and config_write_refused
          and override_works and can_fail and drift_closes
          and not d_missed and not d_false and never_denies and d_ms < BUDGET_MS and acceptance_arms)
    print("helmet-duck %s -- selftest" % VERSION)
    print("  unarmed until accepted     : %s (%s -> %s)" % (acceptance_arms, d_unarmed, d_armed))
    print("  deny fixtures denied       : %d of %d%s" % (len(gates_fx["deny"]) - len(missed), len(gates_fx["deny"]), "" if not missed else "  MISSED " + str(missed)))
    print("  allow fixtures allowed     : %d of %d%s" % (len(gates_fx["allow"]) - len(false_pos), len(gates_fx["allow"]), "" if not false_pos else "  FALSE " + str(false_pos)))
    print("  hook exit code always 0    : %s%s" % (not bad_exit, "" if not bad_exit else "  " + str(bad_exit)))
    print("  output well-formed         : %s" % (not malformed))
    print("  under %d ms                : %s%s" % (BUDGET_MS, not slow, "" if not slow else "  " + str(slow)))
    print("  read-ledger flips G1       : %s (%s -> %s)" % (read_ledger_flips, d1, d2))
    print("  evidence age flips G2      : %s (%s -> %s)" % (evidence_flips, d_fresh, d_stale))
    print("  evidence bound to cmd+tree : %s (%s, %s)" % (evidence_bound, d_other_cmd, d_other_tree))
    print("  project file cannot disarm : %s (%s)" % (config_holds, d_disarm))
    print("  reads mean reading         : %s (wc %s, cat %s)" % (reads_mean_reading, d_wc, d_cat))
    print("  project config write       : %s (%s after a read)" % (config_write_refused, d_cfg))
    print("  override opens, then ages  : %s (%s -> %s)" % (override_works, d_ov, d_ov_stale))
    print("  test can fail (mutated)    : %s" % can_fail)
    print("  drift fails closed         : %s" % drift_closes)
    print("  dissent defects fire       : %d of %d%s" % (len(dissent_fx["defects"]) - len(d_missed), len(dissent_fx["defects"]), "" if not d_missed else "  MISSED " + str(d_missed)))
    print("  dissent clean silent       : %d of %d%s" % (len(dissent_fx["clean"]) - len(d_false), len(dissent_fx["clean"]), "" if not d_false else "  FALSE " + str(d_false)))
    print("  dissent never denies, fast : %s (%.0f ms)" % (never_denies, d_ms))
    print("\n%s" % ("PASS" if ok else "FAIL"))
    _log({"event": "selftest", "decision": "PASS" if ok else "FAIL"})
    return 0 if ok else 1


# --------------------------------------------------------------------- main
def main(argv=None):
    ap = argparse.ArgumentParser(prog="duck", description="Helmet Duck: gates, dissent chair and mirror for coding agents.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    for k in ("pre", "post", "stop", "dissent", "selftest", "seal", "override", "accept", "status", "evidence",
              "rates", "report", "brief", "mirror-report"):
        sub.add_parser(k)
    sw = sub.add_parser("mirror-sweep")
    sw.add_argument("--days", type=int, default=14)
    cl = sub.add_parser("claim")
    cl.add_argument("cls", choices=sorted(CLASSES))
    cl.add_argument("text")
    for k in ("repay", "default", "void"):
        p = sub.add_parser(k)
        p.add_argument("id")
        p.add_argument("evidence")
    pd = sub.add_parser("pending")
    pd.add_argument("--limit", type=int, default=5)
    lc = sub.add_parser("licence")
    lc.add_argument("action", choices=("activate", "status", "deactivate"))
    lc.add_argument("key", nargs="?")
    args = ap.parse_args(argv)

    if args.cmd == "licence":
        return cmd_licence(args.action, args.key)

    if args.cmd in ("pre", "post", "stop", "dissent"):
        try:
            ev = json.load(sys.stdin)
        except (ValueError, OSError):
            ev = {}
        try:
            return {"pre": cmd_pre, "post": cmd_post, "stop": cmd_stop, "dissent": cmd_dissent}[args.cmd](ev)
        except SystemExit:
            raise
        except Exception as exc:            # a crashed gate must not become a silent allow
            if args.cmd == "pre":
                _deny("G4", "the gate crashed (%s: %s); failing closed. Run `duck override` from a terminal "
                            "to open every gate for 30 minutes, or uninstall the plugin." % (type(exc).__name__, exc))
            _log({"event": args.cmd, "decision": "crash", "error": repr(exc)[:200]})
            return 0
    if args.cmd == "selftest":
        return cmd_selftest()
    if args.cmd == "seal":
        return cmd_seal()
    if args.cmd == "override":
        return cmd_override()
    if args.cmd == "accept":
        return cmd_accept()
    if args.cmd == "status":
        return cmd_status()
    if args.cmd == "evidence":
        return cmd_evidence()
    if args.cmd == "claim":
        cid = hashlib.sha1(("claim|%s|%.6f" % (args.text, time.time())).encode()).hexdigest()[:10]
        _append_claim({"kind": "claim", "id": cid, "class": args.cls, "text": args.text,
                       "source": "prose", "at": int(time.time())})
        print("opened %s in %s" % (cid, args.cls))
        return 0
    if args.cmd in ("repay", "default", "void"):
        recs = {r["id"]: r for r in _read_claims() if "id" in r}
        if args.id not in recs:
            print("no such claim or card %s" % args.id, file=sys.stderr)
            return 1
        _append_claim({"kind": args.cmd, "id": args.id, "class": recs[args.id].get("class"),
                       "evidence": args.evidence, "at": int(time.time())})
        print("%s %s" % (args.cmd, args.id))
        return 0
    if args.cmd == "rates":
        for c, v in rates().items():
            print("  %-30s %2d repaid  %2d defaulted  rate %s" % (
                c, v["repaid"], v["defaulted"], ("%.2f" % v["rate"]) if v["rate"] is not None else "-"))
        return 0
    if args.cmd == "pending":
        if not _accepted():
            print(UNARMED_NOTICE)
        for r in _open_claims()[-args.limit:]:
            print("  %s  %-28s %s" % (r["id"], r.get("class"), (r.get("text") or r.get("excerpt", ""))[:70]))
        return 0
    if args.cmd == "report":
        recs = _read_claims()
        cards = [r for r in recs if r.get("kind") == "card"]
        closes = {r["id"]: r for r in recs if r.get("kind") in ("repay", "default", "void")}
        n = rp = df = 0
        for c in cards:
            cl = closes.get(c["id"])
            if cl and cl["kind"] == "void":
                continue
            n += 1
            if cl:
                rp += cl["kind"] == "repay"
                df += cl["kind"] == "default"
        print("dissent cards %d, repaid %d, defaulted %d, default-rate %s" % (
            n, rp, df, ("%.2f" % (df / (rp + df))) if rp + df else "no closures yet"))
        return 0
    if args.cmd == "brief":
        return mirror_brief()
    if args.cmd == "mirror-sweep":
        mirror_sweep(args.days)
        return 0
    if args.cmd == "mirror-report":
        return mirror_report()
    return 0


if __name__ == "__main__":
    sys.exit(main())
