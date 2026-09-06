# Helmet Duck for Codex

Codex sends the same hook events as Claude Code, with the same field names, and
accepts the same JSON answer. The one difference is how files are edited: Codex
uses `apply_patch`, so the duck reads the file paths out of the patch headers and
applies the same gates to them. `codex/hooks.json` is the Codex wiring;
`hooks/hooks.json` is Claude Code's. The Python is shared.

## Install as hooks (works today)

1. Clone or download this repository somewhere permanent, for example
   `~/helmet-duck`.
2. Copy `codex/hooks.json` to `~/.codex/hooks.json` and replace every
   `$PLUGIN_ROOT` with the absolute path of that directory. For one project only,
   put the file at `<repo>/.codex/hooks.json` instead.
3. Start Codex and run `/hooks`. Codex refuses to run a hook it has not seen you
   review: read each definition and trust it. This repeats whenever a hook's text
   changes.
4. From a terminal, read https://helmetduck.com/risks.html, then:

       python3 ~/helmet-duck/duck.py accept
       python3 ~/helmet-duck/duck.py seal

5. Confirm: `python3 ~/helmet-duck/duck.py status` shows `harness : codex` when
   run through a hook, and `risks accepted (armed) : yes`.

Hooks are enabled by default in current Codex versions. If yours predates that,
add `[features]` with `codex_hooks = true` to `~/.codex/config.toml`.

Verified 2026-09-06 with Codex CLI 0.144.6 through a repository-level
`.codex/hooks.json` pointing at the duck: the canary was refused (G0), a blind
shell append to an unread file was refused (G1), an `apply_patch` to an unread
file was refused through its patch headers (G1), and a `cat` followed by an append
to the same file was allowed, which shows Codex's shell reads feed the read ledger.
Codex reported each refusal to the model as "Command blocked by PreToolUse hook:
GATE ...", and the duck logged every decision under the Codex thread id.
One operator note for automation: `codex exec` reads additional input from a
non-terminal stdin, so a script that leaves stdin open hangs forever; close it
with `</dev/null`.

## Install as a plugin

The manifest is `.codex-plugin/plugin.json`; it points Codex at
`codex/hooks.json` and the shared `skills/`. Codex installs plugins from a
marketplace, and even an installed plugin's hooks stay off until you review and
trust them in `/hooks`. Follow OpenAI's current plugin installation guide for the
marketplace step; the manifest here is ready for it.

## What is different from the Claude Code build

| | Claude Code | Codex |
| --- | --- | --- |
| File edits seen by G1 and G4 | `Write`, `Edit`, `MultiEdit` | `apply_patch`, by parsing the patch headers |
| Reads that satisfy G1 | `Read`, `Grep`, shell read commands, the harness's own edits | shell read commands and the harness's own patches |
| Transcripts the mirror sweeps | `~/.claude/projects` | `~/.codex/sessions` and `~/.codex/archived_sessions` |
| Hook trust | none required | required, per hook, in `/hooks` |
| Plugin root variable | `${CLAUDE_PLUGIN_ROOT}` | `$PLUGIN_ROOT` |

Everything on the risks page applies to both.
