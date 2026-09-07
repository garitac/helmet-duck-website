# Helmet Duck

**Deterministic hooks that block common coding-agent mistakes, in the harness, not in the prompt.**

Everything an agent is told is advice, and advice is exactly what an agent skips
when it decides it already knows. Helmet Duck is not advice. At each hook event a
script, never the model, evaluates a predicate, and the harness refuses the
action or refuses to let the turn end. Thinking cannot be gated. Its consequences
can.

## Why it exists

Between June and August 2026 one owner spent a large amount of money on coding
agents and got no product back. The agents worked from memory instead of reading
the tree, appended notes to files they had never opened, committed without running
the tests, spawned audits of audits, and asserted every wrong thing with full
confidence. The mirror, run on 2026-09-07 over fourteen days of the author's own transcripts,
found 353 moments where the machinery caught the agent (229 failed assertions, 78 gate
refusals, 44 syntax errors, 2 denials), 75 of them since the hooks went in on 2026-09-05,
with 141 more inside test suites counted apart. This is that harness, generalised, for
Claude Code and Codex.

## What it does

| Part | Event | What happens |
| --- | --- | --- |
| **G0 known-bad forms** | before a tool runs | `--no-verify`, a heredoc through ssh, a force-push, `rm -rf` on a root, and a canary literal are refused with the same words every time. Configurable. |
| **G1 overwrite unread** | before a tool runs | A shell overwrite of an existing file the agent has not read this session is refused. The harness already refuses this for its Edit and Write tools; G1 closes the shell routes around that. |
| **G2 commit unevidenced** | before a tool runs | In a project that declares an evidence command, `git commit` is refused unless `duck evidence` ran that same command and recorded PASS within the last 30 minutes on the same tree. `git -C dir commit` is seen. Opt-in per project. |
| **G3 stop unfinished** | when the turn ends | The turn cannot end with open dissent claims, or (opt-in) a dirty worktree. Capped at two blocks in a row, then allowed and logged: a gate that can loop is a cost. |
| **G4 self-protection** | before a tool runs | Writes to the duck, its state, the harness settings and hooks, the override file and the project's own configuration are refused, and so are the owner's commands (override, accept, seal, licence) when an agent runs them. A project file may tighten the gates, never loosen them. A duck whose hash differs from its sealed manifest fails closed. A gate the agent can edit is advice. |
| **Owner override** | terminal | `duck override` opens every gate for 30 minutes, logged. The agent cannot do this (G4). |
| **Dissent chair** | before a tool runs | A deterministic classifier recognises four defect classes agents repeat and prints the one question a real check would have asked, with that class's measured default rate. Advisory. It never denies. |
| **Mirror** | session start | Sweeps the harness's own transcripts for the moments the machine caught the agent and opens the session with the count. The agent's inside view is not consulted, because its inside view is the problem. |
| **Agent Code** | each prompt | Seven duties and three verification checks, in English, in the agent's context every turn. Courage to deliver never overrides the owner's word on an irreversible act. |

## What it does not do

Stated rather than pretended:

- It does not see a claim made from memory in prose. No event fires when the model thinks. Those claims are opened by hand with `duck claim` and closed with `repay` or `default`.
- It does not see writes whose path is assembled at runtime inside another program.
- The mirror's recall is partial. A wrong claim spoken fluently leaves no error signature.
- A `head` or `tail` counts as a read of the whole file: the ledger records that content was shown, not how much.
- The boundary is the agent's tools. A person at the keyboard can run `duck override`, edit a file by hand, or uninstall. It protects against an agent's mistakes, not against a person.

## Risks first

Read [RISKS.md](RISKS.md), also published at https://helmetduck.com/risks.html.
Installing or using Helmet Duck means you accept every risk on it. The duck refuses
nothing until you record that acceptance with `duck accept`, which also arms the gates.

English is the only language of this repository: code, comments, copy and the Agent
Code. The gate refuses any non-Latin script, so nobody can claim an instruction was
unclear because it was not in English.

## Install (Claude Code)

```
/plugin marketplace add garitac/helmet-duck
/plugin install helmet-duck@helmet-duck
```

Then, from a terminal, record your acceptance and seal the installed copy so an
edited duck fails closed. You type these, never the agent, which is refused them.
The plugin installs under `~/.claude/plugins/cache/helmet-duck/helmet-duck/<version>/`:

```
DUCK="$(ls -d ~/.claude/plugins/cache/helmet-duck/helmet-duck/*/duck.py | tail -1)"
python3 "$DUCK" accept && python3 "$DUCK" seal
python3 "$DUCK" status
```

Expected in the status: `risks accepted (armed) : yes` and `sealed : yes`. Then, inside
a session, ask the agent to run `echo HELMET-DUCK-CANARY-DENY`; the harness answers
`GATE G0: canary: the deny channel is live`.

Uninstall with `/plugin uninstall helmet-duck@helmet-duck`; deleting `~/.helmet-duck`
removes every record it kept.

## Install (Codex)

Same duck, same gates. Codex edits files through `apply_patch`, and the duck reads
the paths out of each patch. See [codex/README.md](codex/README.md): copy
`codex/hooks.json` to `~/.codex/hooks.json` with the path filled in, trust the hooks
in `/hooks`, then `accept` and `seal`. The Codex plugin manifest is
`.codex-plugin/plugin.json`.

To arm G2 in a project, add `.helmet-duck.json` at its root:

```json
{"evidence": {"command": "python3 -m pytest -q", "max_age_minutes": 30}}
```

Requirements: Python 3.9 or later, standard library only. No network. Nothing leaves your machine.

## Commands

```
duck accept                      record acceptance of RISKS.md; arms the gates
duck status                      what is armed, what is fresh, what is open
duck selftest                    every gate proven on recorded fixtures, under 150 ms
duck evidence                    run the project's check and record it (opens G2)
duck seal                        write MANIFEST.json; an edited duck then fails closed
duck override                    OWNER ONLY: open every gate for 30 minutes
duck claim CLASS "text"          open a prose claim
duck repay|default|void ID "why" close one
duck pending | rates | report    the ledger
duck mirror-sweep | mirror-report | brief
duck licence activate KEY        register a Personal licence (one call to the vendor, nothing gated in 0.1)
duck licence status | deactivate
```

## Money

Sponsorship through GitHub Sponsors; Personal and Team licences through a merchant
of record. Software only: no installation service, no custom work, no hours. The
author is one person, and support is the public issue tracker, in English, as time
allows. No payment code lives here; see [docs/commerce.md](docs/commerce.md).

## Configuration

User-wide: `~/.helmet-duck/config.json`. Per project: `.helmet-duck.json` at the
project root. Both merge over the defaults. Keys: `gates` (switch each gate),
`forbidden` (G0 patterns and reasons), `exempt_roots` (paths G1 ignores),
`evidence`, `stop`, `dissent`.

## Site and pipeline

helmetduck.com is a static page in `site/`, built by `tools/build.py`, gated by
`tools/check.py`, and deployed by GitHub Actions through OIDC. Two scheduled
watchers with no write access to anything but one issue each guard the live site:
the sentinel rebuilds the revision the site declares and compares every file, and
the sentry reads the access logs and defangs every client-written string before
anyone reads it. The owner reads all of it in a local console, `helmet-duck-console-start`,
bound to this machine only ([docs/console.md](docs/console.md)). Runbooks: [docs/deploy.md](docs/deploy.md) and
[docs/security.md](docs/security.md). Report a vulnerability through [SECURITY.md](SECURITY.md).

## Licence

Copyright (c) 2026 Carlos Garita. All rights reserved. The source is visible so the
hooks can be inspected before they run; see `LICENSE`.
