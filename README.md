# Helmet Duck

**The rules an AI coding agent cannot skip, because the harness refuses.**

Everything an agent is told is advice, and advice is exactly what an agent skips
when it decides it already knows. Helmet Duck is not advice. At each hook event a
script, never the model, evaluates a predicate, and the harness refuses the
action or refuses to let the turn end. Thinking cannot be gated. Its consequences
can.

## Why it exists

Between June and August 2026 one owner spent about 1.2 million yen on coding
agents and got no product back. The agents worked from memory instead of reading
the tree, appended notes to files they had never opened, committed without running
the tests, spawned audits of audits, and asserted every wrong thing with full
confidence. The first version of these hooks, installed on 2026-09-05, caught the
agent 242 times in its first week. This is that harness, generalised.

## What it does

| Part | Event | What happens |
| --- | --- | --- |
| **G0 known-bad forms** | before a tool runs | `--no-verify`, a heredoc through ssh, a force-push, `rm -rf` on a root, and a canary literal are refused with the same words every time. Configurable. |
| **G1 overwrite unread** | before a tool runs | A shell overwrite of an existing file the agent has not read this session is refused. The harness already refuses this for its Edit and Write tools; G1 closes the shell routes around that. |
| **G2 commit unevidenced** | before a tool runs | In a project that declares an evidence command, `git commit` is refused unless `duck evidence` ran that command and recorded PASS within the last 30 minutes. Opt-in per project. |
| **G3 stop unfinished** | when the turn ends | The turn cannot end with open dissent claims, or (opt-in) a dirty worktree. Capped at two blocks in a row, then allowed and logged: a gate that can loop is a cost. |
| **G4 self-protection** | before a tool runs | Writes to the duck, its state, the harness settings and hooks, and the override file are refused. A duck whose hash differs from its sealed manifest fails closed. A gate the agent can edit is advice. |
| **Owner override** | terminal | `duck override` opens every gate for 30 minutes, logged. The agent cannot do this (G4). |
| **Dissent chair** | before a tool runs | A deterministic classifier recognises four defect classes agents repeat and prints the one question a real check would have asked, with that class's measured default rate. Advisory. It never denies. |
| **Mirror** | session start | Sweeps the harness's own transcripts for the moments the machine caught the agent and opens the session with the count. The agent's inside view is not consulted, because its inside view is the problem. |
| **Bushido** | each prompt | Seven virtues and three verification checks, in the agent's context every turn. |

## What it does not do

Stated rather than pretended:

- It does not see a claim made from memory in prose. No event fires when the model thinks. Those claims are opened by hand with `duck claim` and closed with `repay` or `default`.
- It does not see writes whose path is assembled at runtime inside another program.
- The mirror's recall is partial. A wrong claim spoken fluently leaves no error signature.

## Install (Claude Code)

```
/plugin marketplace add garitac/helmet-duck
/plugin install helmet-duck@helmet-duck
```

Then, from a terminal, seal the installed copy so an edited duck fails closed:

```
duck seal
```

To arm G2 in a project, add `.helmet-duck.json` at its root:

```json
{"evidence": {"command": "python3 -m pytest -q", "max_age_minutes": 30}}
```

Requirements: Python 3.9 or later, standard library only. No network. Nothing leaves your machine.

## Commands

```
duck status                      what is armed, what is fresh, what is open
duck selftest                    every gate proven on recorded fixtures, under 150 ms
duck evidence                    run the project's check and record it (opens G2)
duck seal                        write MANIFEST.json; an edited duck then fails closed
duck override                    OWNER ONLY: open every gate for 30 minutes
duck claim CLASS "text"          open a prose claim
duck repay|default|void ID "why" close one
duck pending | rates | report    the ledger
duck mirror-sweep | mirror-report | brief
```

## Configuration

User-wide: `~/.helmet-duck/config.json`. Per project: `.helmet-duck.json` at the
project root. Both merge over the defaults. Keys: `gates` (switch each gate),
`forbidden` (G0 patterns and reasons), `exempt_roots` (paths G1 ignores),
`evidence`, `stop`, `dissent`.

## Licence

Copyright (c) 2026 Carlos Garita. All rights reserved. The source is visible so the
hooks can be inspected before they run; see `LICENSE`.
