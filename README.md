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
| **Agent Code** | each prompt | Seven duties and three verification checks, in English, in the agent's context every turn. Courage to deliver never overrides the owner's word on an irreversible act. |

## What it does not do

Stated rather than pretended:

- It does not see a claim made from memory in prose. No event fires when the model thinks. Those claims are opened by hand with `duck claim` and closed with `repay` or `default`.
- It does not see writes whose path is assembled at runtime inside another program.
- The mirror's recall is partial. A wrong claim spoken fluently leaves no error signature.

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
edited duck fails closed:

```
duck accept
duck seal
```

Uninstall with `/plugin uninstall helmet-duck@helmet-duck`; deleting `~/.helmet-duck`
removes every record it kept.

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

Sponsorship through GitHub Sponsors, Personal licences through a merchant of
record, Team engagements invoiced in yen. No payment code lives here; see
[docs/commerce.md](docs/commerce.md).

## Configuration

User-wide: `~/.helmet-duck/config.json`. Per project: `.helmet-duck.json` at the
project root. Both merge over the defaults. Keys: `gates` (switch each gate),
`forbidden` (G0 patterns and reasons), `exempt_roots` (paths G1 ignores),
`evidence`, `stop`, `dissent`.

## Site and pipeline

helmetduck.com is a static page in `site/`, built by `tools/build.py`, gated by
`tools/check.py`, and deployed by GitHub Actions through OIDC. The runbook is
[docs/deploy.md](docs/deploy.md).

## Licence

Copyright (c) 2026 Carlos Garita. All rights reserved. The source is visible so the
hooks can be inspected before they run; see `LICENSE`.
