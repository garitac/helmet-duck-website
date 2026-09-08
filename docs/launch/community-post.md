# Community post (Claude Code community, Reddit r/ClaudeAI, Discord)

Shorter, practical, for people already running agents.

## Title

Helmet Duck: a Claude Code plugin whose gates refuse blind overwrites, unevidenced commits and known-bad commands

## Body

If your agent has ever appended to a file it never opened, committed without
running the tests, or force-pushed because it "knew" the branch was fine, this
is for that.

Helmet Duck is a plugin of hooks. A script, not the model, evaluates each rule,
so the agent cannot talk its way past it:

    /plugin marketplace add garitac/helmet-duck
    /plugin install helmet-duck-bushido@helmet-duck
    duck accept
    duck seal

What it refuses: blind shell overwrites of files not read this session (G1),
`git commit` without a fresh passing test run in projects that declare one
(G2), `--no-verify`, heredocs through ssh, force-pushes and `rm -rf` on a root
(G0), edits to itself (G4). What it does not refuse: anything else. It also
prints one dissent question when it recognises a defect pattern, and opens each
session with how often the machinery caught the agent in the last seven days.

Honest limits: it cannot see a claim made in prose, a path built at runtime
inside another program, or any pattern it does not have. Fail-closed by design:
if the duck itself breaks, it refuses everything until `duck override`. Read the
risks page before installing, https://helmetduck.com/risks.html; installing
means accepting it.

Standard library only, no network, all state in ~/.helmet-duck. Free at 0.2.
Source visible for inspection. Built after a summer in which agents cost me
a large amount of money and delivered nothing; the first week of these hooks
caught the agent 242 times.

Site https://helmetduck.com, repo https://github.com/garitac/helmet-duck.
Feedback on false refusals is the most useful thing you can send.
