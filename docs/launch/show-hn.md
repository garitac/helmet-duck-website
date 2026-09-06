# Show HN post

Post as the author, in your own account. Hacker News rewards plain facts and
punishes marketing; this text has no adjectives it cannot back.

## Title (80 characters max)

Show HN: Helmet Duck – hooks that refuse what a coding agent should not do

## Body

I spent June to August 2026 running coding agents on my own projects and a large
amount of money on tokens, and got no product out of it. The
agents worked from memory instead of reading files, appended to files they had
never opened, committed without running tests, and asserted every wrong thing
with full confidence.

Everything I told them was advice, and advice is exactly what an agent skips
when it decides it already knows. So I wrote hooks that are not advice: a script,
never the model, evaluates a rule at each tool call, and the harness refuses the
action. In the first week on my machine the hooks caught the agent 242 times.

Helmet Duck is that harness, generalised, for Claude Code (Codex in progress):

- G0 refuses known-bad forms: --no-verify, heredocs through ssh, force-pushes,
  rm -rf on a root.
- G1 refuses a shell overwrite of any existing file the agent has not read this
  session.
- G2 refuses git commit unless the project's declared test command ran and
  passed in the last 30 minutes.
- G3 refuses to let a turn end with open claims in a ledger, capped so it cannot
  loop.
- G4 refuses edits to itself and to the harness settings, and fails closed if
  its own file no longer matches its sealed manifest.
- A "dissent chair" recognises four defect patterns agents repeat (judging a
  measurement against a cruder reference, treating the head of a sorted file as
  a sample, a grep that matches its own command line, a text-range edit that
  swallows a definition) and asks the one question a real check would have
  asked. Advisory only.
- A "mirror" reads the harness's own transcripts and opens every session with
  how many times the machine caught the agent last week.

Standard-library Python, no network, everything stays in ~/.helmet-duck. It
refuses nothing until you have read the risks page and run `duck accept`. The
risks page is honest about what it cannot see: a wrong claim made in prose, a
write whose path is built at runtime, and anything it has no pattern for.

Version 0.2 is free. Source is visible so you can inspect the hooks before they
run on your machine; the licence forbids redistribution. Site:
https://helmetduck.com. Repo: https://github.com/garitac/helmet-duck.

I am 60, was retired by my last company in June, and this is the first thing
from that summer that works. Criticism of the design is welcome; the risks page
is the place I most want to be wrong about.
