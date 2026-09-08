---
description: "Run the project's declared check command through Helmet Duck and record the result, which opens git commits for 30 minutes (gate G2). Use before committing, or when a commit was refused for missing or stale evidence."
---

Run `duck evidence` with the Bash tool. It runs the command declared under `evidence.command` in the project's `.helmet-duck.json`, records PASS or FAIL with the git HEAD, and prints the tail of the output. If it prints that no evidence command is declared, tell the user how to declare one (a `.helmet-duck.json` at the project root with `{"evidence": {"command": "<test command>"}}`) and do not commit. If it FAILS, fix the failure; never work around the gate.
