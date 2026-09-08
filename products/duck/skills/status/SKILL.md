---
description: "Show Helmet Duck's state for this project (which gates are armed, whether evidence is fresh, open dissent claims, the last 24 hours of decisions). Use when the user asks how the duck, the gates, or the guardrails are doing."
---

Run `duck status` with the Bash tool and report its output to the user as a short table. If it shows open dissent claims, list them with `duck pending` and tell the user each one must be closed with `duck repay|default|void ID "why"` before the turn can end. Do not edit anything under the plugin root or `~/.helmet-duck`; those are the owner's.
