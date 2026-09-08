---
description: "Open, list, or close claims in Helmet Duck's dissent ledger. Use when stating something from memory that should be checked later, when the duck reports open claims, or when the user asks what the agent has claimed and how those claims closed."
---

The ledger records claims and how they closed, so that the class default rate learns.

- To open a claim made from memory: `duck claim existence-from-memory "text"` (or `diagnosis-stated-as-certain`).
- To list open claims and cards: `duck pending --limit 20`.
- To close one: `duck repay ID "what was checked"` when the check confirmed it, `duck default ID "what was found"` when it was wrong, `duck void ID "why"` only for a deliberate test of the channel.
- To see the rates: `duck rates`.

Close every claim with what you actually checked, never with what you remember.
