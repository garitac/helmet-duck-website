# Security policy

Helmet Duck runs as hooks inside a coding agent's harness, with the user's own
privileges. A defect here matters more than in most software, so please report it.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting: open the Security tab of
https://github.com/garitac/helmet-duck and choose "Report a vulnerability". Do not
open a public issue for a security defect. Write in English, so the report and the
fix can be read by everyone who depends on them.

Include what you can of: the Helmet Duck version (`duck status`), the harness and
its version, the exact command or hook event, what happened, and what you expected.
If the duck refused something it should have allowed, or allowed something it should
have refused, include the exact refusal text and the command.

## What to expect

An acknowledgement within seven days, best effort. For a confirmed defect in the
gates, the seal or the fail-closed behaviour, a fix or a stated decision within
thirty days. This is a one-person project: there is no bug bounty. Credit in the
release notes if you want it.

## Scope

In scope: `products/duck/duck.py` and its gates, the hook wiring for Claude Code and Codex, the
seal and the fail-closed behaviour, the site helmetduck.com and its deploy pipeline
(a way to change the live site or to publish without the owner is a vulnerability).

Out of scope: the limitations listed in [RISKS.md](products/duck/RISKS.md), which are documented
rather than hidden; the behaviour of the agent itself; and third-party services
such as GitHub, AWS or the merchant of record.

## Supply chain

Releases come only from https://github.com/garitac/helmet-duck. The `main` branch
is protected: no force-push, no deletion, every change through a pull request that
passes the gate, merged as a squash commit that GitHub signs; every action pinned to
a commit SHA.
On the user's machine the installed duck is sealed, and a modified copy fails closed.

## Watchers

Two scheduled workflows watch the live site with no write access to anything but
one GitHub issue each: the sentinel (`tools/sentinel.py`), which needs no
credentials, and the sentry (`tools/sentry.py`), which reads the access logs
through a read-only role. Both are described in [docs/security.md](docs/security.md).
