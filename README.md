# Helmet Duck

**Deterministic tools for coding agents, sold at https://helmetduck.com.** This repository
holds the brand's storefront. Every product is developed in its own repository and carries
the brand's name; the marketplace and the site here are where finished versions are sold.

## Map

| Path | What it is |
| --- | --- |
| `.claude-plugin/marketplace.json` | The marketplace users add once. It lists every product by its repository. |
| `site/` | helmetduck.com: static pages with a strict content-security policy and no scripts, built by `tools/build.py`. |
| `infra/`, `environments/` | The CloudFormation stacks (site, roles, mail) and the deploy contract, `environments/prod.env.yaml`. |
| `tools/` | `check.py`, the gate CI and the deploy run first; `build.py`; the owner's scripts (`apply.sh`, `mail.sh`, `brake.sh`, `blocklist.sh`, `smtp.sh`); the two watchers (`sentinel.py`, `sentry.py`, `board.sh`); the console under `tools/console/`, with its launcher. |
| `docs/` | Runbooks for deploy, security, console and commerce; launch texts; a legal template. |
| `SECURITY.md`, `LICENSE` | How to report a vulnerability; the licence for everything here. Each product repository carries its own. |

## Products

| Product | Where it is developed | State |
| --- | --- | --- |
| Helmet Duck Bushido: gates, a dissent chair and a mirror for Claude Code and Codex | https://github.com/garitac/helmet-duck-bushido | 0.4.0, live on the marketplace and at helmetduck.com |
| Helmet Duck Eyes: sight measured from rendered pixels | https://github.com/garitac/helmet-duck-eyes | in development; listed here when its first version is tagged |

A finished version reaches the shelf through one pull request in this repository: the
marketplace entry and the site change together, you merge, the manual deploy runs, and the
sentinel confirms the live bytes within the hour. Development churn in a product never
touches the site.

## Install Helmet Duck Bushido (Claude Code)

```
/plugin marketplace add garitac/helmet-duck
/plugin install helmet-duck-bushido@helmet-duck
```

Then, from a terminal, record your acceptance of [RISKS.md](https://github.com/garitac/helmet-duck-bushido/blob/main/RISKS.md) and seal
the installed copy. You type these, never the agent, which is refused them:

```
DUCK="$(ls -d ~/.claude/plugins/cache/helmet-duck/helmet-duck-bushido/*/duck.py | tail -1)"
python3 "$DUCK" accept && python3 "$DUCK" seal
python3 "$DUCK" status
```

The full story, the gates, the commands and the Codex install are in the product's
repository, https://github.com/garitac/helmet-duck-bushido.

## Site and pipeline

helmetduck.com is built from `site/` by `tools/build.py`, gated by `tools/check.py`, and
deployed by a manually dispatched GitHub Actions workflow through OIDC. Two scheduled
watchers with no write access to anything but one issue each guard the live site: the
sentinel rebuilds the revision the site declares and compares every file, and the sentry
reads the access logs and defangs every client-written string before anyone reads it. The
owner reads all of it in a local console, `helmet-duck-console-start`, bound to one machine
([docs/console.md](docs/console.md)). Runbooks: [docs/deploy.md](docs/deploy.md) and
[docs/security.md](docs/security.md).

English is the only language of this repository: code, comments, copy and the Agent Code.
The gate refuses any non-Latin script.

## Licence

Copyright (c) 2026 Carlos Garita. All rights reserved. The source is visible so that what
runs on your machine can be inspected before it runs; see `LICENSE`.
