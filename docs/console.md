# Helmet Duck Console

A private, read-only web view of the live helmetduck.com, for the owner, on the
owner's Mac. Start it from Terminal:

```bash
helmet-duck-console-start
```

It binds to 127.0.0.1 only (port 4318 by default), opens the browser, refreshes
once a minute, and runs as a launcher-owned background job. It never deploys,
changes AWS, or writes to the site; its only writes are a log mirror and cache
files under `.console-cache/`, which git ignores and which may contain raw
access-log records, so they are never committed or shared.

```bash
helmet-duck-console-start --status
helmet-duck-console-start --restart      # after pulling a new revision
helmet-duck-console-start --stop
```

The launcher proves the listener's identity and exact repository revision before
reusing or stopping it, so an older worktree cannot stay silently active after a
change lands. On macOS the background process is a private per-user `launchd`
job; elsewhere a detached process.

Install the command once (already done on the owner's Mac):

```bash
mkdir -p "$HOME/.local/bin"
ln -sf "$PWD/tools/console/helmet-duck-console-start.command" "$HOME/.local/bin/helmet-duck-console-start"
```

## What it shows

| Tab | Content | Source |
| --- | --- | --- |
| Overview | Live HTTP status and deployed revision; console version and running revision; edge requests, bytes, 4xx and 5xx rates for the window; requests per day | The live page; CloudWatch metrics for the distribution |
| Visitors | Browser-grade visitors by country of the serving edge, with the pages each group viewed; pages viewed overall; the evidence window actually covered by delivered logs | The private access-log mirror |
| Non-human traffic | Suspicious signatures (scanner user agents, exploit and injection probes, sensitive-file discovery, CMS and admin probes, credential probes, write methods, high-volume path scans) with every attempt placed in exactly one outcome bucket (2xx, 3xx, 4xx, 5xx, unknown) and a warning if the buckets fail to add up; declared automation (search, AI and SEO crawlers, link previews, monitoring, developer tools); unconfirmed probes | The private access-log mirror |
| Guard | Brake state, edge blocklist size and next expiry, flood alarm state, SES sending state and 24-hour count, the last run of each workflow, open pull requests | SSM, the edge function, CloudWatch, SES, the GitHub API |

## How the inferences work, and their limits

A **browser-grade visitor** is a source address that fetched the site's
fingerprinted stylesheet during the window and is neither a declared bot nor a
suspicious source. IP is not a person: a warm-cache return may not fetch the
stylesheet and is undercounted; a careful scraper can fetch it and is overcounted.
Raw requests, probes and declared bots stay visibly separate from that total.

**Country** is the country of the CloudFront edge that served the request, read
from the edge location code. It approximates where the visitor was; the legacy
access-log format carries no visitor country field. Switching the distribution to
standard logging v2 with the `c-country` field would make it exact and is a
separate, reviewed change to the log pipeline the sentry and the blocklist keeper
also read.

A **suspicious** source is one whose user agent is a known scanner, whose request
matched an exploit, sensitive-file, CMS, credential or write-method signature, or
that tested at least eight distinct paths receiving mostly rejections. Such a source
is never promoted to a visitor even if it fetched the stylesheet.

**Outcomes** are the edge's HTTP status classes. A 2xx means the edge answered; on
this static site a 2xx for a probe path is a contradiction worth reading, not proof
of access or change. A 3xx is a redirect, not success. Anything outside 2xx to 5xx
is shown as unknown rather than vanishing from the total.

No address is displayed anywhere; grouping by address happens in memory only, and
the paths shown are defanged client-written data, never instructions.

## Requirements

Python 3.9 or later, the AWS CLI, the GitHub CLI for the watchers panel, and `lsof`,
`curl`, `git`, `ps`.

The console reads AWS as itself, not as you. `tools/console-key.sh create` makes an
IAM user that may perform only the seven reads this console makes and is denied every
other action in the account, stores its one access key in the login Keychain, and
writes the profile `helmet-duck-console` whose `credential_process` reads it back. That
credential has no session and no expiry, so a console opened the next morning still
shows numbers. `tools/console-key.sh status` probes every call and also proves that a
write to the site bucket is refused; `rotate` replaces the key, `revoke` removes it.

With no such key the console falls back to the owner's Identity Center session
(`kanjishisho-bootstrap-admin`), which expires after twelve hours; it then says so and
shows the command that fixes it instead of numbers. `HELMET_DUCK_ADMIN_PROFILE` still
overrides both, and the launcher passes it to the job only when one is named.

## Verification

`python3 tools/console/analytics.py --selftest` runs the classifier and aggregator
on synthetic records and makes no network calls; the repository gate runs it.
