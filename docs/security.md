# helmetduck.com: security posture

What protects the site, what watches it, what only the owner can do, and how to
verify each claim yourself. States marked "verified" were checked against the live
site and the GitHub API on 2026-09-07; the commands are at the end.

## What an attacker finds

Static files behind CloudFront: no server code, no form, no login, no database, no
script. Injection has nothing to run. The Content Security Policy forbids scripts
even on a defaced page, so a defacement could only change text and links, and only
three doors lead to it: the AWS account, the deploy role, and the repository. The
repository is the one that matters most, because every user's plugin update pulls
from `main`.

## Controls

| Layer | Control | State |
| --- | --- | --- |
| Origin | Private bucket, all public access blocked, readable only by the distribution through Origin Access Control; versioned, 90 days of history; deploys cannot delete | verified: a direct request answers 403 |
| Edge | TLS 1.2 floor (TLS 1.1 refused), HTTP redirected to HTTPS, www to apex, HSTS with preload, strict CSP, frame denial, nosniff, referrer and permissions policies, honest 404 | verified from outside |
| Pipeline | Deploy only by manual dispatch from `main`; OIDC role with PutObject and invalidation only; the role trusts only this repository's `prod` Environment, and that Environment accepts only protected branches | verified |
| Repository | `main` protected: no force-push, no deletion, linear history, the CI check required, admins included; every merge is a squash commit signed by GitHub; SHA pinning required for actions; wiki off; secret scanning with push protection; private vulnerability reporting; Dependabot for the action pins | set 2026-09-07 |
| Domain | Route 53 delegation pinned in the sentinel; CAA restricting issuance to Amazon's CAs; DMARC reject; either null MX with SPF fail-all, or SES's MX, SPF, DKIM and MAIL FROM records once the mail stack exists; registrar transfer lock on helmetduck.com and helmet-duck.com | live since 2026-09-07; the sentinel requires them |
| Money | Monthly budget alert at 80% actual and 100% forecast; CloudFront request-flood alarm, one hour, email; the brake: on alarm the distribution is disabled for an hour, twice as long on each repeat up to a day, and re-enabled by a scheduled tick; bounds the bill, does not keep the site up | alerts live 2026-09-07; brake after the next apply |
| Edge blocklist | Each access-log file wakes a keeper that counts requests per address; an address at or above the threshold (600 in one file) is refused at the edge with 429 for an hour, a day if seen before, before any bandwidth is spent. The list lives in the edge function; `tools/blocklist.sh` shows, clears and tests it. Only hashes of addresses reach logs and mail | after the next apply |
| Watchers | Sentinel every hour with no credentials; sentry every six hours through a read-only role | both live |
| Detection of the operator | The sentinel opens an issue when a law breaks and closes it when the site heals; the sentry does the same for red log findings; both fail their run so the Actions email goes red | live with the sentinel |

## The sentinel

`tools/sentinel.py`, run by `.github/workflows/sentinel.yml`. It reads the revision
marker from the live home page, checks that the revision is a commit on `main`,
rebuilds that revision's `site/` with the current build script, and compares every
published file byte for byte with what the edge serves. Then, independently: no
script, frame, form or event handler in any live page; the six security headers;
the redirects; an honest 404 with the real 404 page; the bucket answers 403
directly; TLS 1.1 refused; certificate issuer, expiry and names; the NS delegation,
CAA, SPF, DMARC and MX answers; and through RDAP the registrar lock, the registry
delegation and the expiry.

Red fails the run and opens or updates one issue titled "sentinel: live-surface
findings". Amber is printed and does not fail: the DNS hygiene records and the
transfer lock are amber while absent until the owner has applied them, then the
flags at the top of the script are flipped and absence becomes red. A third party
being unreachable is always amber: their outage is not our incident.

## The sentry

`tools/sentry.py`, run by `.github/workflows/sentry.yml` through the role
`helmet-duck-sentry`, which can list and read the access-log bucket and nothing
else. It fetches two days of CloudFront standard logs, reads the last 24 hours by
each file's own field header, and reports: requests and bytes against thresholds
(red above 50,000 requests or 20 GB), distinct clients as a salted count, status
classes, every 200 outside the current build (red), probes for software that is not
here (all must be 4xx), the 5xx rate, any TLS below 1.2 (red), unexpected host
headers (amber), and the top paths, probes, user agents and referer hosts.

Every client-written string is defanged before it is printed: decoded once,
characters outside a plain set replaced, whitespace collapsed, length capped, URL
schemes broken, and the block labelled as data, never instruction. No client
address is printed, ever. The full report lands in the run summary every time; an
issue is opened only when a finding is red.

## What only the owner can do

- Run `tools/apply.sh` after `aws login`, with `HELMET_DUCK_ALERT_EMAIL` set, and
  confirm the subscription email. This creates the log bucket, the hygiene records,
  the alerts, the sentry role and the registrar lock. Done on 2026-09-07.
- Run `tools/mail.sh` with the forwarding mailbox for SES mail, click the verification
  link SES sends, and create the SMTP credentials in the SES console: they are a secret,
  which no script here handles. Received mail is stored in the account for 90 days.
- Keep two-factor authentication on the GitHub account and multi-factor
  authentication on the AWS root user. Neither can be verified from here.
- Decide on the paid items below.

## Not done, and why

- DNSSEC: the signing key costs about 1 USD a month. Not free, not yet.
- WAF with rate limiting: about 6 USD a month plus usage. The alarm, the sentry and
  the brake stand in for it: the brake bounds the bill, it cannot keep the site up
  under a flood; the edge blocklist keeps it up under a flood from one or a few
  addresses, with the minutes of delay until the log file lands, and cannot stop a
  flood from thousands of addresses each under the threshold. Shield Standard, AWS's network-level flood protection, is on with
  CloudFront at no cost.
- A CloudTrail trail and GuardDuty: storage and per-event fees. CloudTrail's free
  90-day event history is on by default.
- A rule requiring signed commits. It was tried and removed the same day: GitHub
  refuses to merge a pull request whose branch commits are unsigned, even though
  the squash commit it creates is signed, and the agent that opens the pull
  requests has no signing key. The squash merges are GitHub-signed anyway; the
  required check and admin enforcement are what stop an unreviewed change.

## Verify it yourself

```
curl -sI https://helmetduck.com/                       # headers
curl -sI --tls-max 1.1 https://helmetduck.com/; echo $? # 35 = refused
curl -sI https://helmet-duck-prod-site-244206438585.s3.amazonaws.com/index.html   # 403
python3 tools/sentinel.py                              # every law, from your machine
gh api repos/garitac/helmet-duck/branches/main/protection --jq '{enforce_admins: .enforce_admins.enabled, checks: .required_status_checks.contexts, signatures: .required_signatures.enabled}'
gh api repos/garitac/helmet-duck/actions/permissions --jq .sha_pinning_required
```
