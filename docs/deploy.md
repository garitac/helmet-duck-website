# helmetduck.com: pipeline and deployment runbook

Static site, private S3 bucket behind CloudFront with Origin Access Control, a
certificate issued and DNS-validated in the account's own Route 53 hosted zone,
deployed by GitHub Actions through OIDC. No long-lived keys anywhere. Everything
lives in `us-east-1` because CloudFront reads certificates only from that region.
The security posture and the watchers are described in [security.md](security.md).

## Pieces

| Piece | File | Notes |
| --- | --- | --- |
| Site source | `site/` | HTML, one stylesheet, SVG logo. No scripts, no third-party assets; the CSP forbids both. |
| Build | `tools/build.py` | `site/` to `dist/`: fingerprints CSS, stamps the revision marker, writes sitemap and robots. `--site` builds another tree; `HELMET_DUCK_REVISION` forces the marker (the sentinel uses both). |
| Gate | `tools/check.py` | Duck selftest, manifests, skill frontmatter, tools compile, sentry selftest, workflow pins, site links, weight budget, no scripts, no dotfiles, English only. |
| CI | `.github/workflows/ci.yml` | Runs the gate on every push and pull request. No AWS. |
| Deploy | `.github/workflows/deploy.yml` | Manual only, main only, `dry_run` defaults to true. Assets immutable, HTML no-cache, never `--delete`, targeted invalidation, waits until the edge serves the exact commit. |
| Sentinel | `.github/workflows/sentinel.yml`, `tools/sentinel.py` | Every six hours, no credentials: rebuilds the live revision and compares every file, checks headers, redirects, 404, bucket, TLS, certificate, DNS and registration. One standing issue. |
| Sentry | `.github/workflows/sentry.yml`, `tools/sentry.py` | Every six hours, read-only role: reads the access logs, counts, classifies probes, defangs every client string. Report in the run summary; an issue only when red. |
| Board | `tools/board.sh` | The one-issue alert board both watchers use. |
| Infra | `infra/frontend.yaml` | Certificate, site bucket, log bucket, OAC, headers policy, edge router, distribution with logging, A/AAAA records, CAA, null MX, SPF, DMARC, and (with an email) SNS topic, request-flood alarm, monthly budget. |
| Identity | `infra/github-oidc.yaml` | Deploy role trusting only `garitac/helmet-duck` Environment `prod`; sentry role trusting only Environment `sentry`, reading the log bucket only. Creates the account's OIDC provider only if none exists. |
| Apply | `tools/apply.sh` | Idempotent: the three stacks (mail when a forwarding address exists, site, roles), both GitHub Environments (protected branches only) and their variables, the registrar lock on both domains, the contract file. |
| Mail | `infra/mail.yaml`, `tools/mail.sh` | Amazon SES in us-east-1: domain identity with DKIM and MAIL FROM, receipt rule storing each message in a private bucket for 90 days, a forwarder function to the owner's mailbox, the owner's mailbox verified for the sandbox. The script runs the apply, requests production access, waits for DKIM, opens the contract pull request. SMTP credentials for replying from Gmail are the owner's. |
| Contract | `environments/prod.env.yaml` | The one place the deploy targets are written down. |
| Pins | `.github/dependabot.yml` | Weekly pull requests for the action SHAs. The repository requires SHA pinning. |

## Apply (owner, from a terminal, any time; it is idempotent)

1. Sign in to account 244206438585. The browser opens; the session is cached for the CLI.

   ```
   aws login --profile kanji-shisho
   ```

2. Apply, with the address that should receive the budget alert and the flood alarm.
   Certificate validation was the slow step the first time; a re-apply that adds
   logging updates the distribution, a few minutes.

   ```
   HELMET_DUCK_ALERT_EMAIL=you@example.com tools/apply.sh
   ```

3. Confirm the subscription email that SNS sends to that address, or the alarm has
   nowhere to go.

4. Commit the filled `environments/prod.env.yaml` through a pull request (main
   accepts nothing else).

5. Run both watchers once and read their summaries in the Actions tab, then set
   `dns_hygiene_required` and `transfer_lock_required` to `True` in `tools/sentinel.py`.

   ```
   gh workflow run sentinel.yml -R garitac/helmet-duck --ref main
   gh workflow run sentry.yml -R garitac/helmet-duck --ref main
   ```

## Publish

Prove the pipeline without publishing, then publish:

```
gh workflow run deploy.yml -R garitac/helmet-duck --ref main -f dry_run=true
gh workflow run deploy.yml -R garitac/helmet-duck --ref main -f dry_run=false
```

## Rollback

The bucket is versioned with 90 days of noncurrent history. Roll back by
re-deploying an earlier commit from main; the marker wait proves which revision
the edge serves. Nothing in the pipeline can delete an object.

## Cost

Route 53 hosted zone 0.50 USD a month (already paid for the domain). S3, CloudFront
and the certificate are effectively free at this traffic: CloudFront's always-free
tier covers 1 TB a month, ACM public certificates cost nothing, S3 stores a few
hundred kilobytes of site and a few megabytes of logs. Standard logging and the
budget are free. The request-flood alarm costs about 0.10 USD a month. Mail through
SES is 0.10 USD per thousand messages each way, a few cents at most. No WAF, no analytics.

## Deliberately not done

- No mail server and no hosted mailbox. AWS stopped selling WorkMail in April 2026;
  mail is SES receiving forwarded to the owner's own mailbox, and replies go out
  through SES SMTP from that mailbox. Without the mail stack the zone says null MX,
  SPF fail-all, DMARC reject; the sentinel accepts exactly those two states.
- No WAF. The sentry reads the access logs and the alarm watches volume instead;
  a WAF is a separate, reviewed change if the logs ever justify its cost.
- No DNSSEC. The signing key would cost about 1 USD a month; not yet.
- No dev or staging environment. One page, one environment, dry run as the preview.

## Reconstructed, not depended on

The shape of the stacks, workflows and watchers was reconstructed from the owner's
other static sites. Nothing here reads from or points at those repositories; every
template, script and pin is local to this one.
