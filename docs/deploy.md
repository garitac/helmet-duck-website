# helmetduck.com: pipeline and deployment runbook

Static site, private S3 bucket behind CloudFront with Origin Access Control, a
certificate issued and DNS-validated in the account's own Route 53 hosted zone,
deployed by GitHub Actions through OIDC. No long-lived keys anywhere. Everything
lives in `us-east-1` because CloudFront reads certificates only from that region.

## Pieces

| Piece | File | Notes |
| --- | --- | --- |
| Site source | `site/` | HTML, one stylesheet, SVG logo. No scripts, no third-party assets; the CSP forbids both. |
| Build | `tools/build.py` | `site/` to `dist/`: fingerprints CSS, stamps the revision marker, writes sitemap and robots. |
| Gate | `tools/check.py` | Duck selftest, manifests, skill frontmatter, site links, weight budget, no scripts, no dotfiles. |
| CI | `.github/workflows/ci.yml` | Runs the gate on every push and pull request. No AWS. |
| Deploy | `.github/workflows/deploy.yml` | Manual only, main only, `dry_run` defaults to true. Assets immutable, HTML no-cache, never `--delete`, targeted invalidation, waits until the edge serves the exact commit. |
| Infra | `infra/frontend.yaml` | Certificate, bucket, OAC, headers policy, edge router, distribution, A/AAAA records. |
| Identity | `infra/github-oidc.yaml` | Deploy role trusting only `garitac/helmet-duck` environment `prod`. Creates the account's OIDC provider only if none exists. |
| Apply | `tools/apply.sh` | Idempotent: both stacks, the GitHub Environment, its three variables, the contract file. |
| Contract | `environments/prod.env.yaml` | The one place the deploy targets are written down. |

## First-time apply (owner, from a terminal)

1. Sign in to the admin profile of account 244206438585. The browser opens; the
   session is cached locally for the CLI.

   ```
   aws sso login --profile kanjishisho-bootstrap-admin
   ```

2. Apply. Certificate validation is the slow step, usually a few minutes; the
   stack waits for it.

   ```
   tools/apply.sh
   ```

3. Commit the filled `environments/prod.env.yaml`.

4. Prove the pipeline without publishing: dry run.

   ```
   gh workflow run deploy.yml -R garitac/helmet-duck --ref main -f dry_run=true
   ```

5. Publish, once the page content is approved.

   ```
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
hundred kilobytes. No WAF, no analytics, no Lambda.

## Deliberately not done

- No email for the domain (no MX, no SES). The page carries no email address.
- No WAF and no analytics. Add them as separate, reviewed changes.
- No dev or staging environment. One page, one environment, dry run as the preview.

## Reconstructed, not depended on

The shape of the stacks and workflows was reconstructed from the owner's other
static sites. Nothing here reads from or points at those repositories; every
template, script and pin is local to this one.
