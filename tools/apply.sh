#!/usr/bin/env bash
# One-command, idempotent apply of the helmetduck.com pipeline. Run by the OWNER
# from a terminal after signing in to the account (root or admin):
#
#   aws login --profile kanji-shisho
#   HELMET_DUCK_ALERT_EMAIL=you@example.com tools/apply.sh
#
# HELMET_DUCK_ALERT_EMAIL receives the monthly budget alert and the request-flood
# alarm; leave it unset to create neither. It is a stack parameter, never committed.
# HELMET_DUCK_ADMIN_PROFILE overrides the profile name.
#
# It creates or updates two CloudFormation stacks in us-east-1: the site (with its
# access-log bucket, DNS hygiene records and alerts) and the GitHub OIDC roles
# (deploy, and the read-only sentry). It creates the `prod` and `sentry` GitHub
# Environments with their variables, sets the registrar transfer lock on both
# domains, and fills the contract file. Nothing is deleted, nothing is published:
# publishing is the deploy workflow, and its dry_run defaults to true.
set -euo pipefail

PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanji-shisho}"
REGION=us-east-1
ACCOUNT_EXPECTED=244206438585
DOMAIN=helmetduck.com
REPO=garitac/helmet-duck
FRONTEND_STACK=helmet-duck-frontend-prod
OIDC_STACK=helmet-duck-github-oidc
cd "$(dirname "$0")/.."

echo "== identity"
ACCOUNT="$(aws sts get-caller-identity --profile "$PROFILE" --query Account --output text)"
[ "$ACCOUNT" = "$ACCOUNT_EXPECTED" ] || { echo "refusing: profile $PROFILE is account $ACCOUNT, expected $ACCOUNT_EXPECTED"; exit 1; }
aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text

echo "== hosted zone for $DOMAIN"
ZONE="$(aws route53 list-hosted-zones-by-name --dns-name "$DOMAIN." --profile "$PROFILE" \
        --query "HostedZones[?Name=='$DOMAIN.'].Id | [0]" --output text | sed 's|/hostedzone/||')"
[ -n "$ZONE" ] && [ "$ZONE" != "None" ] || { echo "refusing: no public hosted zone for $DOMAIN in this account"; exit 1; }
echo "zone $ZONE"

echo "== stack $FRONTEND_STACK ($REGION): certificate, bucket, distribution, DNS"
aws cloudformation deploy --template-file infra/frontend.yaml --stack-name "$FRONTEND_STACK" \
  --parameter-overrides "SiteDomain=$DOMAIN" "HostedZoneId=$ZONE" "AlertEmail=${HELMET_DUCK_ALERT_EMAIL:-}" \
  --region "$REGION" --profile "$PROFILE" --no-fail-on-empty-changeset
out() { aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue | [0]" --output text; }
BUCKET="$(out "$FRONTEND_STACK" BucketName)"
DIST="$(out "$FRONTEND_STACK" DistributionId)"
CFDOMAIN="$(out "$FRONTEND_STACK" DistributionDomainName)"
LOGS="$(out "$FRONTEND_STACK" LogBucketName)"
echo "bucket $BUCKET  distribution $DIST  $CFDOMAIN"
echo "logs $LOGS  alerts ${HELMET_DUCK_ALERT_EMAIL:+configured}${HELMET_DUCK_ALERT_EMAIL:-not configured (no email given)}"

echo "== GitHub OIDC provider in this account"
PROVIDER="$(aws iam list-open-id-connect-providers --profile "$PROFILE" --output text \
            | tr '\t' '\n' | grep 'token.actions.githubusercontent.com' || true)"
echo "${PROVIDER:-none, the stack will create it}"

echo "== stack $OIDC_STACK: deploy role"
aws cloudformation deploy --template-file infra/github-oidc.yaml --stack-name "$OIDC_STACK" \
  --parameter-overrides "BucketName=$BUCKET" "DistributionId=$DIST" "ExistingOidcProviderArn=$PROVIDER" "LogBucketName=$LOGS" \
  --capabilities CAPABILITY_NAMED_IAM --region "$REGION" --profile "$PROFILE" --no-fail-on-empty-changeset
ROLE="$(out "$OIDC_STACK" DeployRoleArn)"
SENTRY="$(out "$OIDC_STACK" SentryRoleArn)"
echo "deploy role $ROLE"
echo "sentry role $SENTRY"

echo "== GitHub environment prod (protected branches only) and its variables"
POLICY='{"deployment_branch_policy":{"protected_branches":true,"custom_branch_policies":false}}'
gh api -X PUT "repos/$REPO/environments/prod" --input - <<< "$POLICY" >/dev/null
gh variable set AWS_DEPLOY_ROLE_ARN --env prod --body "$ROLE" -R "$REPO"
gh variable set SITE_BUCKET --env prod --body "$BUCKET" -R "$REPO"
gh variable set CLOUDFRONT_DISTRIBUTION_ID --env prod --body "$DIST" -R "$REPO"
gh variable list --env prod -R "$REPO"

echo "== GitHub environment sentry (read-only log role) and its variables"
gh api -X PUT "repos/$REPO/environments/sentry" --input - <<< "$POLICY" >/dev/null
gh variable set AWS_SENTRY_ROLE_ARN --env sentry --body "$SENTRY" -R "$REPO"
gh variable set LOG_BUCKET --env sentry --body "$LOGS" -R "$REPO"
gh variable list --env sentry -R "$REPO"

echo "== registrar transfer lock (Route 53 Domains, us-east-1)"
for d in helmetduck.com helmet-duck.com; do
  if aws route53domains get-domain-detail --domain-name "$d" --region us-east-1 --profile "$PROFILE" \
       --query StatusList --output text 2>/dev/null | grep -q clientTransferProhibited; then
    echo "$d: transfer lock already on"
  elif aws route53domains enable-domain-transfer-lock --domain-name "$d" --region us-east-1 --profile "$PROFILE" --output text >/dev/null; then
    echo "$d: transfer lock requested; it shows in whois within minutes"
  else
    echo "$d: could not set the lock from here; set it in the Route 53 console under Registered domains"
  fi
done

echo "== environment contract"
python3 - "$BUCKET" "$DIST" "$CFDOMAIN" "$ROLE" "$ZONE" "$LOGS" "$SENTRY" "${HELMET_DUCK_ALERT_EMAIL:+configured}" <<'PY'
import pathlib, sys
b, d, c, r, z, logs, sentry, alerts = sys.argv[1:9]
p = pathlib.Path("environments/prod.env.yaml")
t = p.read_text()
for k, v in (("bucket", b), ("cloudfront_distribution", d), ("cloudfront_domain", c), ("role_arn", r), ("route53_hosted_zone_id", z),
             ("log_bucket", logs), ("sentry_role_arn", sentry), ("alerts", alerts or "not configured")):
    import re
    t = re.sub(r'(?m)^(\s*%s:).*$' % k, r'\1 "%s"' % v, t)
t = t.replace("status: PLANNED", "status: CREATED")
p.write_text(t)
print(t)
PY

echo
echo "Applied. Next:"
echo "  1. If an alert email was given, confirm the SNS subscription mail it just received."
echo "  2. Commit environments/prod.env.yaml through a pull request."
echo "  3. Run both watchers once and read their summaries:"
echo "       gh workflow run sentinel.yml -R $REPO --ref main"
echo "       gh workflow run sentry.yml -R $REPO --ref main"
echo "  4. Flip dns_hygiene_required and transfer_lock_required to True in tools/sentinel.py."
echo "  Publishing is still the deploy workflow: gh workflow run deploy.yml -R $REPO --ref main -f dry_run=true"
