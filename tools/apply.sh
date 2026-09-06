#!/usr/bin/env bash
# One-command, idempotent apply of the helmetduck.com pipeline. Run by the OWNER
# from a terminal after signing in to the admin profile:
#
#   aws sso login --profile kanjishisho-bootstrap-admin
#   tools/apply.sh
#
# It creates or updates two CloudFormation stacks in us-east-1 (the site and the
# GitHub OIDC deploy role), creates the `prod` GitHub Environment, and sets its
# three variables. Nothing is deleted, nothing is published: the first publish
# is the deploy workflow, and its dry_run defaults to true.
set -euo pipefail

PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanjishisho-bootstrap-admin}"
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
  --parameter-overrides "SiteDomain=$DOMAIN" "HostedZoneId=$ZONE" \
  --region "$REGION" --profile "$PROFILE" --no-fail-on-empty-changeset
out() { aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue | [0]" --output text; }
BUCKET="$(out "$FRONTEND_STACK" BucketName)"
DIST="$(out "$FRONTEND_STACK" DistributionId)"
CFDOMAIN="$(out "$FRONTEND_STACK" DistributionDomainName)"
echo "bucket $BUCKET  distribution $DIST  $CFDOMAIN"

echo "== GitHub OIDC provider in this account"
PROVIDER="$(aws iam list-open-id-connect-providers --profile "$PROFILE" --output text \
            | tr '\t' '\n' | grep 'token.actions.githubusercontent.com' || true)"
echo "${PROVIDER:-none, the stack will create it}"

echo "== stack $OIDC_STACK: deploy role"
aws cloudformation deploy --template-file infra/github-oidc.yaml --stack-name "$OIDC_STACK" \
  --parameter-overrides "BucketName=$BUCKET" "DistributionId=$DIST" "ExistingOidcProviderArn=$PROVIDER" \
  --capabilities CAPABILITY_NAMED_IAM --region "$REGION" --profile "$PROFILE" --no-fail-on-empty-changeset
ROLE="$(out "$OIDC_STACK" DeployRoleArn)"
echo "role $ROLE"

echo "== GitHub environment prod and its variables"
gh api -X PUT "repos/$REPO/environments/prod" >/dev/null
gh variable set AWS_DEPLOY_ROLE_ARN --env prod --body "$ROLE" -R "$REPO"
gh variable set SITE_BUCKET --env prod --body "$BUCKET" -R "$REPO"
gh variable set CLOUDFRONT_DISTRIBUTION_ID --env prod --body "$DIST" -R "$REPO"
gh variable list --env prod -R "$REPO"

echo "== environment contract"
python3 - "$BUCKET" "$DIST" "$CFDOMAIN" "$ROLE" "$ZONE" <<'PY'
import pathlib, sys
b, d, c, r, z = sys.argv[1:6]
p = pathlib.Path("environments/prod.env.yaml")
t = p.read_text()
for k, v in (("bucket", b), ("cloudfront_distribution", d), ("cloudfront_domain", c), ("role_arn", r), ("route53_hosted_zone_id", z)):
    import re
    t = re.sub(r'(?m)^(\s*%s:).*$' % k, r'\1 "%s"' % v, t)
t = t.replace("status: PLANNED", "status: CREATED")
p.write_text(t)
print(t)
PY

echo
echo "Applied. Next: commit environments/prod.env.yaml, then run the deploy workflow with dry_run=true,"
echo "then with dry_run=false when the page is approved:"
echo "  gh workflow run deploy.yml -R $REPO --ref main -f dry_run=true"
