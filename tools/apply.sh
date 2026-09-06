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
# It creates or updates three CloudFormation stacks in us-east-1: the SES mail stack
# (when a forwarding address exists), the site (with its access-log bucket, DNS hygiene
# records and alerts) and the GitHub OIDC roles (deploy, and the read-only sentry). It creates the `prod` and `sentry` GitHub
# Environments with their variables, sets the registrar transfer lock on both
# domains, deploys the SES mail stack and points the zone at it when tools/mail.sh
# has given a forwarding address, and fills the contract file. Nothing is deleted, nothing is published:
# publishing is the deploy workflow, and its dry_run defaults to true.
set -euo pipefail

PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanji-shisho}"
REGION=us-east-1
ACCOUNT_EXPECTED=244206438585
DOMAIN=helmetduck.com
REPO=garitac/helmet-duck
FRONTEND_STACK=helmet-duck-frontend-prod
OIDC_STACK=helmet-duck-github-oidc
MAIL_STACK=helmet-duck-mail-prod
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

# Parameters not named here keep their stored values, so an apply without the
# alert address leaves the alerts as they are instead of deleting them.
FRONTEND_PARAMS=("SiteDomain=$DOMAIN" "HostedZoneId=$ZONE")
case "${HELMET_DUCK_ALERT_EMAIL:-}" in
  *@example.com|*@example.org|*@example.net)
    echo "refusing: HELMET_DUCK_ALERT_EMAIL is the placeholder '$HELMET_DUCK_ALERT_EMAIL'; alerts sent there reach nobody"; exit 1 ;;
  "") ;;
  *) FRONTEND_PARAMS+=("AlertEmail=$HELMET_DUCK_ALERT_EMAIL") ;;
esac

out() { aws cloudformation describe-stacks --stack-name "$1" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='$2'].OutputValue | [0]" --output text; }

echo "== mail: Amazon SES (infra/mail.yaml)"
# The mail stack exists once tools/mail.sh has run this with a forwarding address. It
# is deployed BEFORE the frontend stack, which then points the apex MX and SPF at SES.
# Without a forwarding address and without an existing mail stack the zone keeps
# saying "no mail". A placeholder address is refused.
MAIL_PROVIDER=none; DKIM_JSON="[]"; MAIL_SENDER=""
FORWARD="${HELMET_DUCK_MAIL_FORWARD_TO:-}"
case "$FORWARD" in *@example.*) echo "refusing: HELMET_DUCK_MAIL_FORWARD_TO is the placeholder '$FORWARD'"; exit 1 ;; esac
if [ -n "$FORWARD" ] || aws cloudformation describe-stacks --stack-name "$MAIL_STACK" --region "$REGION" --profile "$PROFILE" >/dev/null 2>&1; then
  MAIL_PARAMS=("SiteDomain=$DOMAIN" "HostedZoneId=$ZONE")
  [ -n "$FORWARD" ] && MAIL_PARAMS+=("ForwardTo=$FORWARD")
  aws cloudformation deploy --template-file infra/mail.yaml --stack-name "$MAIL_STACK" \
    --parameter-overrides "${MAIL_PARAMS[@]}" \
    --capabilities CAPABILITY_IAM --region "$REGION" --profile "$PROFILE" --no-fail-on-empty-changeset
  RULESET="$(out "$MAIL_STACK" RuleSetName)"
  aws ses set-active-receipt-rule-set --rule-set-name "$RULESET" --region "$REGION" --profile "$PROFILE"
  MAIL_SENDER="$(out "$MAIL_STACK" Sender)"
  DKIM_JSON="$(out "$MAIL_STACK" DkimSelectors | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().strip().split(",")))')"
  MAIL_PROVIDER=ses
  echo "mail stack $MAIL_STACK: rule set $RULESET active; forwarding to the configured mailbox; sender $MAIL_SENDER"
else
  echo "none: the zone keeps its null MX, SPF fail-all and DMARC reject"
fi
FRONTEND_PARAMS+=("MailProvider=$MAIL_PROVIDER")

echo "== stack $FRONTEND_STACK ($REGION): certificate, bucket, distribution, DNS"
aws cloudformation deploy --template-file infra/frontend.yaml --stack-name "$FRONTEND_STACK" \
  --parameter-overrides "${FRONTEND_PARAMS[@]}" \
  --region "$REGION" --profile "$PROFILE" --no-fail-on-empty-changeset
BUCKET="$(out "$FRONTEND_STACK" BucketName)"
DIST="$(out "$FRONTEND_STACK" DistributionId)"
CFDOMAIN="$(out "$FRONTEND_STACK" DistributionDomainName)"
LOGS="$(out "$FRONTEND_STACK" LogBucketName)"
echo "bucket $BUCKET  distribution $DIST  $CFDOMAIN"
if [ -n "${HELMET_DUCK_ALERT_EMAIL:-}" ]; then echo "logs $LOGS  alerts: set to the given address"; else echo "logs $LOGS  alerts: unchanged (no address given)"; fi

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
ALERTS_STATE="$(aws cloudformation describe-stacks --stack-name "$FRONTEND_STACK" --region "$REGION" --profile "$PROFILE" \
                --query "Stacks[0].Parameters[?ParameterKey=='AlertEmail'].ParameterValue | [0]" --output text)"
{ [ -n "$ALERTS_STATE" ] && [ "$ALERTS_STATE" != "None" ]; } && ALERTS_STATE=configured || ALERTS_STATE="not configured"
python3 - "$BUCKET" "$DIST" "$CFDOMAIN" "$ROLE" "$ZONE" "$LOGS" "$SENTRY" "$ALERTS_STATE" "$MAIL_PROVIDER" "$DKIM_JSON" "$MAIL_SENDER" <<'PY'
import pathlib, re, sys
b, d, c, r, z, logs, sentry, alerts, mail, dkim, sender = sys.argv[1:12]
p = pathlib.Path("environments/prod.env.yaml")
t = p.read_text()
t = re.sub(r'(?m)^(\s*dkim_selectors:).*$', r'\1 %s' % dkim, t)
for k, v in (("bucket", b), ("cloudfront_distribution", d), ("cloudfront_domain", c), ("role_arn", r), ("route53_hosted_zone_id", z),
             ("log_bucket", logs), ("sentry_role_arn", sentry), ("alerts", alerts), ("provider", mail), ("sender", sender)):
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
