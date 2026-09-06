#!/usr/bin/env bash
# One mailbox for the domain: Amazon WorkMail for helmetduck.com. OWNER's terminal.
#
#   tools/mail.sh
#
# Idempotent. Signs you in if the cached session has expired (the browser opens),
# creates the WorkMail organization "helmetduck" in us-east-1 if absent (WorkMail
# is not offered in Tokyo; the rest of the stack lives in us-east-1 anyway),
# registers helmetduck.com, runs tools/apply.sh so the zone receives WorkMail's MX,
# SPF, verification, DKIM and autodiscover records, waits for WorkMail to verify
# them, makes the domain the default, and commits the contract through a pull
# request that merges itself when the check is green.
#
# The one step that stays yours: creating the mailbox user, because it has a
# password. The organization itself costs nothing; each user is 4 USD a month.
set -euo pipefail

PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanji-shisho}"
REGION=us-east-1
ALIAS=helmetduck
DOMAIN=helmetduck.com
REPO=garitac/helmet-duck
cd "$(dirname "$0")/.."

aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1 || aws login --profile "$PROFILE"
echo "signed in as $(aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text)"
wm() { aws workmail "$@" --region "$REGION" --profile "$PROFILE"; }

echo "== WorkMail organization $ALIAS"
ORG="$(wm list-organizations --query "OrganizationSummaries[?Alias=='$ALIAS'].OrganizationId | [0]" --output text)"
if [ -z "$ORG" ] || [ "$ORG" = "None" ]; then
  ORG="$(wm create-organization --alias "$ALIAS" --query OrganizationId --output text)"
  echo "created $ORG"
fi
STATE=""
for i in $(seq 1 40); do
  STATE="$(wm describe-organization --organization-id "$ORG" --query State --output text)"
  [ "$STATE" = "Active" ] && break
  echo "  $STATE; waiting"
  sleep 15
done
[ "$STATE" = "Active" ] || { echo "organization $ORG is $STATE after ten minutes; run this again later"; exit 1; }
echo "organization $ORG is Active"

echo "== domain $DOMAIN"
if ! wm get-mail-domain --organization-id "$ORG" --domain-name "$DOMAIN" >/dev/null 2>&1; then
  wm register-mail-domain --organization-id "$ORG" --domain-name "$DOMAIN"
  echo "registered"
fi
wm get-mail-domain --organization-id "$ORG" --domain-name "$DOMAIN" \
  --query 'Records[].[Type, Hostname, Value]' --output table

echo "== the zone: MX, SPF, verification, DKIM, autodiscover (tools/apply.sh)"
HELMET_DUCK_ADMIN_PROFILE="$PROFILE" tools/apply.sh

echo "== waiting for WorkMail to verify ownership and DKIM (usually minutes)"
OWN=""; DKIM=""
for i in $(seq 1 40); do
  read -r OWN DKIM <<< "$(wm get-mail-domain --organization-id "$ORG" --domain-name "$DOMAIN" \
                          --query '[OwnershipVerificationStatus, DkimVerificationStatus]' --output text)"
  echo "  ownership=$OWN dkim=$DKIM"
  [ "$OWN" = "VERIFIED" ] && [ "$DKIM" = "VERIFIED" ] && break
  sleep 30
done
if [ "$OWN" = "VERIFIED" ]; then
  wm update-default-mail-domain --organization-id "$ORG" --domain-name "$DOMAIN"
  echo "default mail domain: $DOMAIN"
else
  echo "not verified yet; run this script again later and it will set the default domain"
fi

echo "== contract: pull request"
if ! git diff --quiet -- environments/prod.env.yaml; then
  BRANCH="mail-$(date -u +%Y%m%d-%H%M)"
  git checkout -q -b "$BRANCH"
  git add environments/prod.env.yaml
  git commit -q -m "Record the WorkMail mailbox in the contract" \
    -m "tools/mail.sh created the WorkMail organization and tools/apply.sh pointed the zone's mail records at it. The contract records the provider, the DKIM selectors the sentinel checks, and the webmail address."
  git push -q -u origin "$BRANCH"
  gh pr create -R "$REPO" --base main --head "$BRANCH" --title "Record the WorkMail mailbox in the contract" \
    --body "Opened by tools/mail.sh. Contract values only." >/dev/null
  gh pr merge -R "$REPO" --auto --squash --delete-branch "$BRANCH" || echo "merge it when the check is green"
  git checkout -q main
else
  echo "contract unchanged"
fi

cat <<EOF

== yours: the mailbox user (it has a password, so the script does not create it)
  console: https://us-east-1.console.aws.amazon.com/workmail/v2/home?region=$REGION#/organizations/$ORG/users
  Add user -> user name, display name, primary address at $DOMAIN, password. 4 USD a month per user.
  webmail:  https://$ALIAS.awsapps.com/mail
  mail app: IMAP imap.mail.$REGION.awsapps.com port 993 (SSL); SMTP smtp.mail.$REGION.awsapps.com port 465 (SSL);
            user name is the full address.
EOF
