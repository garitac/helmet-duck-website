#!/usr/bin/env bash
# Mail for helmetduck.com through Amazon SES. OWNER's terminal.
#
#   HELMET_DUCK_MAIL_FORWARD_TO=you@your-mailbox tools/mail.sh
#
# Idempotent. Signs you in if the cached session has expired (the browser opens),
# runs tools/apply.sh with the forwarding address so the mail stack exists and the
# zone's MX and SPF point at SES, asks AWS for SES production access if the account
# does not have it yet, waits for the domain's DKIM to verify, and opens the
# contract pull request. Then it prints the steps that stay yours: the verification
# link SES mailed to your mailbox, the SMTP credentials (a secret this script never
# touches), and the Gmail "send mail as" setup.
#
# Cost: effectively nothing at this volume. Receiving and sending are 0.10 USD per
# thousand messages; the bucket holds a few megabytes.
set -euo pipefail

PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanji-shisho}"
# Sign in with the profile's own mechanism: Identity Center (aws sso login) when the
# profile has an sso_session, otherwise the browser sign-in that also covers root.
sign_in() {
  aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1 && return 0
  if aws configure get sso_session --profile "$PROFILE" >/dev/null 2>&1 || aws configure get sso_start_url --profile "$PROFILE" >/dev/null 2>&1; then
    aws sso login --profile "$PROFILE"
  else
    aws login --profile "$PROFILE"
  fi
}
REGION=us-east-1
DOMAIN=helmetduck.com
REPO=garitac/helmet-duck
MAIL_STACK=helmet-duck-mail-prod
cd "$(dirname "$0")/.."

FORWARD="${HELMET_DUCK_MAIL_FORWARD_TO:-}"
if [ -z "$FORWARD" ] && aws cloudformation describe-stacks --stack-name "$MAIL_STACK" --region "$REGION" --profile "$PROFILE" >/dev/null 2>&1; then
  FORWARD="$(aws cloudformation describe-stacks --stack-name "$MAIL_STACK" --region "$REGION" --profile "$PROFILE" \
             --query "Stacks[0].Parameters[?ParameterKey=='ForwardTo'].ParameterValue | [0]" --output text)"
fi
[ -n "$FORWARD" ] || { echo "HELMET_DUCK_MAIL_FORWARD_TO is required the first time: the mailbox that receives the forwarded mail"; exit 1; }
case "$FORWARD" in *@example.*) echo "refusing: $FORWARD is a placeholder"; exit 1 ;; esac

sign_in
echo "signed in as $(aws sts get-caller-identity --profile "$PROFILE" --query Arn --output text)"

echo "== the stacks and the zone (tools/apply.sh)"
HELMET_DUCK_ADMIN_PROFILE="$PROFILE" HELMET_DUCK_MAIL_FORWARD_TO="$FORWARD" tools/apply.sh

echo "== SES production access (needed to send to anyone but verified addresses)"
if [ "$(aws sesv2 get-account --region "$REGION" --profile "$PROFILE" --query ProductionAccessEnabled --output text)" = "True" ]; then
  echo "granted"
else
  REVIEW="$(aws sesv2 get-account --region "$REGION" --profile "$PROFILE" --query 'Details.ReviewDetails.Status' --output text 2>/dev/null || echo none)"
  if [ "$REVIEW" = "PENDING" ]; then
    echo "requested earlier; AWS is reviewing"
  else
    aws sesv2 put-account-details --region "$REGION" --profile "$PROFILE" \
      --production-access-enabled --mail-type TRANSACTIONAL --website-url "https://$DOMAIN" \
      --contact-language EN --additional-contact-email-addresses "$FORWARD" \
      --use-case-description "Contact and support mailbox for the software project at https://$DOMAIN. Inbound mail to a handful of addresses at the domain is stored in the account and forwarded to the owner. Outbound mail is the owner's replies, sent from a mail client through SES SMTP, a few messages a day at most. No marketing, no lists, no automated campaigns."
    echo "requested; AWS usually answers within a day, by mail to the account's address"
  fi
fi

echo "== waiting for the domain's DKIM to verify (minutes, after the records propagate)"
DKIM=""; SEND=""
for i in $(seq 1 30); do
  read -r DKIM SEND <<< "$(aws sesv2 get-email-identity --email-identity "$DOMAIN" --region "$REGION" --profile "$PROFILE" \
                            --query '[DkimAttributes.Status, VerifiedForSendingStatus]' --output text)"
  echo "  dkim=$DKIM verified_for_sending=$SEND"
  [ "$DKIM" = "SUCCESS" ] && break
  sleep 30
done

echo "== contract: pull request"
if ! git diff --quiet -- environments/prod.env.yaml; then
  BRANCH="mail-$(date -u +%Y%m%d-%H%M)"
  git checkout -q -b "$BRANCH"
  git add environments/prod.env.yaml
  git commit -q -m "Record the SES mailbox in the contract" \
    -m "tools/mail.sh ran tools/apply.sh: the mail stack exists, the rule set is active, the zone's MX and SPF point at SES. The contract records the provider, the DKIM selectors the sentinel checks, and the sender address."
  git push -q -u origin "$BRANCH"
  gh pr create -R "$REPO" --base main --head "$BRANCH" --title "Record the SES mailbox in the contract" \
    --body "Opened by tools/mail.sh. Contract values only." >/dev/null
  gh pr merge -R "$REPO" --auto --squash --delete-branch "$BRANCH" || echo "merge it when the check is green"
  git checkout -q main
else
  echo "contract unchanged"
fi

SMTP="$(aws cloudformation describe-stacks --stack-name "$MAIL_STACK" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='SmtpEndpoint'].OutputValue | [0]" --output text)"
cat <<EOF

== yours
  1. SES mailed a verification link to $FORWARD. Click it: in the sandbox, forwarding works only to a verified address.
  2. Send a test message to hello@$DOMAIN from anywhere. It should arrive in $FORWARD within a minute,
     from "<sender> via $DOMAIN" with the original sender in Reply-To.
  3. To reply AS hello@$DOMAIN from Gmail, create SMTP credentials (a secret, so yours):
       https://$REGION.console.aws.amazon.com/ses/home?region=$REGION#/smtp
       "Create SMTP credentials" -> download the user name and password once.
     Then Gmail -> Settings -> Accounts -> "Send mail as" -> Add: hello@$DOMAIN,
       SMTP server $SMTP, the user name and password from above, TLS.
     Gmail mails a confirmation code to hello@$DOMAIN; it arrives through step 2.
  4. Until AWS grants production access, SES sends only to verified addresses; replies to
     customers wait for that mail from AWS.
EOF
