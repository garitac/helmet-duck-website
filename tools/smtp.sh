#!/usr/bin/env bash
# SMTP credentials for sending as an address at helmetduck.com through Amazon SES,
# from the owner's terminal.
#
#   tools/smtp.sh create     an IAM user that may only send mail from this domain, one
#                            access key, and the SMTP password derived from it. Printed
#                            ONCE, here, then never stored anywhere by this script.
#   tools/smtp.sh rotate     a new key (printed once), the old one deleted
#   tools/smtp.sh revoke     every key deleted; Gmail stops sending until you create again
#   tools/smtp.sh status     the user and its keys (ids and ages, never secrets)
#
# The SMTP password is not a separate secret: SES derives it from the access key's
# secret with a published algorithm (an HMAC chain over the region, the service and
# the message "SendRawEmail"). This script performs that derivation locally, which is
# what the SES console's "Create SMTP credentials" button does for you.
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
USER=helmet-duck-smtp
ACCOUNT=244206438585
cd "$(dirname "$0")/.."
sign_in

ensure_user() {
  if ! aws iam get-user --user-name "$USER" --profile "$PROFILE" >/dev/null 2>&1; then
    aws iam create-user --user-name "$USER" --profile "$PROFILE" \
      --tags Key=Project,Value=helmet-duck Key=Purpose,Value="SES SMTP sending from the domain" >/dev/null
    echo "created IAM user $USER"
  fi
  # Least privilege: send raw mail through this domain's identity, from an address at
  # the domain, nothing else in the account.
  aws iam put-user-policy --user-name "$USER" --policy-name send-from-domain --profile "$PROFILE" --policy-document "$(cat <<EOF
{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ses:SendRawEmail",
  "Resource": "arn:aws:ses:$REGION:$ACCOUNT:identity/$DOMAIN",
  "Condition": {"StringLike": {"ses:FromAddress": "*@$DOMAIN"}}}]}
EOF
)"
}

new_key() {  # prints the credentials once; nothing is written to disk
  local out id secret
  out="$(aws iam create-access-key --user-name "$USER" --profile "$PROFILE" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)"
  id="${out%%	*}"; secret="${out##*	}"
  local password
  password="$(python3 - "$secret" "$REGION" <<'PY'
import base64, hashlib, hmac, sys
secret, region = sys.argv[1], sys.argv[2]
def sign(key, msg):
    return hmac.new(key, msg.encode(), hashlib.sha256).digest()
k = sign(("AWS4" + secret).encode(), "11111111")
for part in (region, "ses", "aws4_request", "SendRawEmail"):
    k = sign(k, part)
print(base64.b64encode(bytes([0x04]) + k).decode())
PY
)"
  cat <<EOF

== SMTP credentials, shown once. Paste them into Gmail now; this script keeps nothing.
  SMTP server  : email-smtp.$REGION.amazonaws.com
  Port         : 587   (Secured connection using TLS)
  User name    : $id
  Password     : $password

== Gmail: the gear -> See all settings -> Accounts and Import -> Send mail as -> Add another email address
  Name: your name        Email: hello@$DOMAIN        keep "Treat as an alias" ticked -> Next Step
  then the four values above -> Add Account. Gmail mails a code to hello@$DOMAIN; it arrives in your
  inbox through the forwarder within a minute. Enter it.
  Then, same page: "Reply from the same address the message was sent to".
EOF
  command -v open >/dev/null && open "https://mail.google.com/mail/u/0/#settings/accounts" || true
}

case "${1:-status}" in
  create)
    ensure_user
    if [ "$(aws iam list-access-keys --user-name "$USER" --profile "$PROFILE" --query 'length(AccessKeyMetadata)' --output text)" != "0" ]; then
      echo "$USER already has a key. Use rotate for a new one (the old is deleted) or revoke to remove all."; exit 1
    fi
    new_key ;;
  rotate)
    ensure_user
    OLD="$(aws iam list-access-keys --user-name "$USER" --profile "$PROFILE" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
    new_key
    for k in $OLD; do aws iam delete-access-key --user-name "$USER" --access-key-id "$k" --profile "$PROFILE"; echo "deleted old key $k"; done ;;
  revoke)
    for k in $(aws iam list-access-keys --user-name "$USER" --profile "$PROFILE" --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
      aws iam delete-access-key --user-name "$USER" --access-key-id "$k" --profile "$PROFILE"; echo "deleted key $k"
    done
    echo "no key remains; Gmail cannot send as the domain until you run create" ;;
  status)
    if aws iam get-user --user-name "$USER" --profile "$PROFILE" >/dev/null 2>&1; then
      echo "user $USER"; aws iam list-access-keys --user-name "$USER" --profile "$PROFILE" \
        --query 'AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]' --output text
    else
      echo "no SMTP user yet; run: tools/smtp.sh create"
    fi ;;
  *)
    echo "usage: tools/smtp.sh create|rotate|revoke|status"; exit 2 ;;
esac
