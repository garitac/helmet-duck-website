#!/usr/bin/env bash
# A credential for the Helmet Duck Console that does not expire.
#
#   tools/console-key.sh create     an IAM user that may only read what the console
#                                   shows, one access key, stored in the login Keychain
#                                   and never written to disk, and the AWS profile that
#                                   reads it back. Needs the admin session, once.
#   tools/console-key.sh status     the identity, the key's id and age, the Keychain
#                                   item, the profile, and a live probe of every call
#                                   the console makes. Never prints a secret.
#   tools/console-key.sh rotate     a new key stored and proved, then the old one deleted
#   tools/console-key.sh revoke     every key deleted and the Keychain item removed; the
#                                   console falls back to the admin session
#   tools/console-key.sh credential-process    what the AWS CLI calls; prints the
#                                   credential document. Not for humans.
#
# Why this exists: the console read AWS through the owner's Identity Center session,
# which expires after twelve hours, so a dashboard opened the next morning showed
# nothing but the words "Token has expired". This identity has no session and no
# expiry. What it costs is a standing key on this Mac, so the key is held by the
# login Keychain rather than by a file, is passed to the Keychain on standard input
# rather than on a command line, and can do nothing but read: the policy allows the
# seven calls the console makes and then denies every other action in the account
# outright, so the ceiling holds even if another policy is ever attached.
set -euo pipefail
umask 077

PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanjishisho-bootstrap-admin}"   # the admin session, for create/rotate/revoke
CONSOLE_PROFILE=helmet-duck-console
SERVICE=helmet-duck-console
IAM_USER=helmet-duck-console-reader
POLICY_NAME=read-what-the-console-shows
REGION=us-east-1
FUNCTION=helmet-duck-prod-edge-router
BRAKE=/helmet-duck/prod/brake

SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"; TARGET="$(readlink "$SOURCE")"
  case "$TARGET" in /*) SOURCE="$TARGET" ;; *) SOURCE="$DIR/$TARGET" ;; esac
done
SELF="$(cd -P "$(dirname "$SOURCE")" && pwd)/$(basename "$SOURCE")"
ROOT="$(cd -P "$(dirname "$SELF")/.." && pwd)"

die() { echo "console-key: $*" >&2; exit 1; }

# ---------------------------------------------------------------- the Keychain item
# The secret reaches the Keychain on standard input, so it never appears in the
# argument list of any process. /usr/bin/security is pre-authorised to read it back,
# so the console does not raise a Keychain prompt when it starts.
keychain_put() {  # $1 access key id, $2 secret, read from the caller's variable
  security delete-generic-password -s "$SERVICE" >/dev/null 2>&1 || true
  printf 'add-generic-password -a %s -s %s -j %s -T /usr/bin/security -U -w %s\n' \
    "$1" "$SERVICE" "helmet-duck-console" "$2" | security -i >/dev/null
}
keychain_id() { security find-generic-password -s "$SERVICE" 2>/dev/null | sed -n 's/^[[:space:]]*"acct"<blob>="\(.*\)"$/\1/p'; }
keychain_secret() { security find-generic-password -s "$SERVICE" -w 2>/dev/null; }
keychain_drop() { security delete-generic-password -s "$SERVICE" >/dev/null 2>&1 || true; }

# ---------------------------------------------------------------- what the CLI calls
credential_process() {
  local id secret
  id="$(keychain_id)" || true
  secret="$(keychain_secret)" || true
  [ -n "$id" ] && [ -n "$secret" ] || die "no console key in the login Keychain; run: tools/console-key.sh create"
  printf '{"Version":1,"AccessKeyId":"%s","SecretAccessKey":"%s"}\n' "$id" "$secret"
}

# ---------------------------------------------------------------- the admin session
sign_in() {
  aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1 && return 0
  echo "The admin session has expired. Signing in once, to create the identity that never will."
  aws sso login --profile "$PROFILE"
}

contract() {  # $1 key in environments/prod.env.yaml
  sed -n "s/^[[:space:]]*$1:[[:space:]]*\"\([^\"]*\)\".*/\1/p" "$ROOT/environments/prod.env.yaml" | head -1
}

policy_document() {
  local account="$1" logs="$2" allow
  allow='"cloudwatch:GetMetricStatistics","cloudwatch:DescribeAlarms","s3:ListBucket","s3:GetBucketLocation","s3:GetObject","ssm:GetParameter","cloudfront:GetFunction","ses:GetAccount","sts:GetCallerIdentity"'
  cat <<EOF
{"Version": "2012-10-17", "Statement": [
 {"Sid": "EdgeMetricsAndTheAlarm", "Effect": "Allow",
  "Action": ["cloudwatch:GetMetricStatistics", "cloudwatch:DescribeAlarms"], "Resource": "*"},
 {"Sid": "TheAccessLogsOnly", "Effect": "Allow",
  "Action": ["s3:ListBucket", "s3:GetBucketLocation"], "Resource": "arn:aws:s3:::$logs"},
 {"Sid": "ReadTheAccessLogs", "Effect": "Allow",
  "Action": "s3:GetObject", "Resource": "arn:aws:s3:::$logs/*"},
 {"Sid": "TheBrakeOnly", "Effect": "Allow",
  "Action": "ssm:GetParameter", "Resource": "arn:aws:ssm:$REGION:$account:parameter$BRAKE"},
 {"Sid": "TheEdgeRouterOnly", "Effect": "Allow",
  "Action": "cloudfront:GetFunction", "Resource": "arn:aws:cloudfront::$account:function/$FUNCTION"},
 {"Sid": "MailSendingState", "Effect": "Allow",
  "Action": "ses:GetAccount", "Resource": "*"},
 {"Sid": "NothingElseEverEvenIfAnotherPolicyIsAttached", "Effect": "Deny",
  "NotAction": [$allow], "Resource": "*"}]}
EOF
}

ensure_user() {
  local account logs
  account="$(contract account_id)"; logs="$(contract log_bucket)"
  [ -n "$account" ] && [ -n "$logs" ] || die "environments/prod.env.yaml does not name the account and the log bucket"
  if ! aws iam get-user --user-name "$IAM_USER" --profile "$PROFILE" >/dev/null 2>&1; then
    aws iam create-user --user-name "$IAM_USER" --profile "$PROFILE" \
      --tags Key=Project,Value=helmet-duck Key=Purpose,Value="Read-only console on the owner's Mac" >/dev/null
    echo "created IAM user $IAM_USER"
  fi
  aws iam put-user-policy --user-name "$IAM_USER" --policy-name "$POLICY_NAME" --profile "$PROFILE" \
    --policy-document "$(policy_document "$account" "$logs")"
  echo "policy $POLICY_NAME applied: seven reads allowed, everything else denied"
}

new_key() {  # stores the key in the Keychain; the secret is never printed and never touches a file
  local out id secret
  out="$(aws iam create-access-key --user-name "$IAM_USER" --profile "$PROFILE" --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)"
  id="${out%%	*}"; secret="${out##*	}"
  [ "${#id}" -ge 16 ] && [ -n "$secret" ] || die "AWS did not return a usable key"
  keychain_put "$id" "$secret"
  secret=""
  [ "$(keychain_id)" = "$id" ] || die "the Keychain did not keep the key"
  echo "key $id stored in the login Keychain (service $SERVICE)"
}

ensure_profile() {
  case "$SELF" in *" "*) die "this repository's path contains a space, which the AWS CLI cannot pass to a credential process" ;; esac
  aws configure set --profile "$CONSOLE_PROFILE" credential_process "$SELF credential-process"
  aws configure set --profile "$CONSOLE_PROFILE" region "$REGION"
  aws configure set --profile "$CONSOLE_PROFILE" output json
  echo "profile $CONSOLE_PROFILE points at this script"
}

wait_for_key() {  # IAM is eventually consistent; a new key is not usable the instant it exists
  local i
  for i in $(seq 1 20); do
    aws sts get-caller-identity --profile "$CONSOLE_PROFILE" >/dev/null 2>&1 && return 0
    sleep 1
  done
  return 1
}

probe() {  # every call the console makes, with the console's own profile
  local account logs ok=0 bad=0
  account="$(contract account_id)"; logs="$(contract log_bucket)"
  run() { local what="$1"; shift
    if "$@" >/dev/null 2>&1; then printf '  %-5s %s\n' ok "$what"; ok=$((ok + 1))
    else printf '  %-5s %s\n' FAIL "$what"; bad=$((bad + 1)); fi
  }
  if ! aws sts get-caller-identity --profile "$CONSOLE_PROFILE" >/dev/null 2>&1; then
    echo "  the profile $CONSOLE_PROFILE does not answer; nothing below would mean anything."
    echo "  run: tools/console-key.sh create"
    return 1
  fi
  printf '  %-5s %s\n' ok "identity"; ok=$((ok + 1))
  run "edge metrics (CloudWatch)" aws cloudwatch get-metric-statistics --namespace AWS/CloudFront --metric-name Requests \
    --dimensions "Name=DistributionId,Value=$(contract cloudfront_distribution)" Name=Region,Value=Global \
    --start-time "$(date -u -v-1d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%SZ)" \
    --end-time "$(date -u +%Y-%m-%dT%H:%M:%SZ)" --period 86400 --statistics Sum --profile "$CONSOLE_PROFILE" --region "$REGION"
  run "access-log bucket listing" aws s3api list-objects-v2 --bucket "$logs" --max-items 1 --profile "$CONSOLE_PROFILE" --region "$REGION"
  run "the brake (SSM)" aws ssm get-parameter --name "$BRAKE" --profile "$CONSOLE_PROFILE" --region "$REGION"
  run "the edge router (CloudFront)" aws cloudfront get-function --name "$FUNCTION" --stage LIVE --profile "$CONSOLE_PROFILE" --region "$REGION" /dev/null
  run "the flood alarm (CloudWatch)" aws cloudwatch describe-alarms --alarm-names helmet-duck-prod-request-flood --profile "$CONSOLE_PROFILE" --region "$REGION"
  run "mail sending state (SES)" aws sesv2 get-account --profile "$CONSOLE_PROFILE" --region "$REGION"
  # A write must fail, and it must fail because IAM refused it. A write that fails
  # because the profile is missing proves nothing, so the refusal has to say so.
  echo
  local err
  if err="$(aws s3api put-object --bucket "$(contract bucket)" --key .console-key-probe \
            --profile "$CONSOLE_PROFILE" --region "$REGION" 2>&1)"; then
    printf '  %-5s %s\n' FAIL "writing to the site bucket was NOT denied"; bad=$((bad + 1))
    aws s3api delete-object --bucket "$(contract bucket)" --key .console-key-probe --profile "$PROFILE" --region "$REGION" >/dev/null 2>&1 || true
  elif printf '%s' "$err" | grep -qi "accessdenied\|explicit deny\|not authorized"; then
    printf '  %-5s %s\n' ok "writing to the site bucket is denied by the policy"; ok=$((ok + 1))
  else
    printf '  %-5s %s\n' FAIL "the write failed for another reason, so nothing is proved: $(printf '%s' "$err" | tail -1 | cut -c1-70)"
    bad=$((bad + 1))
  fi
  echo
  echo "$ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-status}" in
  credential-process) credential_process ;;
  create)
    sign_in; ensure_user
    if aws iam list-access-keys --user-name "$IAM_USER" --profile "$PROFILE" --query 'length(AccessKeyMetadata)' --output text | grep -qv '^0$'; then
      die "$IAM_USER already has a key; use rotate, or revoke first"
    fi
    new_key; ensure_profile
    echo
    wait_for_key || die "the new key did not become usable within 20 seconds; run status to look again"
    probe || die "the key works but the policy does not cover every call the console makes"
    echo
    echo "The console now reads AWS through $CONSOLE_PROFILE, with no session to expire. Restart it:"
    echo "  helmet-duck-console-start --restart"
    ;;
  rotate)
    sign_in; ensure_user
    old="$(aws iam list-access-keys --user-name "$IAM_USER" --profile "$PROFILE" --query 'AccessKeyMetadata[].AccessKeyId' --output text)"
    new_key; ensure_profile
    wait_for_key || die "the new key did not become usable within 20 seconds; the old key is still in place"
    probe || die "the new key does not pass the probe; the old key is still in place"
    for k in $old; do aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$k" --profile "$PROFILE"; echo "deleted old key $k"; done
    ;;
  revoke)
    sign_in
    for k in $(aws iam list-access-keys --user-name "$IAM_USER" --profile "$PROFILE" --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null); do
      aws iam delete-access-key --user-name "$IAM_USER" --access-key-id "$k" --profile "$PROFILE"; echo "deleted key $k"
    done
    keychain_drop; echo "Keychain item removed. The console falls back to $PROFILE and its expiring session."
    ;;
  status)
    id="$(keychain_id)"
    echo "Keychain item ($SERVICE):   ${id:-none; run create}"
    echo "profile $CONSOLE_PROFILE:  $(aws configure get credential_process --profile "$CONSOLE_PROFILE" 2>/dev/null || echo 'not configured')"
    if aws sts get-caller-identity --profile "$PROFILE" >/dev/null 2>&1; then
      aws iam list-access-keys --user-name "$IAM_USER" --profile "$PROFILE" \
        --query 'AccessKeyMetadata[].[AccessKeyId,Status,CreateDate]' --output text 2>/dev/null || echo "IAM user $IAM_USER does not exist yet"
    else
      echo "(the admin session is expired, so the IAM side is not shown; the console does not need it)"
    fi
    echo
    [ -n "$id" ] && probe || true
    ;;
  --help|-h|help) sed -n '2,24p' "$SELF" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command: $1 (create, rotate, revoke, status)" ;;
esac
