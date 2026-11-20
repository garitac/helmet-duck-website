#!/usr/bin/env bash
# The edge blocklist, from the owner's terminal.
#
#   tools/blocklist.sh status    the addresses currently refused at the edge, and until when
#   tools/blocklist.sh clear     empty the list and publish the edge function
#   tools/blocklist.sh test      run offline policy and retry regression tests
#
# The keeper combines request timestamps across log files in free Standard
# parameters; more than 50 in five minutes triggers a temporary block.
# test is entirely offline. clear pauses the keeper, waits for its maximum
# invocation duration, clears its state and the edge list, then resumes it.
set -euo pipefail
if [ "${1:-status}" = test ]; then
  exec python3 "$(dirname "$0")/test_keeper.py"
fi

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
STACK=helmet-duck-frontend-prod
cd "$(dirname "$0")/.."

sign_in
out() { aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" --output text; }
FN="$(out EdgeFunctionName)"; FN="${FN##*/}"          # the API wants the name; tolerate an ARN
TMP="$(mktemp -d)"
PAUSED=""; ORIGINAL_LIMIT=""
cleanup() {
  if [ -n "$PAUSED" ]; then
    if [ "$ORIGINAL_LIMIT" = None ]; then
      aws lambda delete-function-concurrency --function-name "$KEEPER" --region "$REGION" --profile "$PROFILE" >/dev/null
    else
      aws lambda put-function-concurrency --function-name "$KEEPER" --reserved-concurrent-executions "$ORIGINAL_LIMIT" --region "$REGION" --profile "$PROFILE" >/dev/null
    fi
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

fetch() {  # the DEVELOPMENT stage holds the latest code; prints the ETag
  aws cloudfront get-function --name "$FN" --stage DEVELOPMENT --profile "$PROFILE" "$TMP/fn.js" --query ETag --output text
}
show() {
  python3 - "$TMP/fn.js" <<'PY'
import json, re, sys, time
code = open(sys.argv[1]).read()
listed = json.loads(re.search(r"/\*BLOCKLIST\*/(.*?)/\*END\*/", code, re.S).group(1) or "{}")
now = time.time()
if not listed:
    print("blocklist: empty")
for ip, until in sorted(listed.items(), key=lambda kv: kv[1]):
    left = (until - now) / 60
    print("  %-40s %s" % (ip, "refused for %d more minute(s)" % left if left > 0 else "expired, forgotten within a day"))
PY
}

case "${1:-status}" in
  status)
    fetch >/dev/null; show ;;
  clear)
    KEEPER="$(out KeeperFunctionName)"
    ORIGINAL_LIMIT="$(aws lambda get-function-concurrency --function-name "$KEEPER" --region "$REGION" --profile "$PROFILE" --query ReservedConcurrentExecutions --output text)"
    MAX_WAIT="$(aws lambda get-function-configuration --function-name "$KEEPER" --region "$REGION" --profile "$PROFILE" --query Timeout --output text)"
    aws lambda put-function-concurrency --function-name "$KEEPER" --reserved-concurrent-executions 0 --region "$REGION" --profile "$PROFILE" >/dev/null
    PAUSED=1
    echo "keeper paused; waiting up to $MAX_WAIT seconds for an in-flight invocation"
    for (( i=0; i<MAX_WAIT; i++ )); do sleep 1; done
    for i in {0..7}; do
      aws ssm put-parameter --name "/helmet-duck/prod/keeper/state/$i" --type String --tier Standard --value '{}' --overwrite --region "$REGION" --profile "$PROFILE" >/dev/null
    done
    ETAG="$(fetch)"
    python3 - "$TMP/fn.js" <<'PY'
import re, sys
p = sys.argv[1]; code = open(p).read()
code = re.sub(r"^/\*KEEPER_LOCK:.*?\*/\n", "", code, flags=re.S)
open(p, "w").write(re.sub(r"/\*BLOCKLIST\*/.*?/\*END\*/", "/*BLOCKLIST*/{}/*END*/", code, flags=re.S))
PY
    CFG="$(aws cloudfront describe-function --name "$FN" --stage DEVELOPMENT --profile "$PROFILE" --query FunctionSummary.FunctionConfig --output json)"
    NEW="$(aws cloudfront update-function --name "$FN" --if-match "$ETAG" --function-config "$CFG" --function-code "fileb://$TMP/fn.js" --profile "$PROFILE" --query ETag --output text)"
    aws cloudfront publish-function --name "$FN" --if-match "$NEW" --profile "$PROFILE" >/dev/null
    echo "blocklist cleared and published; live at every edge within a minute" ;;
  *)
    echo "usage: tools/blocklist.sh status|clear|test"; exit 2 ;;
esac
