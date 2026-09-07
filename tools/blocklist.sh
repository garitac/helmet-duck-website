#!/usr/bin/env bash
# The edge blocklist, from the owner's terminal.
#
#   tools/blocklist.sh status    the addresses currently refused at the edge, and until when
#   tools/blocklist.sh clear     empty the list and publish the edge function
#   tools/blocklist.sh test      prove the path end to end with a documentation address
#
# The list lives inside the edge function's code (infra/frontend.yaml), between
# the markers /*BLOCKLIST*/ and /*END*/, written by the keeper function each time
# a log file shows an address at or above BlockAt requests. `test` uploads a
# synthetic log file in which 192.0.2.1 (reserved for documentation, never routed)
# makes 700 requests, waits for the keeper, shows the list, then clears it.
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
STACK=helmet-duck-frontend-prod
cd "$(dirname "$0")/.."

sign_in
out() { aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue | [0]" --output text; }
FN="$(out EdgeFunctionName)"; FN="${FN##*/}"          # the API wants the name; tolerate an ARN
LOGS="$(out LogBucketName)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

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
    ETAG="$(fetch)"
    python3 - "$TMP/fn.js" <<'PY'
import re, sys
p = sys.argv[1]; code = open(p).read()
open(p, "w").write(re.sub(r"/\*BLOCKLIST\*/.*?/\*END\*/", "/*BLOCKLIST*/{}/*END*/", code, flags=re.S))
PY
    CFG="$(aws cloudfront describe-function --name "$FN" --stage DEVELOPMENT --profile "$PROFILE" --query FunctionSummary.FunctionConfig --output json)"
    NEW="$(aws cloudfront update-function --name "$FN" --if-match "$ETAG" --function-config "$CFG" --function-code "fileb://$TMP/fn.js" --profile "$PROFILE" --query ETag --output text)"
    aws cloudfront publish-function --name "$FN" --if-match "$NEW" --profile "$PROFILE" >/dev/null
    echo "blocklist cleared and published; live at every edge within a minute" ;;
  test)
    python3 - "$TMP/selftest.gz" <<'PY'
import gzip, sys, time
fields = "date time x-edge-location sc-bytes c-ip cs-method cs(Host) cs-uri-stem sc-status".split()
t = time.gmtime()
rows = ["\t".join([time.strftime("%Y-%m-%d", t), time.strftime("%H:%M:%S", t), "SELF", "0", "192.0.2.1", "GET", "helmetduck.com", "/", "200"])] * 700
open(sys.argv[1], "wb").write(gzip.compress(("#Version: 1.0\n#Fields: " + " ".join(fields) + "\n" + "\n".join(rows) + "\n").encode()))
PY
    for old in $(aws s3 ls "s3://$LOGS/cloudfront/" --profile "$PROFILE" | awk '/selftest\./ {print $4}'); do
      aws s3 rm "s3://$LOGS/cloudfront/$old" --profile "$PROFILE" --only-show-errors   # a file left by an earlier interrupted test
    done
    KEY="cloudfront/selftest.$(date -u +%Y%m%d-%H%M%S).gz"
    aws s3 cp "$TMP/selftest.gz" "s3://$LOGS/$KEY" --profile "$PROFILE" --only-show-errors
    echo "uploaded a synthetic log file: 700 requests from 192.0.2.1; waiting for the keeper"
    for i in $(seq 1 12); do
      sleep 10; fetch >/dev/null
      if grep -q '192.0.2.1' "$TMP/fn.js"; then echo "listed after about $((i * 10)) seconds:"; show; break; fi
      [ "$i" = 12 ] && { echo "not listed after two minutes; read the keeper's log in CloudWatch"; exit 1; }
    done
    aws s3 rm "s3://$LOGS/$KEY" --profile "$PROFILE" --only-show-errors
    "$0" clear ;;
  *)
    echo "usage: tools/blocklist.sh status|clear|test"; exit 2 ;;
esac
