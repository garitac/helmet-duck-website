#!/usr/bin/env bash
# The brake, from the owner's terminal.
#
#   tools/brake.sh status     what the brake knows and whether the distribution is enabled
#   tools/brake.sh release    enable the distribution now and clear the wait
#   tools/brake.sh off        the brake does nothing until switched on again
#   tools/brake.sh on         the brake acts again
#
# The brake itself lives in infra/frontend.yaml: when the request-flood alarm fires
# it disables the distribution for an hour, twice as long on each repeat up to a
# day, and a scheduled tick re-enables it. It bounds the bill; it cannot keep the
# site up. This script is the hand on it.
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
PARAM=/helmet-duck/prod/brake
STACK=helmet-duck-frontend-prod
cd "$(dirname "$0")/.."

sign_in
DIST="$(aws cloudformation describe-stacks --stack-name "$STACK" --region "$REGION" --profile "$PROFILE" \
        --query "Stacks[0].Outputs[?OutputKey=='DistributionId'].OutputValue | [0]" --output text)"
state() { aws ssm get-parameter --name "$PARAM" --region "$REGION" --profile "$PROFILE" --query Parameter.Value --output text 2>/dev/null || echo '{}'; }
enabled() { aws cloudfront get-distribution-config --id "$DIST" --profile "$PROFILE" --query DistributionConfig.Enabled --output text; }
put() { aws ssm put-parameter --name "$PARAM" --type String --overwrite --value "$1" --region "$REGION" --profile "$PROFILE" >/dev/null; }

case "${1:-status}" in
  status)
    echo "distribution $DIST enabled: $(enabled)"
    echo "brake state: $(state)"
    ;;
  release)
    put "$(state | python3 -c 'import json,sys; s=json.load(sys.stdin); s["until"]=0; print(json.dumps(s))')"
    if [ "$(enabled)" = "False" ]; then
      ETAG="$(aws cloudfront get-distribution-config --id "$DIST" --profile "$PROFILE" --query ETag --output text)"
      aws cloudfront get-distribution-config --id "$DIST" --profile "$PROFILE" --query DistributionConfig --output json \
        | python3 -c 'import json,sys; c=json.load(sys.stdin); c["Enabled"]=True; print(json.dumps(c))' > /tmp/helmet-duck-dist.json
      aws cloudfront update-distribution --id "$DIST" --if-match "$ETAG" --distribution-config file:///tmp/helmet-duck-dist.json --profile "$PROFILE" >/dev/null
      rm -f /tmp/helmet-duck-dist.json
      echo "distribution $DIST enabled again; it takes a few minutes to deploy"
    else
      echo "distribution already enabled; wait cleared"
    fi
    ;;
  off)
    put "$(state | python3 -c 'import json,sys; s=json.load(sys.stdin); s["off"]=True; print(json.dumps(s))')"
    echo "brake off: the alarm still mails you, nothing is disabled automatically"
    ;;
  on)
    put "$(state | python3 -c 'import json,sys; s=json.load(sys.stdin); s.pop("off", None); print(json.dumps(s))')"
    echo "brake on"
    ;;
  *)
    echo "usage: tools/brake.sh status|release|off|on"; exit 2 ;;
esac
