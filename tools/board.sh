#!/usr/bin/env bash
# One standing GitHub issue per watcher, used as the alert board.
#
#   tools/board.sh "<issue title>" <exit code> <findings file> [label]
#
# Exit code 0: the laws held. An open issue with this title is closed with a
# note; otherwise nothing happens and nobody is notified.
# Any other code: the findings are posted, as a new issue or as a comment on the
# open one. The GitHub notification is the alert: no extra service, no webhook,
# no secret. Code 2 (red) also fails the workflow run so the Actions UI goes red.
#
# The board writes issues and nothing else. It never deploys and never touches
# production; a watcher with write access to production is a second way to
# break things, not a guard.
set -euo pipefail
TITLE="$1"; CODE="$2"; FILE="$3"; LABEL="${4:-watcher}"

NUM="$(gh issue list --state open --search "\"$TITLE\" in:title" --json number,title \
       --jq "[.[] | select(.title == \"$TITLE\")][0].number // empty")"

if [ "$CODE" = "0" ]; then
  if [ -n "$NUM" ]; then
    gh issue comment "$NUM" --body "Every law held again at $(date -u +%FT%TZ). Closing: the site healed."
    gh issue close "$NUM"
    echo "healed; closed #$NUM"
  else
    echo "every law held; nothing to report"
  fi
  exit 0
fi

FOOT="<sub>Raised by the scheduled watcher, run ${GITHUB_SERVER_URL:-}/${GITHUB_REPOSITORY:-}/actions/runs/${GITHUB_RUN_ID:-}. It reports only; it never deploys.</sub>"
BODY="$(cat "$FILE")"$'\n\n'"$FOOT"

if [ -n "$NUM" ]; then
  gh issue comment "$NUM" --body "$BODY"
  echo "updated #$NUM"
else
  gh issue create --title "$TITLE" --body "$BODY" --label "$LABEL" 2>/dev/null \
    || gh issue create --title "$TITLE" --body "$BODY"
  echo "opened a new issue"
fi

[ "$CODE" = "2" ] && exit 1 || exit 0
