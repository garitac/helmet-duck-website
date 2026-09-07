#!/usr/bin/env bash
set -euo pipefail
umask 077

# Helmet Duck Console lifecycle launcher. Install on the PATH once with:
#   ln -sf "$PWD/helmet-duck-console-start.command" "$HOME/.local/bin/helmet-duck-console-start"
#
# Runs the private, read-only console on 127.0.0.1 as a per-user launchd job on
# macOS (a detached process elsewhere), opens the browser, and proves the running
# process's identity and repository revision before reusing or stopping it. It
# never deploys, changes AWS or writes to the site.

SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  SOURCE_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  TARGET="$(readlink "$SOURCE")"
  case "$TARGET" in /*) SOURCE="$TARGET" ;; *) SOURCE="$SOURCE_DIR/$TARGET" ;; esac
done
REPO_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
DATA_DIR="$REPO_DIR/.console-cache/launcher"

ACTION=start
OPEN_BROWSER=true
PORT="${HELMET_DUCK_CONSOLE_PORT:-4318}"
PROFILE="${HELMET_DUCK_ADMIN_PROFILE:-kanjishisho-bootstrap-admin}"
NAME="Helmet Duck Console"

usage() {
  cat <<'EOF'
usage: helmet-duck-console-start [port] [--no-open|--status|--stop|--restart|--help]
                                 [--profile AWS_PROFILE]

Runs the private, read-only Helmet Duck console on 127.0.0.1 (default port 4318).
The launcher proves process identity and repository revision before reusing or
stopping a listener. Use --restart after updating the repository.
EOF
}

die() { echo "helmet-duck-console-start: $*" >&2; exit 1; }

while [ "$#" -gt 0 ]; do
  case "$1" in
    --no-open) OPEN_BROWSER=false ;;
    --status) ACTION=status; OPEN_BROWSER=false ;;
    --stop) ACTION=stop; OPEN_BROWSER=false ;;
    --restart) ACTION=restart ;;
    --profile) shift; [ "$#" -gt 0 ] || die "--profile requires a value"; PROFILE="$1" ;;
    --help|-h) usage; exit 0 ;;
    *[!0-9]*|'') die "unknown argument: $1" ;;
    *) PORT="$1" ;;
  esac
  shift
done
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || die "port must be between 1024 and 65535"

for c in curl git lsof python3 ps; do
  command -v "$c" >/dev/null 2>&1 || die "required system command is missing: $c"
done
AWS_BIN="$(command -v aws || true)"; [ -n "$AWS_BIN" ] || die "the AWS CLI is required"
GH_BIN="$(command -v gh || true)"; [ -n "$GH_BIN" ] || die "the GitHub CLI (gh) is required"
PY_BIN="$(command -v python3)"

mkdir -p "$DATA_DIR"; chmod 0700 "$DATA_DIR"
URL="http://127.0.0.1:$PORT"
PID_FILE="$DATA_DIR/console-$PORT.pid"
LOG_FILE="$DATA_DIR/console-$PORT.log"
EXPECTED_REVISION="$(git -C "$REPO_DIR" rev-parse HEAD 2>/dev/null)" || die "could not read the repository revision"
PLATFORM="$(uname -s)"
LABEL="com.helmetduck.console.$PORT"
[ "$PLATFORM" != Darwin ] || command -v launchctl >/dev/null 2>&1 || die "launchctl is required on macOS"

api_response() { curl -fsS --connect-timeout 1 --max-time 4 -H "Host: 127.0.0.1:$PORT" "$URL/api/ping" 2>/dev/null; }
api_is_console() { local r; r="$(api_response)" || return 1; [[ "$r" == *'"ok": true'* && "$r" == *"\"name\": \"$NAME\""* ]]; }
api_ready() { local r; r="$(api_response)" || return 1; [[ "$r" == *"\"name\": \"$NAME\""* && "$r" == *"\"revision\": \"$EXPECTED_REVISION\""* ]]; }
listener_pid() { local v; v="$(lsof -nP -tiTCP:"$PORT" -sTCP:LISTEN 2>/dev/null || true)"; [[ "$v" =~ ^[0-9]+$ ]] || return 1; printf '%s\n' "$v"; }
command_is_console() { local cmd; cmd="$(ps -p "$1" -o command= 2>/dev/null)" || return 1; [[ "$cmd" == *"tools/console/server.py"* ]]; }
is_console_pid() {
  local pid="$1" l
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  l="$(listener_pid)" || return 1
  [ "$l" = "$pid" ] || return 1
  command_is_console "$pid" || return 1
  api_is_console
}
managed_pid() {
  local pid
  [ ! -L "$PID_FILE" ] || return 2
  [ -e "$PID_FILE" ] || return 1
  pid="$(tr -dc '0-9' <"$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 2
  is_console_pid "$pid" || return 2
  printf '%s\n' "$pid"
}
clear_demonstrably_stale_pid() {
  local pid
  [ -f "$PID_FILE" ] && [ ! -L "$PID_FILE" ] || return 1
  pid="$(tr -dc '0-9' <"$PID_FILE")"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null && return 1
  listener_pid >/dev/null 2>&1 && return 1
  rm -f "$PID_FILE"
}
write_pid() { local t="$PID_FILE.tmp.$$"; [ ! -L "$PID_FILE" ] || die "refusing linked PID state"; printf '%s\n' "$1" >"$t"; mv "$t" "$PID_FILE"; }
supervisor_job_exists() { [ "$PLATFORM" = Darwin ] || return 1; launchctl list "$LABEL" >/dev/null 2>&1; }
remove_supervisor_job() { supervisor_job_exists || return 0; launchctl remove "$LABEL"; }
open_console() { $OPEN_BROWSER || return 0; if command -v open >/dev/null 2>&1; then open "$URL"; else echo "Open $URL in a browser."; fi; }

show_status() {
  local pid
  if pid="$(listener_pid)" && is_console_pid "$pid"; then
    if api_ready; then echo "$NAME is ready on $URL (pid $pid, revision ${EXPECTED_REVISION:0:12})"; return 0; fi
    echo "$NAME on $URL is running older or unidentified code; use --restart" >&2; return 1
  fi
  echo "$NAME is not ready on $URL"; return 1
}

stop_local() {
  local pid="" ownership=0
  if pid="$(managed_pid)"; then ownership=0; else ownership=$?; fi
  if [ "$ownership" -eq 2 ]; then
    if clear_demonstrably_stale_pid; then ownership=1
    elif pid="$(listener_pid)" && is_console_pid "$pid"; then ownership=0
    else die "launcher PID state cannot safely identify a $NAME process"; fi
  fi
  if [ "$ownership" -eq 1 ]; then
    if pid="$(listener_pid)"; then is_console_pid "$pid" || die "port $PORT is held by another process; refusing to stop it"
    else remove_supervisor_job; rm -f "$PID_FILE"; echo "$NAME is already stopped on $URL"; return 0; fi
  fi
  if supervisor_job_exists; then remove_supervisor_job; else kill "$pid"; fi
  for _ in $(seq 1 40); do listener_pid >/dev/null 2>&1 || break; sleep 0.1; done
  listener_pid >/dev/null 2>&1 && die "$NAME process $pid did not release port $PORT"
  rm -f "$PID_FILE"
  echo "Stopped $NAME on $URL"
}

start_local() {
  local pid
  if pid="$(listener_pid)"; then
    is_console_pid "$pid" || die "port $PORT is held by another process; refusing to replace it"
    if api_ready; then write_pid "$pid"; echo "$NAME is already ready on $URL (pid $pid, revision ${EXPECTED_REVISION:0:12})"; open_console; return 0; fi
    die "$NAME on $URL is running older code; use --restart"
  fi
  if [ -e "$PID_FILE" ] && ! clear_demonstrably_stale_pid; then die "launcher PID state cannot safely identify a managed process"; fi
  remove_supervisor_job
  local env_args=(HOME="$HOME" PATH="$PATH" HELMET_DUCK_ADMIN_PROFILE="$PROFILE" HELMET_DUCK_AWS_BIN="$AWS_BIN"
                  HELMET_DUCK_GH_BIN="$GH_BIN" HELMET_DUCK_CONSOLE_REVISION="$EXPECTED_REVISION")
  if [ "$PLATFORM" = Darwin ]; then
    launchctl submit -l "$LABEL" -o "$LOG_FILE" -e "$LOG_FILE" -- \
      /usr/bin/env "${env_args[@]}" "$PY_BIN" "$REPO_DIR/tools/console/server.py" --port "$PORT" --no-open
    pid=""
  else
    ( cd "$REPO_DIR"; nohup env "${env_args[@]}" "$PY_BIN" tools/console/server.py --port "$PORT" --no-open >>"$LOG_FILE" 2>&1 </dev/null & write_pid "$!" )
    pid="$(tr -dc '0-9' <"$PID_FILE")"
  fi
  for _ in $(seq 1 50); do
    if api_ready; then
      pid="$(listener_pid)" || true
      if [ -n "$pid" ] && is_console_pid "$pid"; then
        write_pid "$pid"; echo "$NAME is ready on $URL (pid $pid, revision ${EXPECTED_REVISION:0:12})"; open_console; return 0
      fi
    fi
    if [ -n "$pid" ] && ! kill -0 "$pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  if [ -s "$LOG_FILE" ]; then
    echo "$NAME failed to become ready; recent log output:" >&2
    tail -40 "$LOG_FILE" >&2 || true
  elif [ "$PLATFORM" = Darwin ]; then
    echo "$NAME failed to become ready and the job wrote no log: launchd did not start it." >&2
    echo "Run this command from a normal Terminal window (not from a sandboxed tool), then: launchctl list | grep helmetduck" >&2
  else
    echo "$NAME failed to become ready and wrote no log." >&2
  fi
  remove_supervisor_job
  if [ -n "$pid" ] && is_console_pid "$pid"; then kill "$pid"; fi
  rm -f "$PID_FILE"
  die "startup failed"
}

case "$ACTION" in
  status) show_status ;;
  stop) stop_local ;;
  restart) stop_local; start_local ;;
  start) start_local ;;
esac
