#!/usr/bin/env bash
#
# Run the Track A capture sessions headlessly, one per fixture repo.
#
#   ./run-capture.sh                 all six, in order
#   ./run-capture.sh payments web    only these
#   ./run-capture.sh --reset         wipe the index first
#
# Each session is a plausible engineering request that happens to require
# reading the manifests. None of them mention BlastRadius — telling Claude to
# index something measures instruction-following, not the tool.
#
# Sessions are read-only: Write, Edit and Bash are denied, so the fixture repos
# stay in the exact state grade.py expects.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="${BLASTRADIUS_FIXTURES:-$HOME/br-fixtures}"
RESET=0
WANTED=""

while [ $# -gt 0 ]; do
  case "$1" in
    --reset)    RESET=1; shift ;;
    --fixtures) FIXTURES="$2"; shift 2 ;;
    -h|--help)  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*)         echo "unknown option: $1" >&2; exit 2 ;;
    *)          WANTED="$WANTED $1"; shift ;;
  esac
done

if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; X=$'\033[0m'
else
  G=""; R=""; Y=""; D=""; B=""; X=""
fi

if ! command -v blastradius >/dev/null 2>&1; then
  [ -x "$HERE/.venv/bin/blastradius" ] && PATH="$HERE/.venv/bin:$PATH" && export PATH
fi
command -v blastradius >/dev/null 2>&1 || { echo "blastradius not found — run ./verify.sh"; exit 1; }
command -v claude      >/dev/null 2>&1 || { echo "claude not found on PATH"; exit 1; }

prompt_for() {
  case "$1" in
    payments)       echo "This image is bigger than it should be. Walk the Dockerfile and tell me what each stage contributes." ;;
    checkout)       echo "Our npm install is slow in CI. What in package.json and the Dockerfile is causing a cold cache on every build?" ;;
    web)            echo "Do a dependency audit of this repo — what are we on, and what is behind?" ;;
    platform-infra) echo "Which of these terraform modules could drift without us noticing on the next apply?" ;;
    notifications)  echo "Review this Helm chart's dependencies for anything unpinned or pointing somewhere local." ;;
    legacy-cron)    echo "This service is not reproducible between builds. Find every reason why." ;;
    *) return 1 ;;
  esac
}

REPOS="${WANTED:-payments checkout web platform-infra notifications legacy-cron}"

if [ "$RESET" -eq 1 ]; then
  DB="${BLASTRADIUS_DB:-$HOME/.blastradius/index.db}"
  rm -f "$DB" "$DB-wal" "$DB-shm"
  printf "%s✓%s wiped %s\n\n" "$G" "$X" "$DB"
fi

ALLOW="Read,Glob,Grep,mcp__blastradius__record_dependencies,mcp__blastradius__blast_radius,mcp__blastradius__hygiene"
DENY="Write,Edit,NotebookEdit,Bash"

# The index count, or empty if the CLI is not working. Never a raw traceback.
refs() {
  blastradius stats 2>/dev/null \
    | python3 -c 'import json,sys
try:
    print(json.load(sys.stdin)["references"])
except Exception:
    pass' 2>/dev/null
}

require_cli() {
  if [ -z "$(refs)" ]; then
    printf "\n%s✗%s %s is not working\n\n" "$R" "$X" "$(command -v blastradius)"
    blastradius stats 2>&1 | sed 's/^/    /' | tail -4
    cat <<EOF

${B}The environment is broken, not the tool.${X} An editable install can lose its
link to the package; a plain install cannot. You are testing, not developing
the package, so use one:

    pip install .          ${D}# not -e${X}

Then re-point the hooks at it and continue:

    blastradius install
    blastradius doctor
    ./run-capture.sh${WANTED:+$WANTED}

EOF
    exit 1
  fi
}

require_cli

# A non-editable install does not follow `git pull`. Catch it before six
# sessions run against yesterday's code.
if blastradius doctor 2>/dev/null | grep -q "OLDER than the source"; then
  printf "\n%s✗%s the installed package is older than this checkout\n" "$R" "$X"
  printf "    %sa plain install does not follow git pull%s\n\n" "$D" "$X"
  printf "    run: pip install .\n\n"
  exit 1
fi

START_REFS="$(refs)"

for repo in $REPOS; do
  dir="$FIXTURES/$repo"
  if [ ! -d "$dir/.git" ]; then
    printf "%s✗%s %s is not a fixture repo — skipping\n" "$R" "$X" "$dir"
    continue
  fi
  prompt="$(prompt_for "$repo")" || { printf "%s✗%s no prompt for %s\n" "$R" "$X" "$repo"; continue; }

  printf "%s%s──  %s%s\n" "$B" "$G" "$repo" "$X"
  printf "%s    \"%s\"%s\n" "$D" "$prompt" "$X"

  require_cli
  before="$(refs)"

  if ( cd "$dir" && claude -p "$prompt" \
        --allowedTools "$ALLOW" \
        --disallowedTools "$DENY" \
        --permission-mode dontAsk \
        >/dev/null 2>"$dir/.br-session.log" ); then
    after="$(refs)"
    if [ -z "$after" ]; then
      printf "    %s✗%s the CLI stopped working during this session\n" "$R" "$X"
      require_cli
    fi
    gained=$(( after - before ))
    if [ "$gained" -gt 0 ]; then
      printf "    %s✓%s recorded %s reference(s)\n\n" "$G" "$X" "$gained"
    elif [ -n "$(blastradius repos 2>/dev/null | grep " acme/$repo\$")" ]; then
      # Already fully indexed — the Stop hook correctly has nothing to ask for.
      printf "    %s✓%s already indexed, nothing new\n\n" "$G" "$X"
    else
      printf "    %s!%s session finished but nothing was recorded\n" "$Y" "$X"
      printf "      %ssee %s/.br-session.log%s\n\n" "$D" "$dir" "$X"
    fi
  else
    printf "    %s✗%s session failed — see %s/.br-session.log\n\n" "$R" "$X" "$dir"
  fi
done

END_REFS="$(refs)"
printf "%s%s references recorded this run: %s%s\n\n" "$B" "$G" "$(( END_REFS - START_REFS ))" "$X"

blastradius repos
printf "\n"
python3 "$HERE/fixtures/grade.py" || true
