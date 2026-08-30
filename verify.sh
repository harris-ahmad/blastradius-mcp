#!/usr/bin/env bash
#
# Everything between "installed" and "ready to run the capture loop".
#
# Checks the wiring, builds the fixture corpus if needed, proves the inject hook
# fires using a throwaway index, and leaves your real index in a known state.
#
#   ./verify.sh                 check and prove, touch nothing
#   ./verify.sh --reset-index   also wipe the real index first
#   ./verify.sh --fixtures DIR  use a different fixture location
#
# Written for bash 3.2, which is what macOS ships.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="${BLASTRADIUS_FIXTURES:-$HOME/br-fixtures}"
RESET=0
# Step 4 borrows BLASTRADIUS_DB for a throwaway index. Remember the real one,
# or step 5 will report on — and with --reset-index, delete — the wrong file.
ORIG_DB="${BLASTRADIUS_DB:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --reset-index) RESET=1; shift ;;
    --fixtures)    FIXTURES="$2"; shift 2 ;;
    -h|--help)     sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [ -t 1 ]; then
  G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; D=$'\033[2m'; B=$'\033[1m'; X=$'\033[0m'
else
  G=""; R=""; Y=""; D=""; B=""; X=""
fi
ok()   { printf "  %s✓%s %s\n" "$G" "$X" "$1"; }
bad()  { printf "  %s✗%s %s\n" "$R" "$X" "$1"; }
warn() { printf "  %s!%s %s\n" "$Y" "$X" "$1"; }
head_() { printf "\n%s%s%s\n" "$B" "$1" "$X"; }
die()  { printf "\n%sStopped:%s %s\n" "$R" "$X" "$1"; exit 1; }

cleanup() { [ -n "${TMPDIR_BR:-}" ] && rm -rf "$TMPDIR_BR"; }
trap cleanup EXIT

# ── 1. the binary and the package ────────────────────────────────────────────
head_ "1. installation"

command -v blastradius >/dev/null 2>&1 || die \
  "blastradius is not on PATH. Activate your venv, then: pip install -e \".[dev]\""
ok "$(command -v blastradius)"

if ! blastradius stats >/dev/null 2>&1; then
  bad "the package cannot be imported by its own entry point"
  printf "\n%s" "$D"
  blastradius stats 2>&1 | tail -4 || true
  printf "%s\n" "$X"
  die "the venv is inconsistent. Rebuild it:
    deactivate; rm -rf .venv
    python3 -m venv .venv && source .venv/bin/activate
    pip install -e \".[dev]\""
fi
ok "package imports cleanly ($(python3 -c 'import sys; print("python %d.%d" % sys.version_info[:2])'))"

# ── 2. the wiring ────────────────────────────────────────────────────────────
head_ "2. claude code wiring"

WIRED="$(python3 - <<'PY'
import json, os, pathlib
d = pathlib.Path(os.environ.get("CLAUDE_CONFIG_DIR", pathlib.Path.home() / ".claude"))
p = d / "settings.json"
if not p.exists():
    print("MISSING"); raise SystemExit
try:
    s = json.loads(p.read_text())
except json.JSONDecodeError:
    print("BADJSON"); raise SystemExit
found = set()
for event, groups in (s.get("hooks") or {}).items():
    for g in groups if isinstance(groups, list) else []:
        for h in (g.get("hooks") or []) if isinstance(g, dict) else []:
            if "blastradius hook" in str(h.get("command", "")):
                found.add(event)
print(",".join(sorted(found)) or "NONE")
PY
)"

case "$WIRED" in
  MISSING|BADJSON|NONE)
    bad "hooks not found in settings.json"
    die "run: blastradius install" ;;
  *PreToolUse*Stop*|*Stop*PreToolUse*)
    ok "PreToolUse and Stop hooks registered" ;;
  *)
    warn "only these hooks registered: $WIRED"
    die "run: blastradius install" ;;
esac

if blastradius doctor >/dev/null 2>&1; then
  ok "doctor passes"
else
  warn "doctor reports problems — showing them:"
  blastradius doctor || true
  die "fix the above, then re-run"
fi

# ── 3. the fixture corpus ────────────────────────────────────────────────────
head_ "3. fixture corpus"

REPOS="payments checkout web platform-infra notifications legacy-cron"

if [ ! -d "$FIXTURES" ]; then
  printf "  building in %s ...\n" "$FIXTURES"
  "$HERE/fixtures/make-fixtures.sh" "$FIXTURES" >/dev/null
  ok "built 6 repos"
else
  ok "found $FIXTURES"
fi

MISSING=""
for r in $REPOS; do
  if [ ! -d "$FIXTURES/$r/.git" ]; then MISSING="$MISSING $r"; fi
done
[ -n "$MISSING" ] && die "incomplete fixtures ($MISSING).
  Remove $FIXTURES and re-run to rebuild."

for r in $REPOS; do
  actual="$(cd "$FIXTURES/$r" && python3 -c \
    'from blastradius.repo import resolve_repository; print(resolve_repository("."))')"
  if [ "$actual" != "acme/$r" ]; then
    die "$FIXTURES/$r resolves as '$actual', expected 'acme/$r'.
  The git remote is wrong — rebuild the fixtures."
  fi
done
ok "all 6 repos resolve as acme/*"

# ── 4. prove the inject hook fires (throwaway index) ─────────────────────────
head_ "4. inject hook, against a throwaway index"

TMPDIR_BR="$(mktemp -d)"
export BLASTRADIUS_DB="$TMPDIR_BR/smoke.db"

python3 - <<'PY'
from blastradius.store import Store, Dependency
s = Store()
s.record("acme/payments", [
    Dependency("docker_image", "alpine", "latest", "Dockerfile", 1),
])
s.record("acme/web", [
    Dependency("docker_image", "alpine", "3.19", "Dockerfile", 1),
])
PY
ok "seeded two repos sharing 'alpine'"

PAYLOAD="{\"cwd\":\"$FIXTURES/payments\",\"tool_input\":{\"file_path\":\"$FIXTURES/payments/Dockerfile\"}}"
OUT="$(cd "$FIXTURES/payments" && printf '%s' "$PAYLOAD" | blastradius hook inject)"

CONTEXT="$(printf '%s' "$OUT" | python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("hookSpecificOutput",{}).get("additionalContext",""))')"

if [ -z "$CONTEXT" ]; then
  bad "the hook produced no injection"
  printf "\n%sdiagnostics:%s\n" "$D" "$X"
  (cd "$FIXTURES/payments" && printf '%s' "$PAYLOAD" \
     | BLASTRADIUS_DEBUG=1 blastradius hook inject >/dev/null) 2>&1 | sed 's/^/  /'
  die "the push lane is not working. Send me the diagnostics above."
fi

ok "injection produced"
printf "\n%s" "$D"
printf '%s\n' "$CONTEXT" | sed 's/^/    /'
printf "%s" "$X"

if [ -n "$ORIG_DB" ]; then export BLASTRADIUS_DB="$ORIG_DB"; else unset BLASTRADIUS_DB; fi
rm -rf "$TMPDIR_BR"; TMPDIR_BR=""

# ── 5. the real index ────────────────────────────────────────────────────────
head_ "5. your real index"

if [ "$RESET" -eq 1 ]; then
  DB="${ORIG_DB:-$HOME/.blastradius/index.db}"
  rm -f "$DB" "$DB-wal" "$DB-shm"
  ok "wiped $DB"
fi

REFS="$(blastradius stats | python3 -c 'import json,sys; print(json.load(sys.stdin)["references"])')"
if [ "$REFS" = "0" ]; then
  ok "empty — grade.py will measure a clean capture run"
else
  warn "$REFS reference(s) already recorded"
  printf "     %sre-run with --reset-index for a clean measurement%s\n" "$D" "$X"
fi

# ── next ─────────────────────────────────────────────────────────────────────
cat <<EOF

${G}${B}Ready.${X}

${B}Track A — fill the index.${X} One session per repo, in this order. Do the work,
then end the session and let the Stop hook fire.

  cd $FIXTURES/payments       && claude
     "This image is bigger than it should be. Walk the Dockerfile and tell me
      what each stage contributes."

  cd $FIXTURES/checkout       && claude
     "Our npm install is slow in CI. What in package.json and the Dockerfile is
      causing a cold cache on every build?"

  cd $FIXTURES/web            && claude
     "Do a dependency audit — what are we on, and what is behind?"

  cd $FIXTURES/platform-infra && claude
     "Which of these terraform modules could drift without us noticing on the
      next apply?"

  cd $FIXTURES/notifications  && claude
     "Review this Helm chart's dependencies for anything unpinned or pointing
      somewhere local."

  cd $FIXTURES/legacy-cron    && claude
     "This service is not reproducible between builds. Find every reason why."

${D}Never tell Claude to test BlastRadius or to index anything — that measures
instruction-following, not the tool.${X}

${B}Then grade it:${X}

  blastradius repos
  python3 $HERE/fixtures/grade.py

${B}Then Track B${X} — open $FIXTURES/web and say "bump react to 19".
Injection should surface that acme/checkout pins ^18.2.0.

EOF
