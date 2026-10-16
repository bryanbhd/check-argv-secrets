#!/usr/bin/env bash
# Run both implementations over tests/fixtures and compare with tests/expected.txt.
#   tests/run.sh            bash script only
#   tests/run.sh --semgrep  also the semgrep rules (needs semgrep)
set -uo pipefail
cd "$(dirname "$0")/.."
want=$(grep -v '^#' tests/expected.txt | sort)
fail=0

check() {   # check NAME ACTUAL
  if [ "$2" = "$want" ]; then echo "PASS  $1 ($(wc -l <<<"$2") findings, as expected)"
  else echo "FAIL  $1"; diff <(echo "$want") <(echo "$2") | sed 's/^/      /'; fail=1; fi
}

got=$(bash check-argv-secrets.sh -q tests/fixtures 2>/dev/null \
  | sed -E 's#^tests/fixtures/([^:]+):([0-9]+): \[([a-z-]+)\].*#\1 \2 \3#' | sort)
check "check-argv-secrets.sh" "$got"

if [ "${1:-}" = "--semgrep" ]; then
  got=$(semgrep scan --config rules/argv-secrets.yaml --metrics=off --quiet --json tests/fixtures 2>/dev/null \
    | python3 -c 'import json,sys
for r in json.load(sys.stdin)["results"]:
    print(r["path"].split("fixtures/",1)[1], r["start"]["line"], r["check_id"].rsplit(".",1)[-1].removeprefix("argv-secret-"))' | sort)
  check "semgrep rules" "$got"
fi

# the safe fixtures must be clean on their own
bash check-argv-secrets.sh -q tests/fixtures/good >/dev/null 2>&1 && echo "PASS  good fixtures are clean" || { echo "FAIL  good fixtures flagged"; fail=1; }
exit $fail
