#!/usr/bin/env bash
# Tests for check-memory-secrets.sh. The fake secrets are assembled here at run time from fragments, so no
# secret-shaped string is committed to the repo (and secret scanners stay quiet about the test suite).
#   tests/run-memory.sh
set -uo pipefail
cd "$(dirname "$0")/.."
S=./check-memory-secrets.sh
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
ok()  { echo "PASS  $1"; }
bad() { echo "FAIL  $1"; fail=1; }
rep() { printf '%*s' "$2" '' | tr ' ' "$1"; }          # rep CHAR COUNT

GH="ghp_$(rep A 36)"
URLPW="Hunter2$(rep x 6)"
HVS="hvs.$(rep B 24)"

mkdir -p "$T/mem" "$T/clean"
cat >"$T/mem/notes.md" <<EOF
---
name: notes
---
keep this first line
token is $GH for the repo
connect with postgresql://app:${URLPW}@db.example.test/app
vault token $HVS
keep this last line
EOF
printf -- '---\nname: clean\n---\nsecrets live in Vault; use a token from the loader.\n' >"$T/clean/clean.md"

# 1. default output names the finding but never prints the value
out=$(bash $S -q "$T/mem" 2>/dev/null); rc=$?
[ $rc -eq 1 ] && ok "findings exit 1" || bad "findings exit 1 (got $rc)"
for v in "$GH" "$URLPW" "$HVS"; do
  case "$out" in *"$v"*) bad "default output leaked a value"; break;; esac
done
case "$out" in *"[gh-pat]"*"[url-cred]"*|*"[url-cred]"*"[gh-pat]"*) ok "default output names pattern ids" ;; *) bad "default output missing pattern ids";; esac
echo "$out" | grep -qE '^.*notes\.md:[0-9]+: \[[a-z-]+\]$' && ok "finding format is file:line: [id]" || bad "finding format"

# 2. --show-match is opt-in and does print the match
out=$(bash $S -q --show-match "$T/mem" 2>/dev/null)
case "$out" in *"$GH"*) ok "--show-match prints the match" ;; *) bad "--show-match prints the match";; esac

# 3. clean file passes
bash $S -q "$T/clean" >/dev/null 2>&1 && ok "clean file exits 0" || bad "clean file exits 0"

# 4. --scrub --dry-run changes nothing; --scrub removes the values and keeps a backup
before=$(sha256sum "$T/mem/notes.md")
bash $S -q --scrub --dry-run "$T/mem" >/dev/null 2>&1
[ "$(sha256sum "$T/mem/notes.md")" = "$before" ] && ok "--dry-run leaves the file untouched" || bad "--dry-run modified the file"
bash $S -q --scrub "$T/mem" >/dev/null 2>&1
grep -qF "$GH" "$T/mem/notes.md" && bad "--scrub left the token" || ok "--scrub removed the token"
grep -q "REDACTED" "$T/mem/notes.md" && ok "--scrub marks the place" || bad "--scrub marker missing"
ls "$T/mem"/notes.md.bak-* >/dev/null 2>&1 && ok "--scrub wrote a backup" || bad "--scrub backup missing"

# 5. --purge-line deletes only the flagged lines and keeps a backup of the original
rm -f "$T/mem"/notes.md.bak-*
cat >"$T/mem/notes.md" <<EOF
keep this first line
token is $GH for the repo
keep this last line
keep this last line
EOF
bash $S -q --purge-line "$T/mem" >/dev/null 2>&1
[ -f "$T/mem/notes.md" ] && ok "--purge-line leaves the file in place" || bad "--purge-line lost the file"
if [ -f "$T/mem/notes.md" ]; then
  [ "$(wc -l <"$T/mem/notes.md")" -eq 3 ] && ok "--purge-line removed exactly one line" || bad "--purge-line line count"
  grep -qF "$GH" "$T/mem/notes.md" && bad "--purge-line left the token" || ok "--purge-line removed the token line"
fi
bak=$(ls "$T/mem"/notes.md.bak-* 2>/dev/null | head -1)
[ -n "$bak" ] && grep -qF "$GH" "$bak" && ok "--purge-line backup holds the original" || bad "--purge-line backup"

# 6. usage error
bash $S --no-such-flag >/dev/null 2>&1; [ $? -eq 2 ] && ok "unknown flag exits 2" || bad "unknown flag exits 2"

exit $fail
