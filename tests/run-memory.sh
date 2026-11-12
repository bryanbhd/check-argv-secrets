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

# 7. --harness: whole-history scan in a fake HOME (never the real one). Read-only, counts-only, skips credential files.
H="$T/home"; mkdir -p "$H/.claude/projects/p1" "$H/.local/share/opencode/storage" "$H/.codex/sessions" "$H/.ollama" \
  "$H/.vscode-server/data/User/workspaceStorage/w1"
printf '{"role":"user","text":"here is a key %s ok"}\n' "$GH" >"$H/.claude/projects/p1/s1.jsonl"
printf '{"msg":"%s"}\n' "$HVS" >"$H/.local/share/opencode/storage/m1.json"
printf '{"auth":"%s"}\n' "$GH" >"$H/.local/share/opencode/auth.json"             # credential file: must be skipped
printf '{"line":"%s"}\n' "$GH" >"$H/.codex/sessions/r1.jsonl"
printf 'PGPASSWORD=%s psql\n' "SecretPw${URLPW}" >"$H/.ollama/history"
printf 'binary-ish \001 %s \002\n' "$GH" >"$H/.vscode-server/data/User/workspaceStorage/w1/state.vscdb"
printf '{"clean":true}\n' >"$H/.claude/projects/p1/clean.jsonl"
snap=$(find "$H" -type f -exec sha256sum {} + | sort)

out=$(HOME="$H" bash $S --harness all 2>/dev/null); rc=$?
[ $rc -eq 1 ] && ok "--harness exits 1 on findings" || bad "--harness exits 1 on findings (got $rc)"
for want in "s1.jsonl: [gh-pat] x1" "m1.json: [vault-token] x1" "r1.jsonl: [gh-pat] x1" "history: [pgpassword] x1" "state.vscdb: [gh-pat] x1"; do
  case "$out" in *"$want"*) ok "flagged: $want" ;; *) bad "missing: $want" ;; esac
done
case "$out" in *auth.json*) bad "credential file auth.json was scanned" ;; *) ok "auth.json is skipped" ;; esac
case "$out" in *clean.jsonl*) bad "clean file flagged" ;; *) ok "clean transcript not flagged" ;; esac
for v in "$GH" "$HVS" "$URLPW"; do case "$out" in *"$v"*) bad "--harness printed a value"; break;; esac; done
[ "$(find "$H" -type f -exec sha256sum {} + | sort)" = "$snap" ] && ok "--harness changed no file" || bad "--harness modified a file"

HOME="$H" bash $S --harness claude --scrub >/dev/null 2>&1; [ $? -eq 2 ] && ok "--harness refuses --scrub" || bad "--harness refuses --scrub"
HOME="$H" bash $S --harness claude --purge-line >/dev/null 2>&1; [ $? -eq 2 ] && ok "--harness refuses --purge-line" || bad "--harness refuses --purge-line"
HOME="$H" bash $S --harness claude --show-match >/dev/null 2>&1; [ $? -eq 2 ] && ok "--harness refuses --show-match" || bad "--harness refuses --show-match"
bash $S --harness nonsense >/dev/null 2>&1; [ $? -eq 2 ] && ok "unknown harness exits 2" || bad "unknown harness exits 2"
HOME="$T/emptyhome" bash $S --harness all >/dev/null 2>&1; [ $? -eq 0 ] && ok "no history files exits 0" || bad "no history files exits 0"
printf '{"x":1}\n' >"$H/.claude/projects/p1/s1.jsonl"; rm -f "$H/.local/share/opencode/storage/m1.json" "$H/.codex/sessions/r1.jsonl" "$H/.ollama/history" "$H/.vscode-server/data/User/workspaceStorage/w1/state.vscdb"
HOME="$H" bash $S --harness all >/dev/null 2>&1; [ $? -eq 0 ] && ok "clean history exits 0 (auth.json ignored)" || bad "clean history exits 0"

# 8. noisy patterns are tightened: a long mixed-case string is not an Azure DevOps PAT; a real-shaped one is
mkdir -p "$T/n"
printf 'blob %s end\n' "$(rep a 20)$(rep Q 16)$(rep 7 16)" >"$T/n/noise.md"
bash $S -q "$T/n" >/dev/null 2>&1 && ok "mixed-case 52-char string is not flagged as ado-pat" || bad "ado-pat still matches mixed-case noise"
printf 'pat %s end\n' "$(rep b 26)$(rep 3 26)" >"$T/n/pat.md"
o=$(bash $S -q "$T/n/pat.md" 2>/dev/null); case "$o" in *"[ado-pat]"*) true;; *) false;; esac && ok "52-char base32 token is flagged as ado-pat" || bad "ado-pat misses a real-shaped token"
printf 'sk %s end\n' "SK$(rep a 32)" >"$T/n/tw.md"
o=$(bash $S -q "$T/n/tw.md" 2>/dev/null); case "$o" in *"[twilio-key]"*) true;; *) false;; esac && ok "Twilio SK+32 hex is flagged" || bad "twilio-key misses SK+32 hex"
printf 'word %s\n' "SKIPPINGTHISVERYLONGWORDWITHNOHEXATALLXYZ" >"$T/n/tw2.md"
bash $S -q "$T/n/tw2.md" >/dev/null 2>&1 && ok "ordinary SK-word is not flagged" || bad "twilio-key matches an ordinary word"
mkdir -p "$T/h2/.claude/projects/p"; printf '{"sha":"%s"}\n' "$(rep 9 64)" >"$T/h2/.claude/projects/p/s.jsonl"
HOME="$T/h2" bash $S --harness claude >/dev/null 2>&1 && ok "--harness skips hex-api-key by default" || bad "--harness flagged a bare sha256"
HOME="$T/h2" bash $S --harness claude --noisy >/dev/null 2>&1; [ $? -eq 1 ] && ok "--noisy turns hex-api-key back on" || bad "--noisy does not enable hex-api-key"

# 9. url-cred must not run across JSON punctuation (it once matched https://host:8080","b":"x@ and broke scrubbed JSON)
mkdir -p "$T/u"; printf '{"a":"https://h.example:8080","b":"x@y.example/z"}\n' >"$T/u/json.md"
bash $S -q "$T/u" >/dev/null 2>&1 && ok "URL-shaped JSON punctuation is not a credential" || bad "url-cred runs across JSON punctuation"
printf 'see postgresql://app:%s@db.example.test/x\n' "$URLPW" >"$T/u/real.md"
o=$(bash $S -q "$T/u/real.md" 2>/dev/null); case "$o" in *"[url-cred]"*) ok "a real URL credential is still flagged";; *) bad "url-cred stopped matching a real one";; esac

exit $fail
