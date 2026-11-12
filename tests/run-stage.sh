#!/usr/bin/env bash
# Tests for stage-harness-scrub.py in a fake HOME. Fake secrets are assembled at run time, never committed.
#   tests/run-stage.sh
set -uo pipefail
cd "$(dirname "$0")/.."
S=./check-memory-secrets.sh; ST=./stage-harness-scrub.py
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0; ok(){ echo "PASS  $1"; }; bad(){ echo "FAIL  $1"; fail=1; }
rep(){ printf '%*s' "$2" '' | tr ' ' "$1"; }
GH="ghp_$(rep A 36)"; HVS="hvs.$(rep B 24)"; PW="Hunter2$(rep x 6)"; KEYBODY="$(rep Q 40)"; KT="PRIVATE"; KT="$KT KEY"   # built at run time: no key block in the source

H="$T/home"; mkdir -p "$H/.claude/projects/p" "$H/.local/share/opencode/storage" "$H/.codex/sessions"
printf '{"t":"key %s and vault %s"}\n{"t":"db postgresql://app:%s@db.example.test/x"}\n{"t":"fine"}\n' "$GH" "$HVS" "$PW" >"$H/.claude/projects/p/a.jsonl"
printf '{"k":"-----BEGIN OPENSSH %s-----\\n%s\\n%s\\n-----END OPENSSH %s-----\\n"}\n' "$KT" "$KEYBODY" "$KEYBODY" "$KT" >"$H/.local/share/opencode/storage/k.json"
printf '{"k2":"clipped -----BEGIN OPENSSH %s-----\\n%s\\n%s"}\n' "$KT" "$KEYBODY" "$KEYBODY" >>"$H/.local/share/opencode/storage/k.json"
printf '{"clean":true}\n' >"$H/.codex/sessions/clean.jsonl"
printf '{"live":"%s"}\n' "$GH" >"$H/.claude/projects/p/live.jsonl"
python3 - "$H/.local/share/opencode/opencode.db" "$GH" <<'PY'
import sqlite3,sys
c=sqlite3.connect(sys.argv[1]); c.execute("create table m(t text)"); c.execute("insert into m values (?)",(sys.argv[2],)); c.commit()
PY
touch -d '2 days ago' "$H/.claude/projects/p/a.jsonl" "$H/.local/share/opencode/storage/k.json" "$H/.codex/sessions/clean.jsonl" "$H/.local/share/opencode/opencode.db"
before=$(find "$H" -type f -exec sha256sum {} + | sort)
HOME="$H" bash $S --harness all >"$T/scan.txt" 2>/dev/null

OUT="$T/staging"
res=$(HOME="$H" python3 $ST --flagged "$T/scan.txt" --out "$OUT" 2>&1); rc=$?
[ $rc -eq 0 ] && ok "staging exits 0" || { bad "staging exits 0 (rc=$rc)"; echo "$res" | sed 's/^/      /'; }
[ "$(find "$H" -type f -exec sha256sum {} + | sort)" = "$before" ] && ok "originals untouched" || bad "an original changed"
SA="$OUT/.claude/projects/p/a.jsonl"; SK="$OUT/.local/share/opencode/storage/k.json"
[ -f "$SA" ] && ok "flagged transcript was staged" || bad "transcript not staged"
for v in "$GH" "$HVS" "$PW" "$KEYBODY"; do
  if grep -rqF -- "$v" "$OUT" 2>/dev/null; then bad "a secret value survived in staging"; break; fi
done; ok "no secret value anywhere in staging"
python3 - "$SA" "$SK" <<'PY' && ok "staged JSON still parses" || bad "staged JSON broken"
import json,sys
for f in sys.argv[1:]:
    for l in open(f):
        if l.strip(): json.loads(l)
PY
grep -q 'REDACTED:' "$SA" && ok "redaction marker with fingerprint present" || bad "no marker"
grep -q 'fine' "$SA" && ok "unflagged content kept" || bad "unflagged content lost"
grep -q 'postgresql://app:\[REDACTED' "$SA" && ok "URL keeps scheme and user, password redacted" || bad "URL redaction shape"
grep -q 'REDACTED-PRIVATE-KEY:' "$SK" && ! grep -qF "$KEYBODY" "$SK" && ok "private key block redacted whole" || bad "private key body survived"
! grep -q 'BEGIN [A-Z ]*PRIVATE KEY' "$SK" && ok "no BEGIN header left (complete block and clipped orphan)" || bad "BEGIN header survived"
[ "$(grep -c 'REDACTED-PRIVATE-KEY:' "$SK")" -ge 2 ] && ok "orphan and complete block both marked" || bad "orphan not marked"
python3 -c 'import json,sys; [json.loads(l) for l in open(sys.argv[1]) if l.strip()]' "$SK" && ok "key file still parses as JSON" || bad "JSON broken by key scrub"
[ ! -e "$OUT/.local/share/opencode/opencode.db" ] && echo "$res" | grep -q 'skipped-sqlite' && ok "SQLite database skipped and reported" || bad "sqlite handling"
echo "$res" | grep -q 'skipped-live' && [ ! -e "$OUT/.claude/projects/p/live.jsonl" ] && ok "recently modified file skipped as live" || bad "live-file handling"
[ ! -e "$OUT/.codex/sessions/clean.jsonl" ] && ok "unflagged file not copied" || bad "clean file copied"
[ "$(stat -c %a "$OUT")" = "700" ] && [ "$(stat -c %a "$SA")" = "600" ] && ok "staging is private (700/600)" || bad "staging permissions"
grep -q '"status": "staged"' "$OUT/manifest.json" && ok "manifest written" || bad "manifest"
for v in "$GH" "$HVS" "$PW"; do grep -qF -- "$v" "$OUT/manifest.json" && { bad "manifest holds a value"; break; }; done

# re-scan of the staged tree must be clean for the real patterns
HOME="$OUT" bash $S --harness claude >/dev/null 2>&1 && ok "staged copy rescans clean" || bad "staged copy still flagged"

HOME="$H" python3 $ST --flagged "$T/scan.txt" --out "$OUT" >/dev/null 2>&1; [ $? -eq 2 ] && ok "refuses a non-empty --out" || bad "non-empty --out"
HOME="$H" python3 $ST --flagged "$T/scan.txt" --out "$H/.claude/staged" >/dev/null 2>&1; [ $? -eq 2 ] && ok "refuses --out inside an agent folder" || bad "--out inside agent folder"
# 10. scrubbing never breaks JSON that was valid: URL-shaped punctuation next to a real secret
H3="$T/h3"; mkdir -p "$H3/.claude/projects/p"
printf '{"a":"https://h.example:8080","b":"x@y.example/z","k":"%s"}\n' "$GH" >"$H3/.claude/projects/p/j.jsonl"
touch -d '2 days ago' "$H3/.claude/projects/p/j.jsonl"
HOME="$H3" bash $S --harness claude >"$T/scan3.txt" 2>/dev/null
HOME="$H3" python3 $ST --flagged "$T/scan3.txt" --out "$T/st3" >/dev/null 2>&1; rc=$?
[ $rc -eq 0 ] && python3 -c "import json,sys; [json.loads(l) for l in open(sys.argv[1]) if l.strip()]" "$T/st3/.claude/projects/p/j.jsonl" \
  && grep -q 'https://h.example:8080' "$T/st3/.claude/projects/p/j.jsonl" && ok "JSON stays valid and URL text is kept" || bad "scrub broke JSON or mangled the URL"

exit $fail
