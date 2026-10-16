#!/usr/bin/env bash
# check-argv-secrets.sh - fail when scripts or CI pipelines pass a secret on a command line.
#
# A process's arguments are readable by every user on the machine (`ps`, /proc/<pid>/cmdline),
# so `curl -H "Authorization: Bearer $TOKEN"` leaks the token while it runs. Secret scanners like
# gitleaks look for secrets *written into* files; this looks for code that *passes* them as argv.
#
# Usage:
#   check-argv-secrets.sh                 scan the git repo you're in (tracked files)
#   check-argv-secrets.sh PATH...         scan these files / directories
#   check-argv-secrets.sh --list-patterns print the built-in patterns and exit
#
# Options:
#   --exclude REGEX        skip files whose path matches REGEX (ERE; may be repeated)
#   --patterns FILE        extra patterns, one ERE per line ('#' comments allowed)
#   -q, --quiet            only print findings
#   -h, --help
#
# Exit status: 0 = clean, 1 = findings, 2 = usage error.
#
# https://github.com/bryanbhd/check-argv-secrets - MIT licence
set -uo pipefail

EXTS='\.(sh|bash|zsh|ya?ml|py|ps1|mk)$|(^|/)(Makefile|Dockerfile|Jenkinsfile)$'
EXCLUDES=('(^|/)(node_modules|vendor|\.git|dist|build)/')
EXTRA_PATTERN_FILES=()
QUIET=0
PATHS=()

# Secret-looking variable names (case-insensitive where used)
SECRET_WORD='(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|CREDENTIAL)'

# Built-in patterns: "id|description|ERE". Matched per line with grep -E.
PATTERNS=(
  "curl-header|credential header as a command-line argument|(-H|--header) [\"'](X-Vault-Token|Authorization|X-Api-Key|X-Auth-Token|PRIVATE-TOKEN|Api-Key|Cookie):[^\"']*\\$"
  "curl-body|secret in a request body built on the command line|(-d|--data|--data-raw|--data-binary|--data-urlencode) [\"']([^\"'\\\\]|\\\\.)*(secret_id|secret|password|passwd|_token|token|api_key|apikey)([^\"'\\\\]|\\\\.)*\\$"
  "subshell|secret expanded into a sub-shell / remote command string|(bash|sh|zsh) -c [\"'][^\"']*\\\$\\{?[A-Za-z_]*${SECRET_WORD}[A-Za-z_]*\\}?"
  "password-flag|password passed as a flag value|(sshpass([^|;&]*) -p ?|(mysql|mariadb|mysqldump|mariadb-dump|mysqladmin)([^|;&]*) (-p|--password=))[\"']?\\$"
  "ado-macro|Azure DevOps secret macro inside script text|\\\$\\((VAULT_SECRET_ID[A-Z_]*|[A-Z_]*(PASSWORD|SECRET|SECRET_ID|API_KEY|TOKEN)[A-Z_]*)\\)"
  "gha-secret|GitHub Actions secret expression inside a run script|\\\$\\{\\{ *secrets\\.[A-Za-z0-9_]+ *\\}\\}"
)

die() { echo "check-argv-secrets: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --exclude) [ $# -ge 2 ] || die "--exclude needs a regex"; EXCLUDES+=("$2"); shift 2 ;;
    --patterns) [ -r "${2:-}" ] || die "--patterns needs a readable file"; EXTRA_PATTERN_FILES+=("$2"); shift 2 ;;
    -q|--quiet) QUIET=1; shift ;;
    --list-patterns)
      for p in "${PATTERNS[@]}"; do IFS='|' read -r id desc _ <<<"$p"; printf '%-14s %s\n' "$id" "$desc"; done
      exit 0 ;;
    -h|--help) sed -n '2,/^set -uo/{/^set -uo/d;s/^# \{0,1\}//;p}' "$0"; exit 0 ;;
    --) shift; PATHS+=("$@"); break ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *) PATHS+=("$1"); shift ;;
  esac
done

for f in "${EXTRA_PATTERN_FILES[@]}"; do
  n=0
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    n=$((n + 1)); PATTERNS+=("custom-$n|custom pattern from $f|$line")
  done <"$f"
done

# ---- collect files ----------------------------------------------------------
collect() {
  if [ ${#PATHS[@]} -eq 0 ]; then
    git rev-parse --is-inside-work-tree >/dev/null 2>&1 || die "not in a git repo - pass the files or directories to scan"
    git ls-files
  else
    local p
    for p in "${PATHS[@]}"; do
      if [ -d "$p" ]; then find "$p" -type f
      elif [ -f "$p" ]; then printf '%s\n' "$p"
      else die "no such file or directory: $p"; fi
    done
  fi
}
exclude_re=$(printf '%s|' "${EXCLUDES[@]}"); exclude_re=${exclude_re%|}
mapfile -t FILES < <(collect | grep -E "$EXTS" | grep -vE "$exclude_re" | sort -u)
# explicitly named files are always scanned, whatever their extension
for p in "${PATHS[@]}"; do [ -f "$p" ] && FILES+=("$p"); done
mapfile -t FILES < <(printf '%s\n' "${FILES[@]}" | grep -v '^$' | sort -u)
[ ${#FILES[@]} -gt 0 ] || { [ "$QUIET" -eq 1 ] || echo "check-argv-secrets: no files to scan"; exit 0; }

# ---- scan -------------------------------------------------------------------
# Lines that are fine even though they match:
#   comments, and the safe CI form - a mapping line `NAME: $(SECRET)` / `NAME: ${{ secrets.X }}`
#   under env:/with:, which hands the secret over as an environment variable or action input.
is_safe_line() {
  [[ "$1" =~ ^[[:space:]]*(#|//|REM[[:space:]]) ]] && return 0
  # ...but never a script key: `- run: ${{ secrets.X }}` puts the secret straight into the script
  [[ "$1" =~ ^[[:space:]]*-?[[:space:]]*(run|bash|script|sh|pwsh|powershell|inlineScript)[[:space:]]*: ]] && return 1
  [[ "$1" =~ ^[[:space:]]*-?[[:space:]]*[A-Za-z_][A-Za-z0-9_-]*:[[:space:]]+[\"\']?(\$\(|\$\{\{) ]] && return 0
  return 1
}

HITS=0
for p in "${PATTERNS[@]}"; do
  IFS='|' read -r id _ re <<<"$p"
  while IFS= read -r hit; do
    file=${hit%%:*}; rest=${hit#*:}; lineno=${rest%%:*}; line=${rest#*:}
    is_safe_line "$line" && continue
    printf '%s:%s: [%s] %s\n' "$file" "$lineno" "$id" "$(sed 's/^[[:space:]]*//' <<<"${line:0:160}")"
    HITS=$((HITS + 1))
  done < <(grep -nHE -- "$re" "${FILES[@]}" 2>/dev/null)
done

if [ "$HITS" -gt 0 ]; then
  echo "check-argv-secrets: ${HITS} place(s) pass a secret on a command line - see https://github.com/bryanbhd/check-argv-secrets#safe-forms" >&2
  exit 1
fi
[ "$QUIET" -eq 1 ] || echo "check-argv-secrets: OK - no secrets on command lines in ${#FILES[@]} file(s)"
exit 0
