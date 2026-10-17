#!/usr/bin/env bash
# check-memory-secrets.sh - find secrets in AI agent memory files; optionally scrub them.
#
# Agent memory files (.md with frontmatter) collect example commands, debug output, and notes.
# A secret pasted "for reference" stays in context forever. This finds them.
#
# Usage:
#   check-memory-secrets.sh                        scan default memory locations
#   check-memory-secrets.sh DIR...                 scan specific directories
#   check-memory-secrets.sh --scrub                replace found secrets with [REDACTED]
#   check-memory-secrets.sh --purge-line           delete entire lines containing secrets
#
# Options:
#   --scan-memory              scan .claude/projects/*/memory/ (default if no paths given)
#   --scan-all                 also scan any other .md in the repo
#   --exclude REGEX            skip files matching REGEX (repeatable)
#   --patterns FILE            extra patterns, one ERE per line
#   --allow-file FILE          allow-list file: one "FILE:LINE" or "FILE" per line (skip these)
#   --scrub                    replace secrets in-place with [REDACTED] (creates .bak-YYYYMMDD)
#   --purge-line               delete entire lines containing secrets (creates .bak-YYYYMMDD)
#   --dry-run                  with --scrub/--purge-line: show what would change, don't write
#   -q, --quiet                only print findings
#   -h, --help
#
# Exit status: 0 = clean, 1 = findings, 2 = usage error.
set -uo pipefail

EXCLUDES=('(^|/)(node_modules|vendor|\.git|dist|build)/')
EXTRA_PATTERN_FILES=()
QUIET=0
SCRUB=0
DRY_RUN=0
PURGE_LINE=0
SCAN_MEMORY=0
SCAN_ALL=0
ALLOW_FILE=""
PATHS=()

# Patterns for memory files: "id|description|ERE"
# These look for actual secret VALUES (not variable names).
# Inspired by TruffleHog/Gitleaks pattern sets.
PATTERNS=(
  # URL-embedded credentials: scheme://user:PASS@host or scheme://:PASS@host
  # Require 6+ chars in password to avoid false positives on placeholders like PASS/xxx
  "url-cred|credential embedded in a URL|((https?|postgresql?|redis|amqp|mongodb|mysql)://[^:/]*:[^@/]{6,}@)"

  # Vault tokens (hvs. prefix is the real format)
  "vault-token|Vault root/unseal token|hvs\.[A-Za-z0-9_-]{20,}"

  # AppRole secret IDs (long hex-ish strings after secret_id:)
  "approle-secret-id|AppRole secret ID value|secret_id:[[:space:]]*[\"']?[A-Za-z0-9_-]{32,}[\"']?"

  # Generic secret key=value in code blocks (password: "...", token: "...")
  # Require 12+ chars to avoid matching placeholder names
  "inline-secret-key|secret value in key=value form|(^|[[:space:]])[A-Za-z_]*(password|passwd|secret|token|api_key|apikey|private_key)[A-Za-z_]*[[:space:]]*[:=][[:space:]]*[\"']?[A-Za-z0-9+/=_-]{12,}[\"']?"

  # GitHub PATs/installation tokens
  "gh-pat|GitHub personal/installation token|(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}"

  # GitLab PATs
  "gl-pat|GitLab personal access token|glpat-[A-Za-z0-9_-]{20,}"
  "gl-token|GitLab deploy/token|gltoken-[A-Za-z0-9_-]{20,}"

  # npm tokens
  "npm-token|npm registry token|npm_[A-Za-z0-9]{36}"

  # Slack tokens
  "slack-token|Slack bot/user token|(xoxb|xoxp|xoxa|xoxr|xoxs|xoxe)-[A-Za-z0-9-]+"

  # Stripe keys
  "stripe-key|Stripe API key|(sk|pk)_(live|test)_[A-Za-z0-9]{20,}"

  # Twilio auth keys
  "twilio-key|Twilio auth key|SK[A-Za-z0-9]{32}"

  # Docker Hub tokens
  "docker-token|Docker Hub personal access token|dckr_pat_[A-Za-z0-9_-]{20,}"

  # Generic bearer token in example commands
  "bearer-token|Bearer token value in example|Bearer [A-Za-z0-9._-]{20,}"

  # AWS access key IDs
  "aws-key|AWS access key ID|AKIA[A-Z0-9]{16}"

  # SSH private keys (BEGIN line)
  "ssh-private-key|SSH private key block|-----BEGIN (RSA |EC |ED25519 |OPENSSH )?PRIVATE KEY-----"

  # PGP private keys
  "pgp-private-key|PGP private key block|-----BEGIN PGP PRIVATE KEY BLOCK-----"

  # JWT tokens (three base64 segments with dots)
  "jwt-token|JWT token|eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"

  # Environment variables with secret-looking values exported inline
  # e.g., export VAULT_TOKEN="hvs.xxx", export DB_PASSWORD="realpassword"
  "env-secret-export|secret in exported environment variable|export[[:space:]]+[A-Za-z_]*(PASSWORD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)[A-Za-z_]*=[\"']?[A-Za-z0-9+/=_-]{12,}"

  # EnvironmentFile= with inline secret (not just a path)
  "env-file-inline|secret in inline EnvironmentFile value|EnvironmentFile=[[:space:]]*[A-Za-z_]*(PASSWORD|SECRET|TOKEN)[A-Za-z_]*=[\"']?[A-Za-z0-9+/=_-]{8,}"

  # PGPASSWORD inline (common Postgres leak)
  "pgpassword|PGPASSWORD set inline|PGPASSWORD=[\"']?[A-Za-z0-9+/=_-]{6,}[\"']?"

  # MYSQL_PWD inline
  "mysql-pwd|MYSQL_PWD set inline|MYSQL_PWD=[\"']?[A-Za-z0-9+/=_-]{6,}[\"']?"

  # SSHPASS inline
  "sshpass|SSHPASS set inline|SSHPASS=[\"']?[A-Za-z0-9+/=_-]{6,}[\"']?"

  # Azure DevOps PATs (v1/v2)
  "ado-pat|Azure DevOps personal access token|[A-Za-z0-9]{52}"

  # Generic hex API keys (64 hex chars standalone, not embedded in paths/URLs)
  # Only match when surrounded by whitespace or common delimiters, not path segments
  "hex-api-key|hex-encoded API key value|(^|[[:space:]\"'=])[A-Fa-f0-9]{64}($|[[:space:]\"',])"
)

die() { echo "check-memory-secrets: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --scan-memory) SCAN_MEMORY=1; shift ;;
    --scan-all) SCAN_ALL=1; shift ;;
    --exclude) [ $# -ge 2 ] || die "--exclude needs a regex"; EXCLUDES+=("$2"); shift 2 ;;
    --patterns) [ -r "${2:-}" ] || die "--patterns needs a readable file"; EXTRA_PATTERN_FILES+=("$2"); shift 2 ;;
    --allow-file) [ -r "${2:-}" ] || die "--allow-file needs a readable file"; ALLOW_FILE="$2"; shift 2 ;;
    --scrub) SCRUB=1; shift ;;
    --purge-line) PURGE_LINE=1; shift ;;
    --dry-run) DRY_RUN=1; shift ;;
    -q|--quiet) QUIET=1; shift ;;
    -h|--help) sed -n '2,/^set -uo/{/^set -uo/d;s/^# \{0,1\}//;p}' "$0"; exit 0 ;;
    --) shift; PATHS+=("$@"); break ;;
    -*) die "unknown option: $1 (see --help)" ;;
    *) PATHS+=("$1"); shift ;;
  esac
done

# Load allow-list (FILE:LINE or FILE per line; # comments allowed)
declare -A ALLOW_LIST=()
if [ -n "$ALLOW_FILE" ]; then
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    line=$(sed 's/^[[:space:]]*//;s/[[:space:]]*$//' <<<"$line")
    ALLOW_LIST["$line"]=1
  done <"$ALLOW_FILE"
fi

is_allowed() {
  local file="$1" lineno="$2"
  # Check exact file:line
  [ "${ALLOW_LIST["${file}:${lineno}"]:-}" = "1" ] && return 0
  # Check whole file
  [ "${ALLOW_LIST["$file"]:-}" = "1" ] && return 0
  return 1
}

# Default: scan memory dirs if nothing specified
if [ ${#PATHS[@]} -eq 0 ] && [ "$SCAN_MEMORY" -eq 0 ] && [ "$SCAN_ALL" -eq 0 ]; then
  SCAN_MEMORY=1
fi

# Known harness memory locations (add your own via --scan-harness PATH)
HARNESS_DIRS=(
  "$HOME/.claude/projects"
)

for f in "${EXTRA_PATTERN_FILES[@]}"; do
  n=0
  while IFS= read -r line; do
    [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
    n=$((n + 1)); PATTERNS+=("custom-$n|custom pattern from $f|$line")
  done <"$f"
done

# ---- collect files ----------------------------------------------------------
collect() {
  if [ ${#PATHS[@]} -gt 0 ]; then
    for p in "${PATHS[@]}"; do
      if [ -d "$p" ]; then find "$p" -type f -name '*.md'
      elif [ -f "$p" ]; then printf '%s\n' "$p"
      else die "no such file or directory: $p"; fi
    done
  elif [ "$SCAN_MEMORY" -eq 1 ]; then
    # .claude memory directories
    local base="${HOME}/.claude/projects"
    if [ -d "$base" ]; then
      find "$base" -path '*/memory/*.md' -type f 2>/dev/null
    fi
  fi
  if [ "$SCAN_ALL" -eq 1 ]; then
    if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
      git ls-files '*.md'
    else
      find "${PATHS[@]:-}" -type f -name '*.md' 2>/dev/null || true
    fi
  fi
}

exclude_re=$(printf '%s|' "${EXCLUDES[@]}"); exclude_re=${exclude_re%|}
mapfile -t FILES < <(collect | grep -vE "$exclude_re" 2>/dev/null | sort -u)
[ ${#FILES[@]} -gt 0 ] || { [ "$QUIET" -eq 1 ] || echo "check-memory-secrets: no files to scan"; exit 0; }

# ---- scan -------------------------------------------------------------------
# Skip lines that are clearly just describing the concept (not showing a value):
#   "secrets live in Vault", "use a token", "the password field"
is_safe_line() {
  local line="$1"
  # Descriptive text without an actual value pattern
  [[ "$line" =~ (secrets?|tokens?|passwords?|credentials?)?[[:space:]]+(live|stored|kept|managed)[[:space:]]+(in|by|with) ]] && return 0
  return 1
}

HITS=0
declare -a FINDINGS=()

for p in "${PATTERNS[@]}"; do
  IFS='|' read -r id _ re <<<"$p"
  while IFS= read -r hit; do
    [ -z "$hit" ] && continue
    file=${hit%%:*}; rest=${hit#*:}; lineno=${rest%%:*}; line=${rest#*:}
      is_safe_line "$line" && continue
    is_allowed "$file" "$lineno" && continue
    FINDINGS+=("$file|$lineno|$id|$line")
    HITS=$((HITS + 1))
  done < <(grep -nHE -- "$re" "${FILES[@]}" 2>/dev/null)
done

if [ "$HITS" -gt 0 ]; then
  # Print findings
  for f in "${FINDINGS[@]}"; do
    IFS='|' read -r file lineno id line <<<"$f"
    printf '%s:%s: [%s] %s\n' "$file" "$lineno" "$id" "$(sed 's/^[[:space:]]*//' <<<"${line:0:160}")"
  done

  if [ "$SCRUB" -eq 1 ] || [ "$PURGE_LINE" -eq 1 ]; then
    echo "" >&2
    if [ "$PURGE_LINE" -eq 1 ]; then
      echo "check-memory-secrets: --purge-line mode (delete entire lines with secrets)" >&2
    else
      echo "check-memory-secrets: --scrub mode (replace secrets with [REDACTED])" >&2
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
      echo "check-memory-secrets: --dry-run: showing what would change" >&2
    else
      BACKUP_SUFFIX=".bak-$(date +%Y%m%d)"
      echo "check-memory-secrets: backing up affected files to ${BACKUP_SUFFIX}" >&2
    fi

    # Group findings by file
    declare -A FILE_CHANGES=()
    declare -A FILE_LINES=()
    for f in "${FINDINGS[@]}"; do
      IFS='|' read -r file lineno id line <<<"$f"
      FILE_CHANGES["$file"]=1
      FILE_LINES["$file"]+=" $lineno"
    done

    for file in "${!FILE_CHANGES[@]}"; do
      if [ ! -r "$file" ]; then continue; fi
      tmp=$(mktemp) || continue

      if [ "$PURGE_LINE" -eq 1 ]; then
        # Delete lines containing secrets
        lines="${FILE_LINES["$file"]}"
        grep -v -nE "$(printf '%s\n' $lines | tr ' ' '\n' | sed 's/^/^[[:space:]]*//' | paste -sd'|')" "$file" > "$tmp" || true
        # Alternative: use sed to delete specific line numbers
        if [ -s "$tmp" ]; then
          :
        else
          # Fallback: delete by line numbers
          sed -i "${lines// /,}d" "$file" && mv "$file" "$tmp"
        fi
      else
        # Scrub mode: replace matched secret portions with [REDACTED]
        cp "$file" "$tmp"

        # URL credentials: keep scheme://user:, replace password, keep @host
        sed -i -E 's#(https?|postgresql?|redis|amqp|mongodb|mysql)://([^:/]+):[^@/]{6,}@#\1://\2:[REDACTED]@#g' "$tmp"

        # Vault tokens
        sed -i -E 's#hvs\.[A-Za-z0-9_-]{20,}#hvs.[REDACTED]#g' "$tmp"

        # AppRole secret IDs
        sed -i -E 's#(secret_id:[[:space:]]*["'"'"']?)[A-Za-z0-9_-]{32,}#\1[REDACTED]#g' "$tmp"

        # Inline key=value secrets
        sed -i -E 's#([A-Za-z_]*(password|passwd|secret|token|api_key|apikey|private_key)[A-Za-z_]*[[:space:]]*[:=][[:space:]]*["'"'"']?)[A-Za-z0-9+/=_-]{12,}#\1[REDACTED]#g' "$tmp"

        # GitHub tokens
        sed -i -E 's#(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}#\1_[REDACTED]#g' "$tmp"

        # GitLab tokens
        sed -i -E 's#(glpat-)[A-Za-z0-9_-]{20,}#\1[REDACTED]#g' "$tmp"

        # npm tokens
        sed -i -E 's#(npm_)[A-Za-z0-9]{36}#\1[REDACTED]#g' "$tmp"

        # Slack tokens
        sed -i -E 's#(xox[bparse]-)[A-Za-z0-9-]+#\1[REDACTED]#g' "$tmp"

        # Stripe keys
        sed -i -E 's#((sk|pk)_(live|test)_)[A-Za-z0-9]{20,}#\1[REDACTED]#g' "$tmp"

        # Docker tokens
        sed -i -E 's#(dckr_pat_)[A-Za-z0-9_-]{20,}#\1[REDACTED]#g' "$tmp"

        # Bearer tokens
        sed -i -E 's#(Bearer )[A-Za-z0-9._-]{20,}#\1[REDACTED]#g' "$tmp"

        # AWS keys
        sed -i -E 's#AKIA[A-Z0-9]{16}#AKIA[REDACTED]#g' "$tmp"

        # JWT tokens
        sed -i -E 's#eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}#eyJ[REDACTED]#g' "$tmp"
      fi

      # Compare
      if ! diff -q "$file" "$tmp" >/dev/null 2>&1; then
        if [ "$DRY_RUN" -eq 1 ]; then
          echo "check-memory-secrets: would modify $file" >&2
          diff -u "$file" "$tmp" | head -40 >&2
        else
          cp "$file" "${file}${BACKUP_SUFFIX}"
          mv "$tmp" "$file"
          echo "check-memory-secrets: modified $file (backup: ${file}${BACKUP_SUFFIX})" >&2
        fi
      else
        rm -f "$tmp"
      fi
    done
    [ "$DRY_RUN" -eq 1 ] || echo "" >&2
  fi

  echo "check-memory-secrets: ${HITS} secret(s) found in ${#FILES[@]} file(s)" >&2
  exit 1
fi

[ "$QUIET" -eq 1 ] || echo "check-memory-secrets: OK - no secrets in ${#FILES[@]} file(s)"
exit 0
