# AGENTS.md: check-argv-secrets

Instructions for AI coding agents working on this repo.

## What it is

A CWE-214 checker in two implementations that must always agree:

- `check-argv-secrets.sh`: dependency-free bash (grep)
- `rules/argv-secrets.yaml`: semgrep rules, regex in `generic` mode

## Rules for changes

- **Change both implementations together.** A new or changed rule goes into the bash `PATTERNS`
  array *and* the semgrep rule file, with the same id (`foo` / `argv-secret-foo`).
- **Every rule change comes with fixtures.** Add the bad line to `tests/fixtures/bad/<rule>.*`,
  its line to `tests/expected.txt`, and the safe form to `tests/fixtures/good/`.
- **Run the tests before committing:** `tests/run.sh --semgrep`. Both implementations must report
  exactly what `tests/expected.txt` lists, and the good fixtures must be clean.
- **The repo checks itself:**
  `bash check-argv-secrets.sh --exclude '^tests/fixtures/' --exclude '^README\.md$'`.
  Rule *messages* must not contain the patterns they describe, or the self-check flags them.
- `.semgrepignore` exists so semgrep scans `tests/`. Don't delete it.
- Keep the script dependency-free: bash, coreutils, grep, sed. No Python, no jq.

## Secrets and publishing

This is a public repo, so every commit is publishing.

- Follow the secrets rules in [`examples/AGENTS.md`](examples/AGENTS.md). This repo should pass
  its own check.
- Fixtures use made-up values and `example.com` hosts only. Never commit a real hostname, IP,
  secret or token, even as a "bad" example.
- Stage files by name (`git add <file>`), never `git add -A`.
