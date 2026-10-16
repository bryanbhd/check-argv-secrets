# check-argv-secrets

Fail the build when a script or CI pipeline **passes a secret on a command line**.

```bash
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/   # leaks $TOKEN
```

While that runs, any user on the machine can read the token with `ps` or
`/proc/<pid>/cmdline` [1]. That covers other containers' users on a shared host, monitoring
agents, and process-accounting logs. The weakness has a name: **CWE-214, Invocation of Process
Using Visible Sensitive Information** [2].

Secret scanners like gitleaks find secrets *written into* files. This finds code that *passes*
secrets as arguments at runtime. They do different jobs, so run both.

It comes in two forms that run the same checks against the same test fixtures:

- **`check-argv-secrets.sh`**: one bash file, no dependencies beyond `grep`
- **`rules/argv-secrets.yaml`**: semgrep rules, for teams that already run semgrep [3]

## What it catches

| Rule | Example it flags |
|---|---|
| `curl-header` | `curl -H "X-Vault-Token: $T"`, `--header "Authorization: Bearer ${TOKEN}"` |
| `curl-body` | `curl --data "{\"secret_id\":\"$SID\"}"`, `-d "user=a&password=$PW"` |
| `subshell` | `ssh host bash -c "PGPASSWORD=$DB_PASSWORD psql …"`, `incus exec c -- sh -c "echo $API_KEY > f"` |
| `password-flag` | `sshpass -p "$PW" ssh …`, `mysql -u root -p"$PW"`, `mysqldump --password=$PW` |
| `ado-macro` | Azure DevOps `$(VAULT_SECRET_ID)` / `$(DB_PASSWORD)` pasted into a script step |
| `gha-secret` | GitHub Actions `run: ./deploy.sh --token ${{ secrets.DEPLOY_TOKEN }}` |

Comment lines are ignored, and so are CI mapping lines like `NAME: $(SECRET)` or
`token: ${{ secrets.X }}` under `env:` / `with:`, because that's the safe way to hand a secret
over. A mapping line whose key is a script (`run:`, `bash:`, `script:`) is still checked.

## Safe forms

The fix is always the same idea: the secret goes in through **stdin, a file, or the
environment**, never as an argument.

| Instead of | Use |
|---|---|
| `curl -H "Authorization: Bearer $TOKEN"` | `curl -K <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN")` |
| `curl --data "{\"secret_id\":\"$SID\"}"` | `curl --data @<(printf '{"secret_id":"%s"}' "$SID")` or `printf … \| curl --data @-` |
| `ssh host bash -c "PGPASSWORD=$PW psql"` | send it on stdin: `printf '%s\n' "$PW" \| ssh host 'read -r PGPASSWORD; export PGPASSWORD; psql …'` |
| `sshpass -p "$PW" ssh …` | `SSHPASS="$PW" sshpass -e ssh …` |
| `mysql -p"$PW"` | `MYSQL_PWD="$PW" mysql …` or `mysql --defaults-extra-file=/run/app/my.cnf` |
| ADO: `$(VAULT_SECRET_ID)` in the script | `env: { VAULT_SECRET_ID: $(VAULT_SECRET_ID) }` and `"$VAULT_SECRET_ID"` in the script |
| GHA: `${{ secrets.X }}` in `run:` | `env: { X: ${{ secrets.X }} }` and `"$X"` in the script |

`<(…)` and `--data @-` hand curl a pipe or file descriptor, so the secret never appears in any
process's arguments. `printf` is a bash builtin, so it doesn't start a process either.

## Use it

```bash
curl -fsSLO https://raw.githubusercontent.com/bryanbhd/check-argv-secrets/main/check-argv-secrets.sh
bash check-argv-secrets.sh                    # scan the git repo you're in (tracked files)
bash check-argv-secrets.sh scripts/ ci.yml    # scan specific files / directories
bash check-argv-secrets.sh --list-patterns
```

Options: `--exclude REGEX` (skip paths, repeatable), `--patterns FILE` (add your own EREs, one
per line), `-q` (findings only). Exit status: `0` clean, `1` findings, `2` usage error.

It scans `*.sh *.bash *.zsh *.yml *.yaml *.py *.ps1 *.mk`, `Makefile`, `Dockerfile` and
`Jenkinsfile`, skipping `node_modules/`, `vendor/`, `dist/` and `build/`. Files you name
explicitly are always scanned.

**Semgrep:**

```bash
semgrep scan --config rules/argv-secrets.yaml .
```

### pre-commit

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/bryanbhd/check-argv-secrets
    rev: v0.1.0
    hooks:
      - id: check-argv-secrets
```

### GitHub Actions

```yaml
- uses: actions/checkout@v4
- name: no secrets on command lines
  run: |
    curl -fsSLO https://raw.githubusercontent.com/bryanbhd/check-argv-secrets/v0.1.0/check-argv-secrets.sh
    bash check-argv-secrets.sh
```

### Azure DevOps

```yaml
- bash: |
    curl -fsSLO https://raw.githubusercontent.com/bryanbhd/check-argv-secrets/v0.1.0/check-argv-secrets.sh
    bash check-argv-secrets.sh
  displayName: no secrets on command lines
```

Pin a tag (or vendor the file into your repo) rather than running `main` in CI.

## Tests

```bash
tests/run.sh             # the bash script against tests/fixtures
tests/run.sh --semgrep   # both implementations
```

`tests/fixtures/bad/` holds one file per rule. `tests/expected.txt` lists every line that must be
flagged, and nothing else may be. `tests/fixtures/good/` holds the safe forms and must come back
clean.

## Limits

- **It matches patterns; it doesn't parse code.** It catches the common shapes. A secret in a
  variable with an unremarkable name (`$X`) passed on a command line won't be flagged by the
  `subshell` rule, which looks for `SECRET`, `PASSWORD`, `TOKEN`, `API_KEY`, `PRIVATE_KEY` or
  `CREDENTIAL` in the name. Add your own naming conventions with `--patterns`.
- One line at a time: a command split across lines with `\` is only matched if the secret and
  the flag are on the same line.
- Expect the odd false positive. Silence a line by moving the secret to a safe form, not by
  excluding the file.

## Background

Written after a sweep of a homelab infrastructure repo found Vault tokens and AppRole secret IDs
being passed to `curl` as arguments. This check has run as a blocking CI step there since.

## Sources

1. `proc_pid_cmdline(5)`, Linux manual page: https://man7.org/linux/man-pages/man5/proc_pid_cmdline.5.html
2. CWE-214: Invocation of Process Using Visible Sensitive Information: https://cwe.mitre.org/data/definitions/214.html
3. Semgrep documentation: https://semgrep.dev/docs/

## License

MIT. See [LICENSE](LICENSE).
