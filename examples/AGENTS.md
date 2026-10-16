# Secrets rules for AI coding agents

<!--
Drop-in snippet for your repo's agent instructions: AGENTS.md (Codex, Copilot, Cursor, Gemini CLI,
opencode and others), CLAUDE.md, .github/copilot-instructions.md, or wherever your agents read
their rules. Copy the section below; adjust the secret-store name to yours.

These rules tell the agent what to do. check-argv-secrets enforces rule 3 in CI, because an
instruction is advice and a failing build is not.
https://github.com/bryanbhd/check-argv-secrets
-->

## Secrets

These rules come from a real incident: a credential sweep found live passwords and API keys in
unit files, `.env` files, container config, process arguments, and in AI assistants' own chat
transcripts and logs. Most of the last group got there as part of a command line.

1. **Secrets live in the secret store** (Vault, a cloud secret manager, your CI's secret
   variables) and services read them at start. Never put a secret in a repo file, `.env`, unit
   file, compose file, container config, chat, log or command-line argument.
2. **Never display secret values**, even while debugging. Print variable *names* only, and
   compare secrets by hash or equality. Never ask the user to paste a secret into chat: have
   them run the command, or read the value from a file inside the command.
3. **Pass secrets via stdin, a file or the environment, never as an argument.** A command line
   is readable by every user on the machine (`ps`, `/proc/<pid>/cmdline`), and an agent's
   commands are also written into its transcript and logs. Safe forms:
   - curl body: `--data @<(printf '{"secret_id":"%s"}' "$SID")` or `printf … | curl --data @-`
   - curl header: `-K <(printf 'header = "Authorization: Bearer %s"\n' "$TOKEN")`
   - mysql / mariadb: `MYSQL_PWD="$PW" mysql …` or `--defaults-extra-file=<file>`, not `-p"$PW"`
   - sshpass: `SSHPASS="$PW" sshpass -e …`, not `sshpass -p "$PW"`
   - remote commands: send the secret on stdin, don't expand it inside `bash -c "…"` / `ssh … "…"`
   - CI secret variables: map them through the step's `env:` and use `"$NAME"` in the script.
     Never paste `$(SECRET)` (Azure DevOps) or `${{ secrets.X }}` (GitHub Actions) into script text.
4. **Rotating means changing the store and restarting the consumer.** If a rotation needs
   editing files on the consumer, wire the consumer to the store first.

Before committing, run the check (it exits 1 on findings):

```bash
bash check-argv-secrets.sh
```
