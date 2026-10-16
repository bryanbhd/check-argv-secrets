#!/bin/bash
# The safe ways to do the same things: secrets go in via stdin, a file or the environment.
# curl -H "Authorization: Bearer $TOKEN"   <- mentioned in a comment, not executed
curl -sS -K <(printf 'header = "X-Vault-Token: %s"\n' "$VAULT_TOKEN") https://vault.example.com/v1/kv/data/app
curl -sS --data @<(printf '{"role_id":"%s","secret_id":"%s"}' "$ROLE_ID" "$SECRET_ID") https://vault.example.com/v1/auth/approle/login
printf '%s' "$PAYLOAD" | curl -sS --data @- https://app.example.com/login
curl -sS -H "Content-Type: application/json" -H "X-Request-Id: $REQ_ID" https://api.example.com/
SSHPASS="$SSH_PASSWORD" sshpass -e ssh admin@host01 uptime
MYSQL_PWD="$MYSQL_ROOT_PASSWORD" mysql -u root -e 'show databases'
mysql --defaults-extra-file=/run/app/my.cnf -e 'select 1'
bash -c "echo hello $USER"
