#!/bin/bash
curl -sS --data "{\"role_id\":\"$ROLE_ID\",\"secret_id\":\"$SECRET_ID\"}" https://vault.example.com/v1/auth/approle/login
curl -sS -d "username=admin&password=$ADMIN_PASSWORD" https://app.example.com/login
