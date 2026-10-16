#!/bin/bash
curl -sS -H "X-Vault-Token: $VAULT_TOKEN" https://vault.example.com/v1/kv/data/app
curl -sS --header "Authorization: Bearer ${API_TOKEN}" https://api.example.com/
