#!/bin/bash
ssh db01 bash -c "PGPASSWORD=$DB_PASSWORD psql -U app -c 'select 1'"
incus exec web01 -- sh -c "echo ${API_KEY} > /etc/app/key"
