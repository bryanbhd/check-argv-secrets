#!/bin/bash
sshpass -p "$SSH_PASSWORD" ssh admin@host01 uptime
mysql -u root -p"$MYSQL_ROOT_PASSWORD" -e 'show databases'
mysqldump --user=backup --password=$BACKUP_PASS appdb > appdb.sql
