#!/bin/sh
exec perl -e 'alarm(shift); exec @ARGV' ${AL:-30} /opt/homebrew/opt/postgresql@16/bin/psql -X -h 127.0.0.1 -p ${PP:-5547} -d fw_appr_e2e -U ec2-user "$@"
