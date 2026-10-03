#!/usr/bin/env bash
# Scratch PG16 cluster that ENFORCES scram-sha-256 (pg_hba), for scram_e2e.sh.
# The shared :5544 cluster uses trust auth, which would make auth checks pass for the wrong reason.
set -euo pipefail
export LC_ALL=C LANG=C
PGBIN=${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}; D=${D:-/tmp/fw-scram-pg}; PORT=${PORT:-55440}
case "${1:-start}" in
  start)
    if [ ! -f $D/PG_VERSION ]; then
      echo "boot-$(openssl rand -hex 6)" > /tmp/fw-scram-pg.su; chmod 600 /tmp/fw-scram-pg.su
      $PGBIN/initdb -D $D -U fwsu --pwfile=/tmp/fw-scram-pg.su --auth=scram-sha-256 -E UTF8 --locale=C >/dev/null
      printf "port=$PORT\nlisten_addresses='127.0.0.1'\npassword_encryption='scram-sha-256'\nunix_socket_directories='/tmp'\n" >> $D/postgresql.conf
    fi
    $PGBIN/pg_ctl -D $D -l $D/log -w status >/dev/null 2>&1 || $PGBIN/pg_ctl -D $D -l $D/log -w start >/dev/null ;;
  stop) $PGBIN/pg_ctl -D $D -w stop -m fast >/dev/null; rm -rf $D /tmp/fw-scram-pg.su ;;
esac
