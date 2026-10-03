#!/usr/bin/env bash
# db_role E2E: real control plane + real proxy + PG16 that enforces scram-sha-256.
# An agent with db_role is switched to a SELECT-only role, so Postgres itself
# rejects its writes; FaultWall refuses its attempts to change role. A second
# agent without db_role still writes. Run from this directory after
# `bash scram_pg.sh start`. Writes dbrole-last-run.txt.
set -uo pipefail
export LC_ALL=C LANG=C
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)
CPREPO=${CPREPO:-/tmp/fw-cp-keys}
PGBIN=${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}
PY=${PY:-/tmp/fw-pyvenv/bin/python}
W=/tmp/fw-dbrole-e2e; rm -rf $W; mkdir -p $W/home
export GOPATH=${GOPATH:-/tmp/fw-gopath} GOMODCACHE=${GOMODCACHE:-/tmp/fw-gopath/pkg/mod}
CPDB=fw_dbrole_cp UPDB=fw_dbrole_up ROLE=fw_dbrole_proxy RO=fw_dbrole_ro ROLEPW="upstream-$(openssl rand -hex 8)"
P="$PGBIN/psql -h 127.0.0.1 -p 5544 -q -v ON_ERROR_STOP=1"
UPPORT=${UPPORT:-55440} UPSU=${UPSU:-fwsu}
export PGPASSWORD_UP=$(cat ${UPSUPWFILE:-/tmp/fw-scram-pg.su})
PU() { PGPASSWORD=$PGPASSWORD_UP $PGBIN/psql -h 127.0.0.1 -p $UPPORT -U $UPSU -q -v ON_ERROR_STOP=1 "$@"; }
cleanup() { [ -f $W/cp.pid ] && kill $(cat $W/cp.pid) 2>/dev/null; [ -f $W/px.pid ] && kill $(cat $W/px.pid) 2>/dev/null; sleep 1
  $PGBIN/dropdb -h 127.0.0.1 -p 5544 --if-exists $CPDB
  PGPASSWORD=$PGPASSWORD_UP $PGBIN/dropdb -h 127.0.0.1 -p $UPPORT -U $UPSU --if-exists $UPDB
  PU -d postgres -c "DROP ROLE IF EXISTS $RO; DROP ROLE IF EXISTS fw_dbrole_notgranted; DROP ROLE IF EXISTS $ROLE" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup >/dev/null 2>&1

$PGBIN/createdb -h 127.0.0.1 -p 5544 $CPDB && PGPASSWORD=$PGPASSWORD_UP $PGBIN/createdb -h 127.0.0.1 -p $UPPORT -U $UPSU $UPDB
# Proxy login (owns nothing, has write grants) + a read-only role granted to it.
# This is the README's "per-agent read-only role" SQL, verbatim in shape.
PU -d postgres -c "SET password_encryption='scram-sha-256'; CREATE ROLE $ROLE LOGIN PASSWORD '$ROLEPW'"
PU -d $UPDB -c "CREATE TABLE orders(id int primary key, status text); INSERT INTO orders VALUES (1,'open');
  GRANT USAGE ON SCHEMA public TO $ROLE; GRANT SELECT, INSERT, UPDATE, DELETE ON orders TO $ROLE;
  CREATE ROLE $RO NOLOGIN; GRANT USAGE ON SCHEMA public TO $RO; GRANT SELECT ON ALL TABLES IN SCHEMA public TO $RO;
  GRANT $RO TO $ROLE;
  CREATE ROLE fw_dbrole_notgranted NOLOGIN;"
HBA=$(PU -d postgres -Atc "select string_agg(distinct auth_method, ',') from pg_hba_file_rules where type='host'")
for f in $CPREPO/migrations/0*.sql; do $P -d $CPDB -f $f >/dev/null || { echo "migration failed: $f"; exit 1; }; done

(cd $CPREPO && go build -o $W/cp ./cmd/controlplane) || exit 1
(cd $ROOT && go build -o $W/faultwall .) || exit 1

FWCP_LISTEN=127.0.0.1:18091 FWCP_DATABASE_URL="postgres://ec2-user@127.0.0.1:5544/$CPDB?sslmode=disable" \
  FWCP_GOTRUE_JWT_SECRET=e2e-secret-e2e-secret-e2e-secret-e2e-secret FWCP_PUBLIC_BASE_URL=http://127.0.0.1:18091 \
  $W/cp > $W/cp.log 2>&1 & echo $! > $W/cp.pid
for i in $(seq 1 40); do curl -sf http://127.0.0.1:18091/healthz >/dev/null && break; sleep 0.25; done

cd $HERE
$PY cp.py POST /v1/dashboard/provision '{}' >/dev/null
TOK=$($PY cp.py POST /v1/dashboard/tokens '{"label":"e2e"}' | sed -n 2p | $PY -c 'import json,sys; print(json.load(sys.stdin)["token"])')
# FaultWall allows writes for ro-agent on purpose: the write must be stopped by Postgres (the role), not by a rule.
RO_AG=$($PY cp.py POST /v1/dashboard/agents "{\"name\":\"ro-agent\",\"writes\":\"allow\",\"db_role\":\"$RO\",\"proxy_host\":\"127.0.0.1:15433\",\"database\":\"$UPDB\"}" | sed -n 2p)
RW_AG=$($PY cp.py POST /v1/dashboard/agents "{\"name\":\"rw-agent\",\"writes\":\"allow\",\"proxy_host\":\"127.0.0.1:15433\",\"database\":\"$UPDB\"}" | sed -n 2p)
BAD_AG=$($PY cp.py POST /v1/dashboard/agents "{\"name\":\"bad-role-agent\",\"db_role\":\"fw_dbrole_notgranted\",\"proxy_host\":\"127.0.0.1:15433\",\"database\":\"$UPDB\"}" | sed -n 2p)
INVALID=$($PY cp.py POST /v1/dashboard/agents '{"name":"x-agent","db_role":"x\"; DROP ROLE y; --"}' | head -1)
j() { $PY -c "import json,sys; print(json.load(sys.stdin)$1)"; }
POLICY=$(curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18091/v1/policy)

printf 'default_policy: allow\nagents: {}\n' > $W/policies.yaml
HOME=$W/home FAULTWALL_CONTROL_PLANE_URL=http://127.0.0.1:18091 FAULTWALL_CONTROL_PLANE_TOKEN=$TOK FW_POLICY_SYNC_INTERVAL=2s \
  FW_UPSTREAM_USER=$ROLE FW_UPSTREAM_PASSWORD=$ROLEPW PORT=${FW_E2E_API_PORT:-18092} BIND_ADDR=127.0.0.1 \
  $W/faultwall --proxy --listen 127.0.0.1:15433 --upstream 127.0.0.1:$UPPORT --policies $W/policies.yaml --mode enforce > $W/proxy.log 2>&1 & echo $! > $W/px.pid
for i in $(seq 1 40); do grep -q "Agent keys synced" $W/proxy.log 2>/dev/null && nc -z 127.0.0.1 15433 && break; sleep 0.25; done
sleep 1

RO_KEY=$(echo "$RO_AG" | j '["key"]') RO_ID=$(echo "$RO_AG" | j '["agent"]["id"]') RO_VIEW_ROLE=$(echo "$RO_AG" | j '["agent"]["db_role"]') \
RW_KEY=$(echo "$RW_AG" | j '["key"]') BAD_KEY=$(echo "$BAD_AG" | j '["key"]') INVALID="$INVALID" \
UPDB=$UPDB ROLE=$ROLE RO=$RO ROLEPW="$ROLEPW" POLICY="$POLICY" HBA="$HBA" UPPORT=$UPPORT UPSU=$UPSU W=$W HERE=$HERE PY=$PY \
  $PY "$HERE/dbrole_e2e.py" | tee "$HERE/dbrole-last-run.txt"
exit ${PIPESTATUS[0]}
