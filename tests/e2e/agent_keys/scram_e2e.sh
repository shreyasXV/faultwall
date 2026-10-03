#!/usr/bin/env bash
# SCRAM E2E: real control plane + real proxy + PG16 (scram-sha-256 upstream role),
# clients psql, psycopg3, pgx. Run from this directory. Writes scram-last-run.txt.
set -uo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../.." && pwd)            # proxy repo
CPREPO=${CPREPO:-/tmp/fw-cp-keys}              # control plane worktree (feat/agent-keys)
PGBIN=${PGBIN:-/opt/homebrew/opt/postgresql@16/bin}
PY=${PY:-/tmp/fw-pyvenv/bin/python}
W=/tmp/fw-scram-e2e; rm -rf $W; mkdir -p $W/home
export GOPATH=${GOPATH:-/tmp/fw-gopath} GOMODCACHE=${GOMODCACHE:-/tmp/fw-gopath/pkg/mod}
CPDB=fw_scram_cp UPDB=fw_scram_up ROLE=fw_scram_proxy ROLEPW="upstream-$(openssl rand -hex 8)"
P="$PGBIN/psql -h 127.0.0.1 -p 5544 -q -v ON_ERROR_STOP=1"
cleanup() { [ -f $W/cp.pid ] && kill $(cat $W/cp.pid) 2>/dev/null; [ -f $W/px.pid ] && kill $(cat $W/px.pid) 2>/dev/null; sleep 1
  $PGBIN/dropdb -h 127.0.0.1 -p 5544 --if-exists $CPDB; $PGBIN/dropdb -h 127.0.0.1 -p 5544 --if-exists $UPDB
  $P -d postgres -c "DROP ROLE IF EXISTS $ROLE" >/dev/null 2>&1; }
trap cleanup EXIT
cleanup >/dev/null 2>&1

# Upstream: a scram-sha-256 role the proxy logs in as.
$PGBIN/createdb -h 127.0.0.1 -p 5544 $CPDB && $PGBIN/createdb -h 127.0.0.1 -p 5544 $UPDB
$P -d postgres -c "SET password_encryption='scram-sha-256'; CREATE ROLE $ROLE LOGIN PASSWORD '$ROLEPW'"
$P -d $UPDB -c "GRANT ALL ON SCHEMA public TO $ROLE; CREATE TABLE orders(id int primary key, status text); INSERT INTO orders VALUES (1,'open'); GRANT ALL ON orders TO $ROLE"
ENC=$($P -d postgres -Atc "select left(rolpassword,13) from pg_authid where rolname='$ROLE'" 2>/dev/null || echo "?")
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
AG=$($PY cp.py POST /v1/dashboard/agents "{\"name\":\"support-agent\",\"proxy_host\":\"127.0.0.1:15433\",\"database\":\"$UPDB\"}" | sed -n 2p)
KEY=$(echo "$AG" | $PY -c 'import json,sys; print(json.load(sys.stdin)["key"])')
CONN=$(echo "$AG" | $PY -c 'import json,sys; print(json.load(sys.stdin)["connection_string"])')
POLICY=$(curl -s -H "Authorization: Bearer $TOK" http://127.0.0.1:18091/v1/policy)

printf 'default_policy: allow\nagents: {}\n' > $W/policies.yaml
HOME=$W/home FAULTWALL_CONTROL_PLANE_URL=http://127.0.0.1:18091 FAULTWALL_CONTROL_PLANE_TOKEN=$TOK FW_POLICY_SYNC_INTERVAL=2s \
  FW_UPSTREAM_USER=$ROLE FW_UPSTREAM_PASSWORD=$ROLEPW \
  $W/faultwall --proxy --listen 127.0.0.1:15433 --upstream 127.0.0.1:5544 --policies $W/policies.yaml --mode monitor > $W/proxy.log 2>&1 & echo $! > $W/px.pid
for i in $(seq 1 40); do grep -q "agent" $W/proxy.log 2>/dev/null && nc -z 127.0.0.1 15433 && break; sleep 0.25; done
sleep 3

KEY="$KEY" CONN="$CONN" UPDB=$UPDB ROLE=$ROLE ROLEPW="$ROLEPW" POLICY="$POLICY" ENC="$ENC" PSQL=$PGBIN/psql W=$W ROOT=$ROOT \
  $PY "$HERE/scram_e2e.py" | tee "$HERE/scram-last-run.txt"
exit ${PIPESTATUS[0]}
