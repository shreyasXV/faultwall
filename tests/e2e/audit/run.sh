#!/usr/bin/env bash
# tests/e2e/audit/run.sh: end-to-end check of `faultwall audit` and --fix.
#
# Needs a local Postgres with a superuser (trust auth is fine) and psql.
#   PGHOST=127.0.0.1 PGPORT=5544 PGUSER=ec2-user tests/e2e/audit/run.sh
#
# Creates scratch databases fwa_scratch / fwa_scratch_copy / fwa_scratch500 and
# roles fwa_* / fw_agent_e2e*, and drops them all on exit. Writes the log to
# tests/e2e/audit/last-run.txt.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/../../.." && pwd)"
LOG="$HERE/last-run.txt"
export PGHOST="${PGHOST:-127.0.0.1}" PGPORT="${PGPORT:-5544}" PGUSER="${PGUSER:-ec2-user}"
PATH="/opt/homebrew/opt/postgresql@16/bin:$PATH"
BIN="${FW_BIN:-/tmp/fw-audit-e2e/faultwall}"
TMP="$(mktemp -d /tmp/fw-audit-e2e.XXXXXX)"
exec > >(tee "$LOG") 2>&1

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "PASS  $*"; }
bad()  { FAIL=$((FAIL+1)); echo "FAIL  $*"; }
check(){ local d="$1"; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
has()  { grep -qF -- "$2" "$1"; }
P()    { psql -X -q -v ON_ERROR_STOP=1 "$@"; }
now()  { perl -MTime::HiRes=time -e 'printf "%.3f", time'; }
since(){ perl -e "printf '%.2f', $(now) - $1"; }

cleanup() {
  P -d postgres -c "DROP DATABASE IF EXISTS fwa_scratch WITH (FORCE)" \
    -c "DROP DATABASE IF EXISTS fwa_scratch_copy WITH (FORCE)" \
    -c "DROP DATABASE IF EXISTS fwa_scratch500 WITH (FORCE)" >/dev/null 2>&1
  for r in fw_agent_e2e fw_agent_e2e_w fwa_app_user fwa_admin fwa_proxy fwa_readers fwa_big; do
    P -d postgres -c "DROP ROLE IF EXISTS $r" >/dev/null 2>&1
  done
  rm -rf "$TMP"
}
trap cleanup EXIT

T0=$(now)
echo "faultwall audit e2e  $(date -u +%Y-%m-%dT%H:%M:%SZ)  postgres=$PGHOST:$PGPORT"
echo "git $(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null)"

echo "== build"
mkdir -p "$(dirname "$BIN")"
( cd "$ROOT" && go build -o "$BIN" . ) || { echo "build failed"; exit 1; }
echo "server: $(P -d postgres -Atc 'select version()')"

echo "== fixture"
cleanup; TMP="$(mktemp -d /tmp/fw-audit-e2e.XXXXXX)"
P -d postgres -c "CREATE DATABASE fwa_scratch" || exit 1
DBLINK=0
if P -d fwa_scratch -c "CREATE EXTENSION dblink" 2>/dev/null; then DBLINK=1; fi
P -d fwa_scratch -f "$HERE/fixture.sql" || exit 1
echo "dblink installed: $DBLINK"
URL="postgres://fwa_app_user@$PGHOST:$PGPORT/fwa_scratch?sslmode=disable"
ADMIN_URL="postgres://$PGUSER@$PGHOST:$PGPORT/fwa_scratch?sslmode=disable"
P -d fwa_scratch -Atc "select count(*) from pg_tables where schemaname in ('public','billing')" | sed 's/^/tables in fixture: /'

# no-network sandbox: deny all outbound except the database port
SB=""
if command -v sandbox-exec >/dev/null 2>&1; then
  cat > "$TMP/nonet.sb" <<EOF
(version 1)
(allow default)
(deny network-outbound)
(allow network-outbound (remote ip "localhost:$PGPORT"))
(allow network-outbound (remote unix-socket))
EOF
  SB="sandbox-exec -f $TMP/nonet.sb"
  if $SB curl -sS -m 5 -o /dev/null https://example.com 2>/dev/null; then
    bad "sandbox blocks outbound network (curl to example.com got through)"
  else
    ok "sandbox blocks outbound network (curl to example.com refused)"
  fi
else
  echo "note: sandbox-exec not available, network-off run skipped (code-level test still applies)"
fi
NOPROXY_ENV=(env HTTP_PROXY=http://127.0.0.1:9 HTTPS_PROXY=http://127.0.0.1:9 http_proxy=http://127.0.0.1:9 https_proxy=http://127.0.0.1:9 ALL_PROXY=http://127.0.0.1:9 NO_PROXY= no_proxy=)

echo "== read-only: schema + grants snapshot before"
snap() { pg_dump -d fwa_scratch -s --no-comments | grep -vE '^-- Dumped|^\\(un)?restrict ' > "$1"; P -d fwa_scratch -Atc "select string_agg(rolname||':'||rolsuper||rolbypassrls||rolcanlogin, ',' order by rolname) from pg_roles where rolname like 'fw%'" >> "$1"; P -d fwa_scratch -Atc "select string_agg(t, ',') from (select count(*)::text t from users union all select count(*)::text from orders union all select count(*)::text from tickets) s" >> "$1"; }
snap "$TMP/before.sql"

echo "== faultwall audit (as fwa_app_user, network off, HTTP proxy vars pointed at a dead port)"
t=$(now)
"${NOPROXY_ENV[@]}" $SB "$BIN" audit "$URL" > "$TMP/out.txt" 2> "$TMP/err.txt"; rc=$?
AUDIT_SECS=$(since "$t")
check "audit exits 0 with network off + proxy vars set (rc=$rc, ${AUDIT_SECS}s)" test "$rc" = 0
cat "$TMP/err.txt"
echo "----- output -----"; cat "$TMP/out.txt"; echo "------------------"
O="$TMP/out.txt"
check "summary: DELETE on 42 of 43 tables, UPDATE 42, INSERT 42, TRUNCATE 42" has "$O" "fwa_app_user can DELETE on 42 of 43 tables, UPDATE 42, INSERT 42, TRUNCATE 42, and read 4 secret columns (users.password_hash, api_tokens.token, customers.ssn, +1 more)."
check "summary: owns 40 (can ALTER/DROP), 1 view reads secret columns" has "$O" "Owns 40 (can ALTER/DROP). 1 view reads secret columns."
check "summary: superuser/bypass RLS line" has "$O" "Superuser: no. Bypasses RLS: no. Create role: no. Create DB: no. Replication: no."
check "summary is the first block (3 lines after the header)" bash -c "sed -n '4p' '$O' | grep -qx Summary && sed -n '7p' '$O' | grep -q '^  Superuser: no'"
check "secret columns listed schema.table.column" has "$O" "Can SELECT 4 secret-looking columns: public.users.password_hash, public.api_tokens.token, public.customers.ssn, billing.invoices.card_token."
check "billing.invoices.card_token readable via inherited role fwa_readers" has "$O" "billing.invoices.card_token: SELECT"
check "view over users.password_hash listed" has "$O" "public.user_logins reads public.users.password_hash"
check "RLS on tenant_notes reported as not applied (owner)" has "$O" "RLS is on for 1 table but does not apply to fwa_app_user on 1: public.tenant_notes (owner)."
check "CREATE in schema public reported" has "$O" "Can CREATE objects (tables, functions) in schema public."
check "membership in fwa_readers shown" has "$O" "member of: fwa_readers"
if [ "$DBLINK" = 1 ]; then
  check "dblink* reported as executable (own-session signal functions not flagged)" has "$O" "Can EXECUTE 1 dangerous function: dblink*."
  check "dblink extension reported" has "$O" "Extensions that reach outside the database are installed: dblink."
fi
check "label: enforced by Postgres" has "$O" "(enforced by Postgres)"
check "label: not enforced by audit or Postgres grants" has "$O" "Not enforced by audit or Postgres grants (what the FaultWall proxy does today, and what is planned)"
check "no claim of Faultwall enforcement in report" bash -c "! grep -q 'enforced by Faultwall' '$O'"
check "approval marked planned" has "$O" "Planned in the FaultWall app, not in this release: writes that pause until a person approves."
for c in "Writes without a WHERE clause" "Row-count caps" "Approval before a write" "Per-agent identity on a shared login" "Query-shape rules"; do
  check "Faultwall control listed: $c" has "$O" "  - $c"
done
check "last line is the one CTA" bash -c "[ \"\$(tail -n1 '$O')\" = \"Want this for your agent's real traffic? Free 48h read: https://faultwall.com\" ]"
check "CTA URL appears exactly once" bash -c "[ \$(grep -c 'Free 48h read: https://faultwall.com' '$O') = 1 ]"
check "no em/en dashes" bash -c "! LC_ALL=C grep -q \$'\xe2\x80\x94\|\xe2\x80\x93' '$O'"
check "no hype words" bash -c "! grep -qiwE 'comprehensive|robust|seamless|seamlessly|powerful|effortless|cutting-edge|revolutionary' '$O'"
check "no emoji (ASCII only)" bash -c "! LC_ALL=C grep -q '[^ -~]' '$O'"
check "under 60s on the fixture" perl -e "exit !($AUDIT_SECS < 60)"

echo "== --role (connect as admin, check fwa_app_user)"
"$BIN" audit "$ADMIN_URL" --role fwa_app_user > "$TMP/role.txt" 2>&1
check "--role gives the same summary as connecting as the role" has "$TMP/role.txt" "fwa_app_user can DELETE on 42 of 43 tables, UPDATE 42, INSERT 42, TRUNCATE 42, and read 4 secret columns"
check "--role says which login it connected as" has "$TMP/role.txt" "Connected as $PGUSER, checking role fwa_app_user."

echo "== DATABASE_URL"
DATABASE_URL="$URL" "$BIN" audit > "$TMP/env.txt" 2>&1
check "uses DATABASE_URL when no URL is given" has "$TMP/env.txt" "fwa_app_user can DELETE on 42 of 43 tables"

echo "== --json"
"${NOPROXY_ENV[@]}" $SB "$BIN" audit "$URL" --json > "$TMP/out.json" 2>&1
check "--json is valid and has the same numbers" python3 - "$TMP/out.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
s = d["summary"]
ok = (d["schema_version"] == 1 and d["role"]["name"] == "fwa_app_user" and s["tables"] == 43 and s["delete"] == 42
      and s["truncate"] == 42 and s["owned"] == 40 and s["secret_columns_readable"] == 4 and s["sensitive_views_readable"] == 1
      and d["cta"].endswith("https://faultwall.com")
      and all(f["label"] in ("enforced by Postgres", "not enforced by audit or Postgres grants") for f in d["findings"])
      and all(f.get("availability") in ("proxy", "partial", "planned") for f in d["findings"] if f["enforced_by"] == "faultwall"))
sys.exit(0 if ok else 1)
PY

echo "== --fix"
"${NOPROXY_ENV[@]}" $SB "$BIN" audit "$URL" --fix --agent e2e > "$TMP/fix.sql" 2>&1; rc=$?
check "--fix exits 0 (rc=$rc)" test "$rc" = 0
echo "----- fix.sql -----"; cat "$TMP/fix.sql"; echo "-------------------"
F="$TMP/fix.sql"
check "--fix has the Rev 4 header" has "$F" "Generates the database privileges that can be represented natively, and identifies controls that still require Faultwall."
check "--fix has the 'Not enforced by audit or this generated role' section" has "$F" "-- Not enforced by audit or this generated role"
check "--fix labels the Agents-page path as planned" has "$F" "NOLOGIN (below) is for the planned FaultWall app"
check "--fix keeps the direct-Postgres alternative" has "$F" "Available now: for an agent that connects to Postgres directly"
check "--fix: NOLOGIN role" has "$F" "CREATE ROLE fw_agent_e2e NOLOGIN;"
check "--fix: column grant leaves out password_hash" has "$F" "GRANT SELECT (id, email, name, created_at) ON public.users TO fw_agent_e2e;  -- leaves out password_hash"
check "--fix: quotes weird names" has "$F" 'GRANT SELECT ON public."Weird Table" TO fw_agent_e2e;'
check "--fix: never REVOKE / ALTER / DROP (anywhere, comments included)" bash -c "! grep -qiE 'REVOKE|ALTER|DROP' '$F'"
check "--fix: no grant to an existing role" bash -c "! grep -E '^GRANT' '$F' | grep -qE 'TO (fwa_app_user|fwa_admin|fwa_readers|fwa_proxy)'"
check "--fix: no write grants by default" bash -c "! grep -E '^GRANT' '$F' | grep -qE 'INSERT|UPDATE|DELETE'"
check "--fix lists rights inherited through PUBLIC (dblink), without REVOKE" has "$F" "-- Still inherited through PUBLIC (affects every role, review with your DBA)"
check "--fix names dblink* under PUBLIC" bash -c "grep -A6 'Still inherited through PUBLIC' '$F' | grep -q 'dblink\\*'"
check "--fix control section describes the new role" has "$F" "Postgres grants can't express these for fw_agent_e2e. Each line says what the FaultWall proxy does today and what is planned:"
check "--fix Faultwall section does not describe the audited role" bash -c "! grep -q 'fwa_app_user can UPDATE or DELETE every row' '$F'"
check "--fix notes SELECT * fails on column-granted tables" has "$F" "SELECT * fails for fw_agent_e2e (permission denied)."

"$BIN" audit "$URL" --fix --agent e2e_w --writes tickets --proxy-role fwa_proxy > "$TMP/fixw.sql" 2>&1
check "--fix --writes tickets grants writes on tickets only" bash -c "grep -q '^GRANT INSERT, UPDATE, DELETE ON public.tickets TO fw_agent_e2e_w;' '$TMP/fixw.sql' && [ \$(grep -cE '^GRANT (INSERT|DELETE)' '$TMP/fixw.sql') = 1 ]"
check "--fix --proxy-role grants the new role to the proxy login" has "$TMP/fixw.sql" "GRANT fw_agent_e2e_w TO fwa_proxy;"
"$BIN" audit "$URL" --fix --new-role fwa_readers > "$TMP/fixexist.txt" 2>&1
check "--fix refuses a role name that already exists" has "$TMP/fixexist.txt" "already exists"

echo "== read-only: snapshot after"
snap "$TMP/after.sql"
check "target DB unchanged by audit (schema, grants, roles, rows)" cmp -s "$TMP/before.sql" "$TMP/after.sql"
check "no fw_agent role was created by --fix" bash -c "[ -z \"\$(psql -X -d postgres -Atc \"select 1 from pg_roles where rolname like 'fw_agent_e2e%'\")\" ]"

echo "== apply --fix to a scratch copy and test the new role"
P -d postgres -c "CREATE DATABASE fwa_scratch_copy TEMPLATE fwa_scratch" || bad "copy db"
P -d fwa_scratch_copy -f "$F" >/dev/null && ok "fix.sql applies cleanly" || bad "fix.sql applies cleanly"
P -d fwa_scratch_copy -f "$TMP/fixw.sql" >/dev/null && ok "fixw.sql applies cleanly" || bad "fixw.sql applies cleanly"
check "new role can SELECT non-secret columns of users" bash -c "[ \"\$(psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT count(*) FROM (SELECT id, email, name FROM users) s' 2>&1)\" = 2 ]"
check "new role can SELECT a plain table" bash -c "[ \"\$(psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT count(*) FROM orders' 2>&1)\" = 2 ]"
check "new role can SELECT the weird table" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT count(*) FROM \"Weird Table\"' >/dev/null 2>&1"
check "new role can't SELECT users.password_hash" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT password_hash FROM users' 2>&1 | grep -q 'permission denied'"
check "new role can't SELECT * FROM users" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT * FROM users' 2>&1 | grep -q 'permission denied'"
check "new role can't read the view over password_hash" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT * FROM user_logins' 2>&1 | grep -q 'permission denied'"
check "new role can't SELECT api_tokens.token / billing.invoices.card_token" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT token FROM api_tokens' 2>&1 | grep -q 'permission denied' && psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'SELECT card_token FROM billing.invoices' 2>&1 | grep -q 'permission denied'"
check "new role can't DELETE" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'DELETE FROM orders' 2>&1 | grep -q 'permission denied'"
check "new role can't UPDATE / TRUNCATE / DROP" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'UPDATE tickets SET status = 1::text' 2>&1 | grep -q 'permission denied' && psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'TRUNCATE filler_01' 2>&1 | grep -q 'permission denied' && psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'DROP TABLE filler_01' 2>&1 | grep -q 'must be owner'"
check "new role can't CREATE in public" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c 'CREATE TABLE x (i int)' 2>&1 | grep -q 'permission denied'"
check "the PUBLIC listing is true: new role can really EXECUTE dblink" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e' -c \"SELECT has_function_privilege('dblink(text,text)', 'EXECUTE')\" 2>&1 | grep -qx t"
check "--writes role can INSERT/DELETE on tickets" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e_w' -c \"INSERT INTO tickets (subject, body, status) VALUES ('s','b','open')\" -c 'DELETE FROM tickets WHERE id = 1' >/dev/null 2>&1"
check "--writes role still can't DELETE on orders" bash -c "psql -X -q -At -d fwa_scratch_copy -c 'SET ROLE fw_agent_e2e_w' -c 'DELETE FROM orders' 2>&1 | grep -q 'permission denied'"
check "proxy login can switch to the --writes role" bash -c "psql -X -q -At -d fwa_scratch_copy -U fwa_proxy -c 'SET ROLE fw_agent_e2e_w' -c 'SELECT current_user' 2>&1 | grep -qx fw_agent_e2e_w"
check "the shared app user still works after --fix (nothing revoked)" bash -c "[ \"\$(psql -X -q -At -d fwa_scratch_copy -U fwa_app_user -c 'SELECT count(*) FROM users' 2>&1)\" = 2 ]"
P -d fwa_scratch_copy -c "DROP OWNED BY fw_agent_e2e, fw_agent_e2e_w" >/dev/null 2>&1
P -d postgres -c "DROP DATABASE fwa_scratch_copy" -c "DROP ROLE fw_agent_e2e" -c "DROP ROLE fw_agent_e2e_w" >/dev/null 2>&1

echo "== 500-table scale"
P -d postgres -c "CREATE DATABASE fwa_scratch500" -c "CREATE ROLE fwa_big LOGIN" >/dev/null
t=$(now)
P -d fwa_scratch500 -c "GRANT CREATE ON SCHEMA public TO fwa_big" -c "SET ROLE fwa_big" -c "DO \$\$ BEGIN FOR i IN 1..500 LOOP
  EXECUTE format('CREATE TABLE t_%s (id serial PRIMARY KEY, name text, email text, note text, amount numeric, created_at timestamptz, %s text)', i,
    CASE WHEN i % 10 = 0 THEN 'password_hash' WHEN i % 10 = 1 THEN 'api_token' ELSE 'col_' || i END);
  IF i % 25 = 0 THEN EXECUTE format('CREATE VIEW v_%s AS SELECT * FROM t_%s', i, i); END IF;
END LOOP; END \$\$" >/dev/null
echo "generated 500 tables + 20 views in $(since "$t")s"
t=$(now)
"${NOPROXY_ENV[@]}" $SB "$BIN" audit "postgres://fwa_big@$PGHOST:$PGPORT/fwa_scratch500?sslmode=disable" > "$TMP/big.txt" 2>&1; rc=$?
BIG_SECS=$(since "$t")
head -6 "$TMP/big.txt"
t=$(now)
"$BIN" audit "postgres://fwa_big@$PGHOST:$PGPORT/fwa_scratch500?sslmode=disable" --fix > "$TMP/bigfix.sql" 2>&1
BIGFIX_SECS=$(since "$t")
check "500 tables: audit exits 0 (rc=$rc)" test "$rc" = 0
check "500 tables: summary counts 500 tables" has "$TMP/big.txt" "fwa_big can DELETE on 500 of 500 tables"
check "500 tables: audit under 60s (${BIG_SECS}s)" perl -e "exit !($BIG_SECS < 60)"
check "500 tables: --fix under 60s (${BIGFIX_SECS}s)" perl -e "exit !($BIGFIX_SECS < 60)"
echo "500-table audit wall time: ${BIG_SECS}s, --fix: ${BIGFIX_SECS}s"

echo
echo "== result: $PASS passed, $FAIL failed. fixture audit ${AUDIT_SECS}s, 500-table audit ${BIG_SECS}s, total e2e $(since "$T0")s"
[ "$FAIL" = 0 ]
