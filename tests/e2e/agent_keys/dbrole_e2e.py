#!/usr/bin/env python3
"""db_role E2E checks. Driven by dbrole_e2e.sh."""
import json, os, subprocess, sys, time
import psycopg
from psycopg import errors

E = os.environ
RO_KEY, RW_KEY, BAD_KEY = E["RO_KEY"], E["RW_KEY"], E["BAD_KEY"]
UPDB, ROLE, RO, ROLEPW = E["UPDB"], E["ROLE"], E["RO"], E["ROLEPW"]
PROXY = "127.0.0.1:15433"
results = []

def check(name, ok, detail=""):
    detail = str(detail)
    for s in (RO_KEY, RW_KEY, BAD_KEY, ROLEPW, E.get("PGPASSWORD_UP", "\x00")):
        detail = detail.replace(s, "<redacted>")
    results.append(bool(ok))
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail[:400]}]" if detail and not ok else ""))

def dsn(agent, key):
    return f"postgresql://{agent}:{key}@{PROXY}/{UPDB}?sslmode=disable"

def expect_err(conn, sql, params=None):
    try:
        conn.execute(sql, params)
        return None
    except psycopg.Error as e:
        conn.rollback() if conn.info.transaction_status != 0 else None
        return e

check("upstream pg_hba enforces scram-sha-256 only", E.get("HBA") == "scram-sha-256", E.get("HBA"))
check("control plane rejects a non-identifier db_role (400)", E.get("INVALID") == "400", E.get("INVALID"))
check("create API returns db_role in the agent view", E.get("RO_VIEW_ROLE") == RO, E.get("RO_VIEW_ROLE"))
pol = json.loads(E["POLICY"])
roles = {k["agent"]: k.get("db_role") for k in pol.get("agent_keys", [])}
check("/v1/policy agent_keys carries db_role (only where set)", roles.get("ro-agent") == RO and roles.get("rw-agent") is None, roles)

# ── ro-agent: pinned to the SELECT-only role ──
c = psycopg.connect(dsn("ro-agent", RO_KEY), autocommit=True)
cu, su = c.execute("select current_user, session_user").fetchone()
check("ro-agent session runs as its db_role (current_user) on the proxy's login (session_user)", (cu, su) == (RO, ROLE), (cu, su))
check("ro-agent SELECT works", c.execute("select status from orders where id=1").fetchone() == ("open",))

e = expect_err(c, "update orders set status='hacked' where id=1")
check("ro-agent UPDATE fails with 42501 raised by Postgres itself (not FaultWall)",
      isinstance(e, errors.InsufficientPrivilege) and "permission denied for table orders" in str(e) and "FaultWall" not in str(e), repr(e))
e = expect_err(c, "insert into orders values (2,'x')")
check("ro-agent INSERT fails with 42501 from Postgres", isinstance(e, errors.InsufficientPrivilege) and "FaultWall" not in str(e), repr(e))

for stmt in (f"SET ROLE {ROLE}", "RESET ROLE", f"SET SESSION AUTHORIZATION {ROLE}", "DISCARD ALL", "RESET ALL",
             f"SELECT set_config('role', '{ROLE}', false)", f"BEGIN; SET LOCAL ROLE {ROLE}; UPDATE orders SET status='x' WHERE id=1; COMMIT"):
    e = expect_err(c, stmt)
    check(f"FaultWall blocks {("SET LOCAL ROLE in a txn" if stmt.startswith("BEGIN") else stmt)} (42501 'agent role is fixed')",
          isinstance(e, errors.InsufficientPrivilege) and "[BLOCKED by FaultWall] agent role is fixed" in str(e), repr(e))
# Extended protocol (bound parameter: the name isn't a constant, so it's refused)
e = expect_err(c, "SELECT set_config(%s, %s, false)", ("role", ROLE))
check("FaultWall blocks set_config('role') over the extended protocol", isinstance(e, errors.InsufficientPrivilege) and "agent role is fixed" in str(e), repr(e))
with c.cursor() as cur:
    try:
        cur.execute("RESET ROLE", prepare=True); ok = False; msg = "ran"
    except psycopg.Error as ex:
        ok, msg = "agent role is fixed" in str(ex), repr(ex)
check("FaultWall blocks a prepared RESET ROLE (Parse/Bind/Execute)", ok, msg)

cu = c.execute("select current_user").fetchone()[0]
check("connection survives the blocked attempts, still pinned", cu == RO, cu)
e = expect_err(c, "update orders set status='hacked' where id=1")
check("after the attempts the write is still refused by Postgres", isinstance(e, errors.InsufficientPrivilege) and "FaultWall" not in str(e), repr(e))
c.close()

# ── rw-agent: no db_role, can write ──
with psycopg.connect(dsn("rw-agent", RW_KEY), autocommit=True) as c2:
    cu = c2.execute("select current_user").fetchone()[0]
    c2.execute("update orders set status='seen' where id=1")
    st = c2.execute("select status from orders where id=1").fetchone()[0]
check("rw-agent (no db_role) runs as the proxy login and can write", cu == ROLE and st == "seen", (cu, st))

# ── role not granted to the proxy login: FATAL with a clear message ──
try:
    psycopg.connect(dsn("bad-role-agent", BAD_KEY)).close()
    check("db_role not granted to the proxy login: FATAL with a clear message", False, "connected")
except psycopg.OperationalError as ex:
    m = str(ex)
    check("db_role not granted to the proxy login: FATAL with a clear message",
          "could not switch agent" in m and "fw_dbrole_notgranted" in m and "permission denied to set role" in m and "GRANT" in m, m)

# ── clearing the role on the control plane ends the pinned session; reconnect runs unpinned ──
c = psycopg.connect(dsn("ro-agent", RO_KEY), autocommit=True)
st, body = subprocess.run([E["PY"], f"{E['HERE']}/cp.py", "PATCH", f"/v1/dashboard/agents/{E['RO_ID']}", '{"db_role": ""}'],
                          capture_output=True, text=True).stdout.split("\n", 1)
check("PATCH db_role \"\" clears it", st == "200" and json.loads(body)["agent"]["db_role"] == "", (st, body[:200]))
ended, err = False, ""
for _ in range(30):
    time.sleep(0.5)
    try:
        c.execute("select 1")
    except psycopg.Error as ex:
        ended, err = True, str(ex); break
check("open pinned session is ended after the role change syncs", ended and "database role" in err, err)
with psycopg.connect(dsn("ro-agent", RO_KEY), autocommit=True) as c3:
    cu = c3.execute("select current_user").fetchone()[0]
check("reconnect after clearing runs without the role", cu == ROLE, cu)

log = open(f"{E['W']}/proxy.log").read()
check("proxy log records the pin and the refused role changes", f'pinned to database role "{RO}"' in log and "role change refused" in log, log[-600:])
check("no key or DB password in the proxy log", all(s not in log for s in (RO_KEY, RW_KEY, BAD_KEY, ROLEPW)))

n, total = sum(results), len(results)
print(f"\n{n}/{total} passed")
sys.exit(0 if n == total else 1)
