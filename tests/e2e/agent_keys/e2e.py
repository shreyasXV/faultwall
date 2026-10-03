#!/usr/bin/env python3
"""E2E for per-agent keys through a real FaultWall proxy + control plane.
Run with /tmp/fw-pyvenv/bin/python. Prints PASS/FAIL per check."""
import json, subprocess, sys, time, urllib.request
sys.path.insert(0, "/tmp/fwk-e2e")
import psycopg
from cp import call

PROXY = "127.0.0.1:15433"
DB = "fwk_up_scratch"
UP = "host=127.0.0.1 port=5544 dbname=fwk_up_scratch user=ec2-user"
PSQL = "/opt/homebrew/opt/postgresql@16/bin/psql"
results = []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)

def red(s, *keys):
    for k in keys:
        s = s.replace(k, "fw_ak_<redacted>")
    return s

def proxy_status():
    return json.loads(urllib.request.urlopen("http://127.0.0.1:18081/api/agent-keys").read())

def pg_labels():
    with psycopg.connect(UP) as c:
        return [r[0] for r in c.execute("SELECT application_name FROM pg_stat_activity WHERE datname=%s AND application_name LIKE 'agent:%%'", (DB,))]

key1 = open("/tmp/fwk-e2e/key1").read().strip()
dsn1 = f"postgresql://support-agent:{key1}@{PROXY}/{DB}"

# 1. psycopg3, key as password: connects, labeled upstream.
with psycopg.connect(dsn1) as c:
    who = c.execute("SELECT current_user, current_setting('application_name')").fetchone()
    labels = pg_labels()
    n = c.execute("SELECT count(*) FROM orders").fetchone()[0]
check("psycopg3 key-as-password connects + reads", n == 5, f"rows={n}")
check("session labeled upstream as agent:support-agent:mission:default",
      who[1] == "agent:support-agent:mission:default" and "agent:support-agent:mission:default" in labels,
      f"current_user={who[0]} application_name={who[1]}")
check("key never reaches Postgres (not in pg_stat_activity)", not any(key1 in l for l in labels))

# 2. writes=ask-first on a no-hold proxy => runs but is flagged, never blocked.
with psycopg.connect(dsn1, autocommit=True) as c:
    c.execute("UPDATE orders SET status='refunded' WHERE id=1")
    st = c.execute("SELECT status FROM orders WHERE id=1").fetchone()[0]
check("write with writes=hold compiles to flag: runs (enforce mode)", st == "refunded")
log = open("/tmp/fwk-e2e/proxy.log").read()
check("write flagged as needs_approval in proxy log", "needs_approval:support-agent-writes-ask-first" in log)

# 3. ddl=block => refused.
try:
    with psycopg.connect(dsn1, autocommit=True) as c:
        c.execute("DROP TABLE orders")
    check("DDL blocked", False, "DROP ran!")
except psycopg.Error as e:
    check("DDL blocked", "BLOCKED by FaultWall" in str(e), str(e).strip()[:90])

# 4. psql with the same connection string.
p = subprocess.run([PSQL, dsn1, "-tAc", "select current_setting('application_name')"], capture_output=True, text=True, timeout=20)
check("psql key-as-password connects + labeled", p.returncode == 0 and p.stdout.strip() == "agent:support-agent:mission:default", red(p.stdout.strip() + p.stderr.strip(), key1))

# 5. key as application_name token (agent keeps real DB creds).
with psycopg.connect(f"host=127.0.0.1 port=15433 dbname={DB} user=ec2-user application_name=agent:support-agent:mission:triage:token:{key1}") as c:
    an = c.execute("SELECT current_setting('application_name')").fetchone()[0]
check("key as application_name token: verified + stripped", an == "agent:support-agent:mission:triage", an)

# 6. wrong key / missing key / spoofed name.
def refused(dsn, needle):
    try:
        psycopg.connect(dsn).close()
        return False, "connected!"
    except psycopg.OperationalError as e:
        m = str(e).strip().splitlines()[-1]
        return needle in str(e), red(m, key1)
ok, m = refused(f"postgresql://support-agent:fw_ak_bogus@{PROXY}/{DB}", "unknown agent key"); check("unknown key refused at startup", ok, m)
ok, m = refused(f"host=127.0.0.1 port=15433 dbname={DB} user=ec2-user application_name=agent:support-agent:mission:x", "needs its key"); check("managed agent name without key refused (no spoofing)", ok, m)

# 7. legacy identity still works.
with psycopg.connect(f"host=127.0.0.1 port=15433 dbname={DB} user=ec2-user application_name=agent:legacy-bot:mission:m") as c:
    n = c.execute("SELECT count(*) FROM orders").fetchone()[0]
check("legacy application_name identity (backward compat)", n == 5)

# 8. policy sync picks up a NEW agent within one sync interval.
interval = 3.0
st, out = call("POST", "/v1/dashboard/agents", {"name": "analytics", "proxy_host": PROXY, "database": DB, "writes": "block"})
d = json.loads(out); key2 = d["key"]; aid2 = d["agent"]["id"]
t0 = time.time(); seen = None
while time.time() - t0 < interval * 2 + 2:
    try:
        psycopg.connect(d["connection_string"]).close(); seen = time.time() - t0; break
    except psycopg.OperationalError:
        time.sleep(0.25)
check(f"new agent usable within one sync interval ({interval:.0f}s)", seen is not None and seen <= interval + 1.0, f"took {seen:.2f}s" if seen else "never")
with psycopg.connect(d["connection_string"], autocommit=True) as c:
    try:
        c.execute("INSERT INTO orders(status,total_cents) VALUES ('x',1)"); check("analytics writes=block refused", False)
    except psycopg.Error as e:
        check("analytics writes=block refused", "BLOCKED" in str(e), str(e).strip()[:80])

# 9. toggle update propagates: analytics writes block -> allow.
call("PATCH", f"/v1/dashboard/agents/{aid2}", {"writes": "allow"})
time.sleep(interval + 1)
with psycopg.connect(d["connection_string"], autocommit=True) as c:
    c.execute("INSERT INTO orders(status,total_cents) VALUES ('from-analytics',1)")
    n = c.execute("SELECT count(*) FROM orders WHERE status='from-analytics'").fetchone()[0]
check("toggle change (writes block->allow) applied after sync", n == 1)

# 10. revoke: a live session is unaffected, new connections are refused.
st, out = call("POST", f"/v1/dashboard/agents/{aid2}/revoke", {})
check("revoke endpoint", st == 200 and json.loads(out)["agent"]["status"] == "revoked")
time.sleep(interval + 1)
ok, m = refused(d["connection_string"], "was revoked"); check("revoked key refused (key as password)", ok, red(m, key2))
p = subprocess.run([PSQL, d["connection_string"], "-tAc", "select 1"], capture_output=True, text=True, timeout=20)
check("revoked key refused (psql)", p.returncode != 0 and "revoked" in p.stderr, red(p.stderr.strip().splitlines()[-1] if p.stderr else "", key2))
ok, m = refused(f"host=127.0.0.1 port=15433 dbname={DB} user=ec2-user application_name=agent:analytics:mission:m:token:{key2}", "was revoked"); check("revoked key refused (key as token)", ok, red(m, key2))
s = proxy_status()
check("proxy status shows only live agents", sorted(s["agents"]) == ["support-agent"], json.dumps({k: s[k] for k in ("agents", "keys", "last_error")}))

print(f"\n{sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
