import json, sys, threading, time, urllib.request
import psycopg
from psycopg import errors

DSN = "host=127.0.0.1 port=5547 dbname=fw_appr_e2e user=ec2-user application_name=agent:support-agent:mission:e2e"
API = "http://127.0.0.1:18099/api/holds"
results = []

def decide(action, delay=1.0, reason=""):
    def run():
        time.sleep(delay)
        for _ in range(40):
            hs = json.load(urllib.request.urlopen(API))["holds"]
            if hs:
                req = urllib.request.Request(f"{API}/{hs[0]['id']}/{action}", data=json.dumps({"by": "py-e2e", "reason": reason}).encode(), method="POST")
                urllib.request.urlopen(req).read(); return
            time.sleep(0.2)
    t = threading.Thread(target=run); t.start(); return t

def status(i):
    with psycopg.connect(DSN.replace("support-agent", "reader"), autocommit=True) as c:
        return c.execute("select status from orders where id=%s", (i,)).fetchone()[0]

def check(name, ok, detail=""):
    results.append((name, ok)); print(("PASS" if ok else "FAIL"), name, detail, flush=True)

def reset():
    with psycopg.connect(DSN.replace("support-agent","reader"), autocommit=True) as c:
        c.execute("update customers set name=name")  # noop
        c.execute("select 1")

# 1 approve (extended protocol, params)
with psycopg.connect(DSN, autocommit=True) as c:
    t = decide("approve", 1.0); t0 = time.time()
    cur = c.execute("update orders set status=%s where id=%s", ("py-approved", 4))
    t.join(); check("approve", cur.rowcount == 1 and status(4) == "py-approved", f"{time.time()-t0:.1f}s")

# 2 deny, conn reusable
with psycopg.connect(DSN, autocommit=True) as c:
    t = decide("deny", 0.5, "nope")
    try:
        c.execute("update orders set status=%s where id=%s", ("py-denied", 5)); check("deny", False)
    except errors.InsufficientPrivilege as e:
        check("deny", status(5) == "open" and "denied by py-e2e" in str(e), str(e).splitlines()[0])
    t.join()
    check("deny: conn reusable", c.execute("select 42").fetchone()[0] == 42)

# 3 in-txn deny -> 25P02 on next stmt
with psycopg.connect(DSN) as c:
    c.execute("select 1")
    t = decide("deny", 0.5)
    try:
        c.execute("update orders set status=%s where id=%s", ("txn", 6)); check("txn deny", False)
    except errors.InsufficientPrivilege:
        pass
    t.join()
    try:
        c.execute("select 1"); check("txn deny -> 25P02", False)
    except errors.InFailedSqlTransaction as e:
        check("txn deny -> 25P02", e.sqlstate == "25P02")
    c.rollback()
    check("txn: rollback ok, row unchanged", c.execute("select 1").fetchone()[0] == 1 and status(6) == "open")

# 4 statement_timeout shorter than hold (extended): must NOT be cancelled by PG
with psycopg.connect(DSN, autocommit=True) as c:
    c.execute("set statement_timeout = '1s'")
    t = decide("approve", 2.5)
    try:
        cur = c.execute("update orders set status=%s where id=%s", ("st-ok", 7))
        check("statement_timeout 1s, approve at 2.5s -> runs", cur.rowcount == 1 and status(7) == "st-ok")
    except Exception as e:
        check("statement_timeout 1s, approve at 2.5s -> runs", False, repr(e))
    t.join()

# 5 prepared/cached statement (prepare=True): each execute held
with psycopg.connect(DSN, autocommit=True) as c:
    for n in range(2):
        t = decide("deny", 0.3)
        try:
            c.execute("update orders set amount=amount+1 where id=%s", (8,), prepare=True); check(f"prepared exec #{n+1} held", False)
        except errors.InsufficientPrivilege:
            check(f"prepared exec #{n+1} held+denied", True)
        t.join()

# 6 pipeline: 3 stmts, middle one held, deny
with psycopg.connect(DSN, autocommit=True) as c:
    t = decide("deny", 0.5)
    err = None
    try:
        with c.pipeline():
            c.execute("update customers set name=%s where id=%s", ("pipe1", 1))
            c.execute("update orders set status=%s where id=%s", ("pipe", 9))
            c.execute("update customers set name=%s where id=%s", ("pipe3", 2))
    except Exception as e:
        err = e
    t.join()
    check("pipeline deny raises", isinstance(err, errors.InsufficientPrivilege), repr(err)[:120])
    check("pipeline: conn reusable", c.execute("select 7").fetchone()[0] == 7)
    with psycopg.connect(DSN.replace("support-agent","reader"), autocommit=True) as r:
        names = [x[0] for x in r.execute("select name from customers order by id")]
    check("pipeline: held row unchanged", status(9) == "open", f"customers={names}")

# 7 pipeline approve
with psycopg.connect(DSN, autocommit=True) as c:
    t = decide("approve", 0.5)
    with c.pipeline():
        c.execute("update orders set status=%s where id=%s", ("pipe-ok", 10))
        c.execute("select 1")
    t.join(); check("pipeline approve", status(10) == "pipe-ok")

# 8 cancel (Ctrl-C equivalent): conn.cancel() while held -> 57014
with psycopg.connect(DSN, autocommit=True) as c:
    def canceller():
        time.sleep(1.0); c.cancel()
    th = threading.Thread(target=canceller); th.start(); t0 = time.time()
    try:
        c.execute("update orders set status=%s where id=%s", ("cancel", 3)); check("cancel", False)
    except errors.QueryCanceled as e:
        check("cancel -> 57014 fast", e.sqlstate == "57014" and time.time()-t0 < 4, f"{time.time()-t0:.1f}s {str(e).splitlines()[0]}")
    th.join()
    check("cancel: conn reusable, row unchanged", c.execute("select 1").fetchone()[0] == 1 and status(3) == "open")
    check("cancel: no pending holds left", json.load(urllib.request.urlopen(API))["holds"] == [])

# 9 client gives up (close socket) while held, then approve -> must not run
c = psycopg.connect(DSN, autocommit=True)
def killer():
    time.sleep(1.0); c.pgconn.finish()
th = threading.Thread(target=killer); th.start()
try:
    c.execute("update orders set status=%s where id=%s", ("ghost", 2))
except Exception:
    pass
th.join(); time.sleep(0.5)
hs = json.load(urllib.request.urlopen(API))["holds"]
check("client gone -> hold dropped, row unchanged", hs == [] and status(2) == "open", f"holds={len(hs)}")

fails = [n for n, ok in results if not ok]
print(f"\n{len(results)-len(fails)}/{len(results)} passed", "FAILED: "+", ".join(fails) if fails else "")
sys.exit(1 if fails else 0)
