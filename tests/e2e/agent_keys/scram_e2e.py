#!/usr/bin/env python3
"""SCRAM E2E checks. Driven by scram_e2e.sh (env carries key, conn string, etc)."""
import json, os, subprocess, sys, textwrap
import psycopg

KEY, CONN, UPDB = os.environ["KEY"], os.environ["CONN"], os.environ["UPDB"]
ROLE, ROLEPW, PSQL, W, ROOT = os.environ["ROLE"], os.environ["ROLEPW"], os.environ["PSQL"], os.environ["W"], os.environ["ROOT"]
POLICY = os.environ["POLICY"]
results = []

def check(name, ok, detail=""):
    for secret in (KEY, ROLEPW):
        detail = str(detail).replace(secret, "<redacted>")
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail[:300]}]" if detail and not ok else ""))

PROXY = "127.0.0.1:15433"
dsn = f"postgresql://support-agent:{KEY}@{PROXY}/{UPDB}?sslmode=disable"

check("upstream role stored as SCRAM-SHA-256", os.environ.get("ENC", "").startswith("SCRAM-SHA-256"), os.environ.get("ENC"))

pol = json.loads(POLICY)
entry = next((k for k in pol.get("agent_keys", []) if k["agent"] == "support-agent"), {})
check("control plane syncs a SCRAM verifier (salt, 4096 iter, keys)", bool(entry.get("scram")) and entry["scram"]["iterations"] == 4096, entry)
check("raw key absent from /v1/policy", KEY not in POLICY)
check("real DB password absent from generated connection string", ROLEPW not in CONN and ROLE not in CONN, CONN)

# psql
p = subprocess.run([PSQL, dsn, "-tAc", "select current_user || '|' || current_setting('application_name')"], capture_output=True, text=True, timeout=30)
check("psql connects with key over SCRAM", p.returncode == 0 and p.stdout.strip() == f"{ROLE}|agent:support-agent:mission:default", p.stdout + p.stderr)

# psycopg3
try:
    with psycopg.connect(dsn) as c:
        u, an = c.execute("select current_user, current_setting('application_name')").fetchone()
        c.execute("update orders set status='seen' where id=1")
    check("psycopg3 connects with key over SCRAM, runs a write", u == ROLE and an == "agent:support-agent:mission:default", (u, an))
except Exception as e:
    check("psycopg3 connects with key over SCRAM, runs a write", False, e)

# pgx
gomod = f"{W}/pgxcheck"
os.makedirs(gomod, exist_ok=True)
open(f"{gomod}/main.go", "w").write(textwrap.dedent('''
    package main
    import ("context"; "fmt"; "os"; "github.com/jackc/pgx/v5")
    func main() {
        c, err := pgx.Connect(context.Background(), os.Args[1])
        if err != nil { fmt.Println("ERR", err); os.Exit(1) }
        defer c.Close(context.Background())
        var u, an string
        if err := c.QueryRow(context.Background(), "select current_user, current_setting('application_name')").Scan(&u, &an); err != nil { fmt.Println("ERR", err); os.Exit(1) }
        fmt.Println(u + "|" + an)
    }'''))
r = subprocess.run(["go", "run", "./pgxcheck", dsn], cwd=W, capture_output=True, text=True, timeout=180,
                   env={**os.environ, "GOFLAGS": "-mod=mod"}) if os.path.exists(f"{W}/go.mod") else None
if r is None:
    subprocess.run(["go", "mod", "init", "pgxcheck"], cwd=W, capture_output=True)
    subprocess.run(["go", "get", "github.com/jackc/pgx/v5@v5.7.1"], cwd=W, capture_output=True, timeout=180)
    r = subprocess.run(["go", "run", "./pgxcheck", dsn], cwd=W, capture_output=True, text=True, timeout=180)
check("pgx connects with key over SCRAM", r.returncode == 0 and r.stdout.strip() == f"{ROLE}|agent:support-agent:mission:default", r.stdout + r.stderr)

def backends():
    with psycopg.connect(f"host=127.0.0.1 port=5544 dbname={UPDB} user=ec2-user") as c:
        return c.execute("select count(*) from pg_stat_activity where usename=%s", (ROLE,)).fetchone()[0]

before = backends()
try:
    psycopg.connect(f"postgresql://support-agent:fw_ak_wrong_key@{PROXY}/{UPDB}?sslmode=disable").close()
    check("wrong key refused with 28P01", False, "connected")
except psycopg.OperationalError as e:
    msg = str(e)
    check("wrong key refused with 28P01", "wrong key" in msg and "BLOCKED by FaultWall" in msg, msg)
check("wrong key opens no upstream backend", backends() == before, f"{before} -> {backends()}")

# The key is useless directly against Postgres.
try:
    psycopg.connect(f"host=127.0.0.1 port=5544 dbname={UPDB} user=support-agent password={KEY}").close()
    check("agent key does not work directly against Postgres", False, "connected")
except psycopg.OperationalError:
    check("agent key does not work directly against Postgres", True)

log = open(f"{W}/proxy.log").read()
check("proxy log: agent authenticated via scram-sha-256", "auth=scram-sha-256" in log, log[-500:])
check("raw key never appears in proxy log", KEY not in log)
check("real DB password never appears in proxy log", ROLEPW not in log)

# Cleartext is refused by default: a client that only does cleartext gets no
# cleartext request (proxy demands SASL). Probe the first auth message raw.
import socket, struct
s = socket.create_connection(("127.0.0.1", 15433), timeout=10)
params = b"user\x00support-agent\x00database\x00" + UPDB.encode() + b"\x00\x00"
s.sendall(struct.pack("!II", 8 + len(params), 196608) + params)
t = s.recv(1); ln = struct.unpack("!I", s.recv(4))[0]; body = s.recv(ln - 4); s.close()
code = struct.unpack("!I", body[:4])[0] if t == b"R" else None
check("proxy demands SASL (code 10), never cleartext (code 3)", t == b"R" and code == 10 and b"SCRAM-SHA-256" in body and b"PLUS" not in body, (t, code, body[:40]))

n, total = sum(results), len(results)
print(f"\n{n}/{total} passed")
sys.exit(0 if n == total else 1)
