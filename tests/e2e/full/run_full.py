#!/usr/bin/env python3
"""Full product E2E: hosted control plane + customer proxy + real Postgres.
connect agent -> read -> blocked DDL -> held write approved in app -> held write denied
-> policy change in app enforced after sync -> activity/audit visible -> key revoked -> refused.
"""
import base64, hashlib, hmac, json, os, subprocess, sys, threading, time, urllib.request, urllib.error
import psycopg

E = os.path.dirname(os.path.abspath(__file__))
SECRET = b"e2e-secret-e2e-secret-e2e-secret-e2e-secret"
CP = "http://127.0.0.1:18091"
PGB = "/opt/homebrew/opt/postgresql@16/bin"
UP_PORT, PROXY_PORT, API_PORT = 55999, 15499, 18093
procs, results = [], []

def check(name, ok, detail=""):
    results.append(ok)
    print(("PASS " if ok else "FAIL ") + name + (f"  [{detail}]" if detail else ""), flush=True)

def b64(b): return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
def jwt():
    h = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    p = b64(json.dumps({"sub": "e2e-user-0001", "email": "e2e@faultwall.test", "aud": "authenticated",
                        "role": "authenticated", "exp": int(time.time()) + 3600, "iat": int(time.time())}).encode())
    return f"{h}.{p}.{b64(hmac.new(SECRET, f'{h}.{p}'.encode(), hashlib.sha256).digest())}"

def call(method, path, body=None):
    req = urllib.request.Request(CP + path, method=method,
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Authorization": "Bearer " + jwt(), "Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            t = r.read().decode(); return r.status, (json.loads(t) if t.strip().startswith(("{", "[")) else t)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()

def start(cmd, env, log):
    p = subprocess.Popen(cmd, env={**os.environ, **env}, stdout=open(log, "w"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL)
    procs.append(p); return p

def wait_http(url, t=20):
    for _ in range(t * 4):
        try: urllib.request.urlopen(url, timeout=1); return True
        except urllib.error.HTTPError: return True
        except Exception: time.sleep(0.25)
    return False

try:
    # 1. hosted control plane
    start([f"{E}/cp"], {"FWCP_LISTEN": "127.0.0.1:18091", "FWCP_ENV": "dev",
          "FWCP_DATABASE_URL": f"postgres://postgres@127.0.0.1:{UP_PORT}/fwcp2?sslmode=disable",
          "FWCP_GOTRUE_JWT_SECRET": SECRET.decode(), "FWCP_PUBLIC_BASE_URL": CP}, f"{E}/cp.log")
    check("control plane up (/healthz)", wait_http(CP + "/healthz"))
    st, prov = call("POST", "/v1/dashboard/provision", {}); check("sign-up provisions a workspace", st in (200, 201), str(st))
    st, tok = call("POST", "/v1/dashboard/tokens", {"name": "e2e-proxy"})
    token = tok.get("token") if isinstance(tok, dict) else None
    check("install token issued", bool(token), str(st))
    st, ag = call("POST", "/v1/dashboard/agents", {"name": "support-agent", "reads": "allow", "writes": "hold", "ddl": "block",
                  "proxy_host": f"127.0.0.1:{PROXY_PORT}", "database": "shop2"})
    key = ag.get("key") if isinstance(ag, dict) else None
    agent_id = ag.get("agent", {}).get("id") if isinstance(ag, dict) and isinstance(ag.get("agent"), dict) else (ag.get("id") if isinstance(ag, dict) else None)
    check("agent created in app, key shown once", bool(key), f"status={st} id={agent_id}")

    # 2. customer-side proxy, pulls policy + keys from control plane
    open(f"{E}/policies.yaml", "w").write("default_policy: allow\nunidentified:\n  policy: deny\nagents: {}\n")
    os.makedirs(f"{E}/home", exist_ok=True)
    start([f"{E}/faultwall", "--proxy", "--listen", f"127.0.0.1:{PROXY_PORT}", "--upstream", f"127.0.0.1:{UP_PORT}",
           "--policies", f"{E}/policies.yaml", "--mode", "enforce"],
          {"HOME": f"{E}/home", "FAULTWALL_CONTROL_PLANE_URL": CP, "FAULTWALL_CONTROL_PLANE_TOKEN": token or "",
           "FW_POLICY_SYNC_INTERVAL": "3s", "FW_UPSTREAM_USER": "fwproxy", "FW_UPSTREAM_PASSWORD": "proxypw",
           "PORT": str(API_PORT), "BIND_ADDR": "127.0.0.1", "FAULTWALL_TELEMETRY": "true", "FW_HOLD_TIMEOUT": "20",
           "FW_BYPASS_DETECTION": "false"}, f"{E}/proxy.log")
    time.sleep(6)
    dsn = f"postgresql://support-agent:{key}@127.0.0.1:{PROXY_PORT}/shop2?sslmode=disable"

    # 3. reads work
    try:
        with psycopg.connect(dsn, autocommit=True) as c:
            n = c.execute("select count(*) from orders").fetchone()[0]
        check("agent connects with its key and reads", n == 2, f"rows={n}")
    except Exception as e:
        check("agent connects with its key and reads", False, str(e)[:200])

    # 4. DDL blocked
    try:
        with psycopg.connect(dsn, autocommit=True) as c: c.execute("drop table tickets")
        check("DROP TABLE blocked by policy", False, "ran!")
    except Exception as e:
        check("DROP TABLE blocked by policy", "BLOCKED" in str(e) or "FaultWall" in str(e), str(e).splitlines()[0][:160])

    # 5. write held -> approved in the app -> runs
    def held_write(sql, out):
        try:
            with psycopg.connect(dsn, autocommit=True) as c:
                t0 = time.time(); c.execute(sql); out["ok"] = True; out["secs"] = round(time.time() - t0, 1)
        except Exception as e: out["err"] = str(e).splitlines()[0][:200]
    def pending():
        st, h = call("GET", "/v1/dashboard/holds?status=pending")
        items = h.get("holds", h) if isinstance(h, dict) else h
        return [x for x in (items or []) if isinstance(x, dict) and x.get("status") == "pending"]

    out = {}; th = threading.Thread(target=held_write, args=("update orders set total = 99 where id = 1", out)); th.start()
    hp = []
    for _ in range(40):
        hp = pending()
        if hp: break
        time.sleep(0.25)
    check("UPDATE pauses and appears in the app's approval queue", bool(hp), f"pending={len(hp)}")
    shape = hp[0].get("query") or hp[0].get("query_text") if hp else ""
    check("approver sees shape only, no values", bool(hp) and "99" not in (shape or ""), f"shape={shape!r}")
    if hp:
        st, _ = call("POST", f"/v1/dashboard/holds/{hp[0]['id']}/approve", {}); check("approve in app", st == 200, str(st))
    th.join(25)
    with psycopg.connect(f"host=127.0.0.1 port={UP_PORT} dbname=shop2 user=postgres") as c:
        v = c.execute("select total from orders where id=1").fetchone()[0]
    check("approved write ran on the database", out.get("ok") and int(v) == 99, f"{out} total={v}")

    # 6. write held -> denied -> never runs
    out = {}; th = threading.Thread(target=held_write, args=("delete from orders where id = 2", out)); th.start()
    for _ in range(40):
        hp = pending()
        if hp: break
        time.sleep(0.25)
    if hp: call("POST", f"/v1/dashboard/holds/{hp[0]['id']}/deny", {})
    th.join(25)
    with psycopg.connect(f"host=127.0.0.1 port={UP_PORT} dbname=shop2 user=postgres") as c:
        cnt = c.execute("select count(*) from orders where id=2").fetchone()[0]
    check("denied write never runs, agent gets a clear error", "err" in out and cnt == 1, out.get("err", "")[:160])

    # 7. policy change in app -> enforced after sync
    st, _ = call("PATCH", f"/v1/dashboard/agents/{agent_id}", {"writes": "block"})
    time.sleep(5)
    try:
        with psycopg.connect(dsn, autocommit=True) as c: c.execute("update orders set total = 1 where id = 1")
        check("policy change (writes -> block) enforced after sync", False, "ran")
    except Exception as e:
        check("policy change (writes -> block) enforced after sync", "BLOCKED" in str(e), str(e).splitlines()[0][:160])

    # 8. audit + activity
    st, au = call("GET", "/v1/dashboard/holds/audit"); s = json.dumps(au)
    check("approval audit trail records approve + deny", st == 200 and "approved" in s and "denied" in s, f"status={st} len={len(s)}")
    time.sleep(3)
    st, act = call("GET", "/v1/dashboard/activity/summary"); check("activity summary served", st == 200, f"{st} {json.dumps(act)[:200]}")

    # 9. revoke key -> refused
    call("POST", f"/v1/dashboard/agents/{agent_id}/revoke", {})
    time.sleep(5)
    try:
        psycopg.connect(dsn).close(); check("revoked key refused", False, "connected")
    except Exception as e:
        check("revoked key refused", "revoked" in str(e).lower() or "BLOCKED" in str(e), str(e).splitlines()[0][:160])
finally:
    for p in procs: p.terminate()
    print(f"\n{sum(results)}/{len(results)} passed")
