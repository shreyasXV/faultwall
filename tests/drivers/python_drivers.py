import asyncio, json, sys, time, urllib.request
import psycopg, psycopg2, asyncpg, sqlalchemy as sa

P = "127.0.0.1:6433"
def url(agent, scheme="postgresql"):
    return f"{scheme}://postgres:faultwall-demo@{P}/demo?sslmode=disable&application_name=agent:{agent}:mission:default"

res = {}
def run(name, fn):
    try:
        fn(); res[name] = "PASS"
    except Exception as e:
        res[name] = f"FAIL {type(e).__name__}: {e}"

def psycopg3_simple():
    with psycopg.connect(url("py3-simple")) as c:
        c.execute("select count(*) from orders").fetchone()
        c.execute("update orders set status=status where id=%s", (1,))
        c.commit()

def psycopg3_prepared():
    with psycopg.connect(url("py3-prepared"), prepare_threshold=0) as c:
        for i in range(10):
            c.execute("select id from orders where id=%s", (i + 1,)).fetchall()

def psycopg3_pipeline():
    with psycopg.connect(url("py3-pipeline")) as c:
        with c.pipeline():
            for i in range(5):
                c.execute("select %s::int", (i,))
            c.execute("update orders set status=status where id=%s", (2,))
        c.commit()

def psycopg3_txn_rollback():
    with psycopg.connect(url("py3-txn")) as c:
        with c.transaction():
            c.execute("select 1")
        try:
            with c.transaction():
                c.execute("select 1/0")
        except psycopg.errors.DivisionByZero:
            pass
        c.execute("select 1").fetchone()

def psycopg3_copy():
    with psycopg.connect(url("py3-copy")) as c:
        with c.cursor().copy("copy (select * from orders limit 5) to stdout") as cp:
            n = sum(1 for _ in cp)

def psycopg3_async():
    async def go():
        async with await psycopg.AsyncConnection.connect(url("py3-async")) as c:
            await (await c.execute("select 1")).fetchone()
    asyncio.run(go())

def psycopg2_basic():
    c = psycopg2.connect(url("py2-basic")); cur = c.cursor()
    cur.execute("select count(*) from orders"); cur.fetchone()
    cur.execute("delete from orders where false"); c.commit(); c.close()

def sqlalchemy_psycopg3():
    e = sa.create_engine(url("sqla", "postgresql+psycopg"))
    with e.begin() as c:
        c.execute(sa.text("select count(*) from orders")).scalar()
        c.execute(sa.text("update orders set status=status where id=:i"), {"i": 3})
    e.dispose()

def asyncpg_basic():
    async def go():
        c = await asyncpg.connect(f"postgresql://postgres:faultwall-demo@{P}/demo", ssl=False,
                                  server_settings={"application_name": "agent:asyncpg:mission:default"})
        for i in range(10):
            await c.fetch("select id from orders where id=$1", i + 1)
        await c.close()
    asyncio.run(go())

def no_appname():
    with psycopg.connect(f"postgresql://postgres:faultwall-demo@{P}/demo?sslmode=disable") as c:
        c.execute("select 1").fetchone()

for n, f in list(globals().items()):
    if callable(f) and n not in ("run", "url") and getattr(f, "__module__", None) == "__main__":
        run(n, f)

time.sleep(1)
act = json.load(urllib.request.urlopen("http://127.0.0.1:6480/api/try/activity"))
agents = {a["agent"]: a["queries"] for a in act["agents"]}
print(json.dumps({"results": res, "agents": agents}, indent=1))
