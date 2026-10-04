import asyncio, json, urllib.request, asyncpg
API="http://127.0.0.1:18099/api/holds"
async def decide(a, d):
    await asyncio.sleep(d)
    for _ in range(40):
        hs=json.load(urllib.request.urlopen(API))["holds"]
        if hs:
            urllib.request.urlopen(urllib.request.Request(f"{API}/{hs[0]['id']}/{a}",data=b'{"by":"asyncpg"}',method="POST")).read(); return
        await asyncio.sleep(0.2)
async def main():
    c=await asyncpg.connect("postgresql://ec2-user@127.0.0.1:5547/fw_appr_e2e", server_settings={"application_name":"agent:support-agent"})
    t=asyncio.create_task(decide("approve",0.5)); r=await c.execute("update orders set status=$1 where id=$2","apg",8); await t; print("approve:", r)
    t=asyncio.create_task(decide("deny",0.5))
    try: await c.execute("update orders set status=$1 where id=$2","apg-no",8); print("FAIL deny")
    except asyncpg.InsufficientPrivilegeError as e: print("deny:", e.sqlstate, str(e)[:70])
    await t; print("reuse:", await c.fetchval("select 5"), "row:", await c.fetchval("select status from orders where id=8"))
asyncio.run(main())
