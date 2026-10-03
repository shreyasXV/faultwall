# Live-query approvals: end-to-end matrix

Needs a local Postgres on 127.0.0.1:5544 and a scratch DB:

    createdb -h 127.0.0.1 -p 5544 fw_appr_e2e
    psql -h 127.0.0.1 -p 5544 -d fw_appr_e2e -c "create table orders(id int primary key, status text, amount int);
      insert into orders select g,'open',g*10 from generate_series(1,10) g;
      create table customers(id int primary key, name text); insert into customers values (1,'a'),(2,'b');"
    go build -o /tmp/fw-appr-bin/faultwall .
    T=8 tests/approvals/run.sh            # proxy :5547, API :18099, rule: UPDATE/DELETE on orders

| script | driver | covers |
|---|---|---|
| `p.sh` + `decide.sh` | psql (simple Q) | approve, deny, in-txn deny -> 25P02, timeout default-deny, Ctrl-C (SIGINT -> CancelRequest -> 57014) |
| `py_e2e.py` | psycopg3 (extended) | approve, deny, 25P02, statement_timeout < hold, prepared stmt cache, pipeline deny/approve, cancel 57014, client gone |
| `pgx/` | pgx v5 | approve, deny with stmt cache, 25P02, statement_timeout, batch deny, ctx deadline -> never runs |
| `asy.py` | asyncpg | approve, deny, conn reuse |

Reset rows between runs: `update orders set status='open'`.
