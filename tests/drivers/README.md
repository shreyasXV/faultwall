# Driver smoke tests for `faultwall try`

Start: `faultwall try --demo --no-demo-agent --no-open --port 6433 --ui-port 6480`

- Python (`pip install "psycopg[binary]" psycopg2-binary sqlalchemy asyncpg`): `python python_drivers.py`
  covers psycopg 3 simple / prepared / pipeline / txn+rollback / COPY / async, psycopg2, SQLAlchemy, asyncpg,
  and a connection with no application_name (must show as an unnamed agent).
- Node (`npm i pg`): `node node_pg.js` (named prepared statement x10 + aborted txn).

Each named agent should appear in `/api/try/activity` with every query counted; `unknown` should have `unnamed: true`.
