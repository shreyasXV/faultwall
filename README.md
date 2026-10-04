<p align="center">
  <img src="assets/logos/logo-v3.svg" alt="FaultWall" width="80">
  <h1 align="center">FaultWall</h1>
  <p align="center"><strong>The Agentic Data Firewall for PostgreSQL</strong></p>
  <p align="center">Identity-aware SQL enforcement for AI agents. Block rogue queries before they hit your database.</p>
</p>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/shreyasXV/faultwall"><img src="https://goreportcard.com/badge/github.com/shreyasXV/faultwall" alt="Go Report Card"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue.svg" alt="License: MIT"></a>
  <img src="https://img.shields.io/badge/go-1.21+-00ADD8.svg" alt="Go 1.21+">
  <img src="https://img.shields.io/badge/postgres-14+-336791.svg" alt="PostgreSQL 14+">
</p>

---

**Your AI agent has your database password. FaultWall makes sure that's safe.**

> **Deterministic. No LLM in the loop.** FaultWall uses the real PostgreSQL C parser (`pg_query_go`) for static SQL analysis — no AI, no API keys, no probabilistic guessing. Every decision is auditable, reproducible, and adds under 1ms of latency.

## Check what your agent's database user can do (30 seconds)

Run this against the database your agent uses. It prints what that login can actually do, using Postgres' own privilege checks (inherited role grants included).

```bash
curl -fsSL https://raw.githubusercontent.com/shreyasXV/faultwall/main/try.sh | FAULTWALL_NO_RUN=1 bash   # installs to ~/.faultwall/bin, no sudo
~/.faultwall/bin/faultwall audit "$DATABASE_URL"
```

It checks:

- superuser, BYPASSRLS, CREATEROLE, CREATEDB, REPLICATION, and membership in `pg_read_server_files`, `pg_write_server_files`, `pg_execute_server_program`, `pg_read_all_data`, `pg_write_all_data`
- per table: SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, ownership (owner can ALTER/DROP), and whether RLS is on and applies to this role
- secret-looking columns it can SELECT (`password_hash`, `token`, `ssn`, `api_key`...), including column-level grants
- views it can read that pull from those columns
- functions it can EXECUTE that reach files, other servers or other sessions (`pg_read_file`, `lo_export`, `dblink*`, and `pg_terminate_backend` when it has `pg_signal_backend`), COPY ... PROGRAM, and extensions like `dblink`, `postgres_fdw`, `plpython3u`
- schemas it can CREATE objects in

Sample output, for a shared `app_user`:

```
Summary
  app_user can DELETE on 42 of 43 tables, UPDATE 42, INSERT 42, TRUNCATE 42, and read 4 secret columns (users.password_hash, api_tokens.token, customers.ssn, +1 more).
  Owns 40 (can ALTER/DROP). 1 view reads secret columns. 1 dangerous function executable (dblink*). RLS applies on 0 of 1 RLS tables.
  Superuser: no. Bypasses RLS: no. Create role: no. Create DB: no. Replication: no.

Fixable with Postgres grants (enforced by Postgres)
  - DELETE on 42 of 43 tables.
  - Can SELECT 4 secret-looking columns: public.users.password_hash, public.api_tokens.token, ...
  - Can read 1 view that reads secret-looking columns: public.user_logins (reads public.users.password_hash).
  ...

Still requires Faultwall (enforced by Faultwall, Postgres can't express these)
  - Writes without a WHERE clause: app_user can UPDATE or DELETE every row of 42 tables in one statement.
  - Row-count caps, approval before a write, per-agent identity on a shared login, query-shape rules.
```

`faultwall audit --fix` prints SQL for a new per-agent role (`fw_agent_<name>`) that keeps the reads, leaves out secret columns with column-level grants, and has no writes unless you pass `--writes orders,tickets`. It only prints the SQL. It never runs it, and it never REVOKEs or ALTERs your existing users, so your app keeps working. It also lists what the new role still gets through PUBLIC (for example `dblink` or CREATE on schema `public`) so you can review those with your DBA. `--role NAME` checks another role, `--json` gives machine-readable output.

Read-only, nothing leaves your machine. The session is set to read-only and runs only catalog queries. There is no telemetry or update check, and no network call besides the one Postgres connection.

## Works with every managed Postgres

| Deployment | Status |
|---|---|
| Self-hosted Postgres 12+ | 🟢 Green |
| AWS RDS Postgres 16 | 🟢 Green |
| AWS Aurora Postgres 16 | 🟢 Green |
| Neon (serverless Postgres 17) | 🟢 Green |
| PgBouncer (tx + session) | 🟢 Green |
| Supabase pooler | 🟡 Yellow ([workaround](docs/compatibility.md#supabase-tested-with-real-instance-2026-04-27)) |
| Cloud SQL · CrunchyBridge · DO MPG | 🟢 Expected ¹ |

¹ Same Postgres wire protocol as validated providers; tested path exists, instance not provisioned.

**Overhead:** +0.14ms per query / −15% TPS on cloud-latency paths (RDS benchmark).
**Zero code changes required** in your agent. Stock Postgres driver, standard connection string.

→ [Full compatibility matrix + SCRAM config per provider](docs/compatibility.md) · [Attack suite results](tests/compat/) · [Reproducible test harness](tests/compat/compat_test.sh)

A prompt injection hides a `DROP TABLE` in a customer feedback comment. Your agent blindly executes it. The WAF sees nothing — it's a legitimate connection with valid credentials. The database sees a normal query from an authorized user.

FaultWall intercepts the query **before it reaches PostgreSQL**, parses the SQL, checks it against your policy, and blocks it:

```
🔌 New connection: agent=cursor-ai/summarize-feedback
🟢 [ALLOWED] agent=cursor-ai/summarize-feedback  query=SELECT * FROM feedback LIMIT 100;
🔴 [BLOCKED] agent=cursor-ai/summarize-feedback  reason=blocked_operation  query=DROP TABLE users;
🔴 [BLOCKED] agent=rogue-bot/steal               reason=agent_not_in_policy  query=SELECT * FROM users;
🔴 [BLOCKED] agent=cursor-ai/summarize-feedback  reason=blocked_function:pg_read_file  query=SELECT pg_read_file('/etc/passwd');
```

---

## Two Modes

### 🛡️ Proxy Mode (Enforce) — **Recommended**

FaultWall sits between your agent and PostgreSQL as an inline L7 proxy. Every SQL query is parsed and checked **before it reaches the database**. Blocked queries never execute.

- Intercepts 100% of queries (Simple + Extended Query Protocol)
- Parses SQL using the real PostgreSQL C parser (`pg_query_go`) — deterministic, no LLM
- Sub-1ms latency overhead per query
- Works with any Postgres client: psql, psycopg2, pgx, SQLAlchemy, JDBC
- Fail-open on internal errors (won't break your app)

```bash
./faultwall --proxy --listen :5433 --upstream localhost:5432 --policies ./policies.yaml
```

Agents connect to port 5433 instead of 5432. That's the only change.

Watch-only first? Add `--mode monitor` (or set `POLICY_ENFORCEMENT=monitor`): same parsing and logging, violations are recorded as `monitored`, nothing is blocked.

### 📊 Monitor Mode (Sidecar)

FaultWall connects to your database as a read-only sidecar, polls `pg_stat_activity`, and logs violations. Good for visibility without being in the data path.

- Dashboard with agent activity, violations, cost attribution
- Anomaly detection and alerting
- Slack notifications
- No query blocking (observe only)

```bash
DATABASE_URL="postgres://user:pass@localhost:5432/mydb" \
POLICY_FILE=./policies.yaml \
./faultwall
```

---

## Try it in 60 seconds (one command, no YAML)

```bash
# Demo: bundled Postgres + two scripted agents, live view at http://localhost:8080
curl -fsSL https://app.faultwall.com/try.sh | bash

# Your database (monitor mode: observes and flags, never blocks)
curl -fsSL https://app.faultwall.com/try.sh | bash -s -- "postgres://user:pass@host:5432/db"
```

It prints a connection string to give your agent (`postgres://…@localhost:5433/db?application_name=agent:my-agent:mission:default`)
and opens a live view of every query, per agent, with what FaultWall *would* have flagged:

- DDL / DCL (`CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `GRANT`…)
- `UPDATE` / `DELETE` with no `WHERE` clause
- writes that touch more than 100 rows
- reads of secret-looking columns (`password`, `token`, `secret`, `ssn`, `api_key`…)
- dangerous server functions (`pg_read_file`, `dblink`, `lo_export`…)

Already installed? `faultwall try [postgres://…]`. With Docker:
`docker run --rm -it -p 5433:5433 -p 8080:8080 ghcr.io/shreyasxv/faultwall try "postgres://user:pass@host.docker.internal:5432/db"`.

**Name your agent.** Keep `application_name=agent:<name>:mission:<task>` on whatever connection string your agent uses, or its queries show up as `unknown`. Most drivers take it as a URL param or a keyword:

```python
psycopg.connect(url, application_name="agent:support-bot:mission:triage")            # psycopg 3 / psycopg2
create_engine(url, connect_args={"application_name": "agent:support-bot:mission:triage"})  # SQLAlchemy
await asyncpg.connect(url, server_settings={"application_name": "agent:support-bot:mission:triage"})
```

Tested through `faultwall try` with psql, pgx, psycopg 3 (simple, prepared, pipeline, async, COPY), psycopg2, SQLAlchemy, asyncpg and node-pg.

When you're ready to block, write a policy (below) and run in proxy mode.

## Quick Start (5 minutes)

### Step 1: Install

```bash
git clone https://github.com/shreyasXV/faultwall && cd faultwall
go build -o faultwall .
```

Or use Docker:
```bash
docker pull ghcr.io/shreyasxv/faultwall:latest
```

### Step 2: Write your policy

Create `policies.yaml`:

```yaml
default_policy: deny

# Dangerous PostgreSQL functions blocked for ALL agents
blocked_functions:
  - pg_read_file
  - pg_read_binary_file
  - pg_ls_dir
  - pg_execute_server_program
  - lo_export
  - lo_import
  - dblink
  - dblink_exec
  - pg_terminate_backend
  - pg_cancel_backend
  - pg_reload_conf
  - pg_sleep
  - set_config

agents:
  cursor-ai:
    description: "Cursor IDE agent"
    profile: standard             # use a security profile
    blocked_tables: [public.users, public.payments]
    missions:
      summarize-feedback:
        tables: [public.feedback, public.products]

  langchain-agent:
    description: "LangChain research agent"
    blocked_operations: [DROP, TRUNCATE, ALTER, GRANT]  # legacy mode still works
    missions:
      analyze-trends:
        tables: [public.orders, public.products]

unidentified:
  policy: deny    # deny | monitor | allow
```

### Step 3: Run FaultWall (Proxy Mode)

```bash
POLICY_ENFORCEMENT=enforce \
./faultwall --proxy --listen :5433 --upstream localhost:5432 --policies ./policies.yaml
```

### Step 4: Point your agents at FaultWall

Change the connection port from `5432` to `5433`:

**Python (psycopg2):**
```python
conn = psycopg2.connect(
    host="localhost", port=5433, dbname="mydb", user="myuser",
    application_name="agent:cursor-ai:mission:summarize-feedback"
)
```

**Node.js (pg):**
```javascript
const client = new Client({
  host: "localhost", port: 5433, database: "mydb", user: "myuser",
  application_name: "agent:cursor-ai:mission:summarize-feedback"
});
```

**Go (pgx):**
```go
conn, err := pgx.Connect(ctx, "postgres://myuser@localhost:5433/mydb?application_name=agent:cursor-ai:mission:summarize-feedback")
```

**psql:**
```bash
psql "host=localhost port=5433 user=myuser dbname=mydb application_name=agent:cursor-ai:mission:summarize-feedback"
```

### Step 5: Verify

```bash
# This should work (agent has access to feedback table):
psql "host=localhost port=5433 ... application_name=agent:cursor-ai:mission:summarize-feedback" \
  -c "SELECT * FROM feedback LIMIT 5;"

# This should be BLOCKED:
psql "host=localhost port=5433 ... application_name=agent:cursor-ai:mission:summarize-feedback" \
  -c "DROP TABLE users;"
# ERROR: [BLOCKED by FaultWall] blocked_operation (op: DROP)
```

---

## How It Works

### Proxy Mode Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌──────────────┐
│   AI Agent      │────▶│  FaultWall   │────▶│  PostgreSQL   │
│ (port 5433)     │     │  L7 Proxy    │     │  (port 5432)  │
└─────────────────┘     └──────┬───────┘     └──────────────┘
                               │
                    ┌──────────┴──────────┐
                    │ For each query:     │
                    │ 1. Parse SQL (AST)  │
                    │ 2. Check policy     │
                    │ 3. Allow or Block   │
                    └─────────────────────┘
```

1. Agent connects to FaultWall on port 5433
2. FaultWall reads the startup message, extracts `application_name` for agent identity
3. Auth handshake is relayed to upstream PostgreSQL
4. Every query (Simple or Extended protocol) is intercepted:
   - SQL is parsed into an AST using `pg_query_go/v6` (the real PostgreSQL C parser)
   - AST is checked against the agent's policy: operation type, tables, functions
   - **Allowed** → query is forwarded to PostgreSQL, response relayed back
   - **Blocked** → PostgreSQL never sees it. Client gets `ERROR: [BLOCKED by FaultWall] reason`
5. All other wire protocol messages are forwarded transparently

### Agent Identity

Agents identify themselves via PostgreSQL's `application_name` parameter:

```
agent:<agent_id>:mission:<mission_id>
```

This is set in the connection string — no code changes beyond the connection config. FaultWall reads it from the startup packet at connect time.

### Per-agent keys (managed from the control plane)

Agents created on the control plane's Agents page get their own key. The agent connects with `postgresql://<agent-name>:<key>@<proxy>/<db>`, and the proxy logs in to Postgres with its own credentials (`FW_UPSTREAM_USER` / `FW_UPSTREAM_PASSWORD`), so the agent never holds the real database password.

The agent authenticates to the proxy with **SCRAM-SHA-256**, the same challenge-response Postgres uses: the key is never sent over the wire, and neither the control plane nor the proxy stores it (only a salted SCRAM verifier). Any driver that supports `password_encryption=scram-sha-256` works unchanged (psql, psycopg 2/3, pgx, asyncpg, node-pg, JDBC). A wrong or revoked key is refused with `28P01` before any upstream connection is opened. Keys created before SCRAM support are refused until re-created, unless you set `FW_ALLOW_CLEARTEXT_KEY=1` on the proxy.

Revoking a key on the Agents page also ends that agent's open sessions on the proxy's next sync (FATAL `agent key revoked`), not just new connections.

**Per-agent database role (`db_role`).** On the Agents page you can give an agent a Postgres role. Right after the proxy logs in upstream, and before the agent can send anything, the proxy runs `SET SESSION ROLE "<db_role>"`. From then on Postgres enforces that role's grants itself: with a SELECT-only role, an `UPDATE` fails with Postgres' own `42501 permission denied`, even if a FaultWall rule were wrong. The agent can't switch back. `SET ROLE`, `RESET ROLE`, `SET SESSION AUTHORIZATION`, `RESET ALL`, `DISCARD ALL` and `set_config('role', ...)` are refused with `42501 [BLOCKED by FaultWall] agent role is fixed`, over both the simple and extended protocol, and the connection stays open. If the role doesn't exist or isn't granted to the proxy's login, the connection gets a FATAL that says so. Changing or clearing an agent's role ends its open sessions, so reconnects pick up the new role. Leave `db_role` empty for "ask first" agents: an approved write still needs write grants. See [Make the proxy the only path to the database](#make-the-proxy-the-only-path-to-the-database) for the SQL.

### What Gets Checked

| Check | Example |
|-------|---------|
| **Blocked operations** | `DROP`, `TRUNCATE`, `DELETE` |
| **Blocked tables** | `public.users`, `public.payments` |
| **Mission scope** | Agent can only access `feedback` and `products` tables during this mission |
| **Blocked functions** | `pg_read_file`, `dblink`, `lo_export` (17 dangerous functions blocked by default) |
| **Unknown agents** | Agents not in the policy file are denied (when `default_policy: deny`) |
| **Unidentified connections** | Connections without `agent:` prefix are denied/monitored per config |

### Query Protocols Supported

| Protocol | Coverage | Used By |
|----------|----------|---------|
| **Simple Query** (`Q` message) | ✅ Full inspection | `psql`, basic clients |
| **Extended Query** (`Parse`/`Bind`/`Execute`) | ✅ Full inspection | psycopg2, pgx, SQLAlchemy, JDBC, all ORMs |

---

## Monitor Mode (Sidecar)

For teams that want visibility without putting a proxy in the data path:

```bash
DATABASE_URL="postgres://user:pass@localhost:5432/mydb" \
POLICY_FILE=./policies.yaml \
POLICY_ENFORCEMENT=monitor \
./faultwall
```

**Features:**
- 📊 Real-time dashboard on port 8080
- 🔍 Anomaly detection (genetic algorithm-tuned baselines)
- ⚡ Auto-throttling (kill runaway queries)
- 💰 Cost attribution per tenant/agent
- 🤖 MCP server for AI agent self-monitoring
- 📨 Slack alerting

**Limitation:** Monitor mode polls `pg_stat_activity` every 10 seconds. Queries that complete faster than 10 seconds may not be detected. Use Proxy Mode for guaranteed enforcement.

---

## Dashboard

Available in both modes at `http://localhost:8080`:

| Panel | What you see |
|-------|-------------|
| **Agent Connections** | Active agents, missions, connection status |
| **Violations** | Blocked queries with agent, table, reason |
| **Tenant Leaderboard** | Ranked by queries, latency, cost |
| **Cost Attribution** | Per-agent/tenant cost breakdowns |
| **Anomalies** | Statistical deviations from baseline |
| **Predictions** | Trend forecasts and breach warnings |
| **APA Proposals** | Policy changes the Autonomous Policy Agent proposes for review |

### APA review: PR mode vs file-drop mode

The Autonomous Policy Agent (APA) watches observations and proposes policy
changes. It never edits your live policy in place. You choose how proposals are
reviewed, in the `apa:` section of `policies.yaml`:

```yaml
apa:
  enabled: true
  provider: openai        # openai | anthropic | litellm | fake
  # PR mode: open a GitHub PR against a repo (needs the gh CLI).
  policy_repo: myorg/faultwall-policies
  # File-drop mode: no git required. APA writes a downloadable, apply-ready
  # policies.yaml plus a diff, surfaced in the dashboard "APA Proposals" panel.
  proposal_dir: ~/.faultwall
```

Set either or both. With no `policy_repo`, APA runs in file-drop mode by default
(proposals land in `~/.faultwall/proposals`, or `APA_PROPOSAL_DIR`). Review them
in the dashboard: Download the proposed YAML, apply it yourself, then
`POST /api/policies/reload` (or restart). Endpoints:

- `GET /api/apa/proposals/files` — list proposals (diff + metadata)
- `GET /api/apa/proposals/files/{id}/download` — download the proposed policies.yaml
- `POST /api/apa/proposals/files/{id}/apply` | `/dismiss` — mark status

---

## Docker Compose

```yaml
version: "3.8"
services:
  postgres:
    image: postgres:16
    environment:
      POSTGRES_PASSWORD: postgres
    ports:
      - "5432:5432"

  faultwall:
    image: ghcr.io/shreyasxv/faultwall:latest
    command: ["./faultwall", "--proxy", "--listen", ":5433", "--upstream", "postgres:5432", "--policies", "/etc/faultwall/policies.yaml"]
    environment:
      POLICY_ENFORCEMENT: enforce
    volumes:
      - ./policies.yaml:/etc/faultwall/policies.yaml:ro
    ports:
      - "5433:5433"
      - "8080:8080"
    depends_on:
      - postgres
```

```bash
docker compose up -d
# Agents connect to localhost:5433
```

---

## Security Profiles

Security profiles let you pick a security posture instead of manually listing operations. Three built-in profiles are available:

| Profile | Posture | Blocked | Use Case |
|---------|---------|---------|----------|
| `permissive` | Log everything, block nothing | — | Visibility into agent behavior |
| `standard` | Block dangerous ops | DCL, ADMIN, EXTENSION, FUNCTION categories + COPY | Agents read/write data safely |
| `strict` | Allowlist only | Everything except SELECT, INSERT, UPDATE, DELETE, EXPLAIN, TRANSACTION | Basic CRUD only |

`standard` and `strict` also enforce "DELETE must include WHERE" and "UPDATE must include WHERE" conditions.

### Using Profiles

```yaml
agents:
  my-agent:
    profile: standard               # pick a built-in profile
    profile_overrides:               # optional per-agent tweaks
      allow: [COPY]                  # allow COPY even though standard blocks it
      block: [DELETE]                # block DELETE even though standard allows it
    blocked_tables: [public.secrets] # table rules still apply on top
```

### Custom Profiles

Define custom profiles in the `profiles` section:

```yaml
profiles:
  readonly:
    extends: strict
    allowed_operations: [SELECT, EXPLAIN]
```

### Backward Compatibility

The existing `blocked_operations` field still works. If an agent has no `profile`, behavior is identical to before. If both `profile` and `blocked_operations` are set, the profile takes precedence.

---

## Privacy: what leaves your box (control-plane telemetry)

**Query values never leave your box. Table and column names do, so we can show you what each agent touched.**

Telemetry is **off** unless the proxy is enrolled to a control plane (`install.sh --token ...` writes `~/.faultwall/config.toml`, or set `FAULTWALL_CONTROL_PLANE_URL` + `FAULTWALL_CONTROL_PLANE_TOKEN`). Turn it all off with `FAULTWALL_TELEMETRY=false` or `telemetry_enabled = false`.

`faultwall try` follows the same rule. Enroll it with `faultwall try --token <TOKEN> --control-plane https://api.faultwall.com [postgres://...]` (try.sh passes both flags through), or use the same env / config file as `--proxy`. The startup banner's `Events go to:` line says where events are going. Without enrollment, `try` sends nothing.

When enrolled, each statement sends one event:

| Field | Example | Notes |
|-------|---------|-------|
| `agent_id`, `mission` | `support-agent`, `refunds` | from `application_name=agent:<id>:mission:<m>`. The `:token:` part is never sent. Connections without a name are sent as their raw application_name (or `unknown`) with `agent_unnamed: true`. |
| `op_type`, `table_name`, `tables` | `UPDATE`, `orders` | names only |
| `rows_affected` | `12` | count from the CommandComplete tag. No row data. |
| `decision`, `flags`, `reasons` | `allow`, `["mass_write"]` | zero-config rules: DDL, UPDATE/DELETE without WHERE, writes over 100 rows, secret-column reads, dangerous server functions, policy violations |
| `fingerprint` | `a1b2c3...` | pg_query structural hash. Literals don't change it. |
| `latency_ms`, `risk_score` | `0.4`, `0.12` | decision latency, QWM score |
| **`query_shape`** | `UPDATE orders SET status = ? WHERE id = ?` | **gated, see below** |

**Never sent:** raw query text, bound parameter values, literals, comments, row data, policy bodies, connection credentials.

### Query shapes (`FW_TELEMETRY_QUERY_SHAPE`)

`query_shape` is the statement with **every** literal replaced by `?` (strings, dollar-quoted bodies, numbers, booleans, `$n` params, `E''`/`U&''`/bit/hex constants) and every comment removed. It is built from the Postgres scanner's token stream (pg_query), not regexes. If a statement can't be tokenized, or anything quote-like survives, the shape is dropped and only the metadata above is sent. It is what makes the hosted feed say *"support-agent ran `UPDATE orders SET status = ? WHERE id = ?` (12 rows)"* instead of *"UPDATE on orders"*.

| Setting | Effect |
|---------|--------|
| *(unset)* | **on** when enrolled (`telemetryQueryShapeDefault` in `telemetry_client.go`) |
| `FW_TELEMETRY_QUERY_SHAPE=off` (or `false`/`0`) | never send shapes |
| `FW_TELEMETRY_QUERY_SHAPE=on` | send shapes |
| `query_shape = false` in `[control_plane]` | same as off; the env var wins |

Identifiers stay in the shape: table, column and function names. If your schema names are themselves sensitive, set `FW_TELEMETRY_QUERY_SHAPE=off`.

Delivery: events are batched (200 per batch, every 2s) on a background goroutine. If the control plane is unreachable they are retried with exponential backoff (1s up to 60s, jittered), and up to 10,000 events are held in memory. Emitting never blocks a query; if the buffer is full the event is dropped.

---

## Configuration

### Proxy Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy` | — | Enable proxy mode |
| `--mode enforce\|monitor` | `enforce` | `monitor` (or `--monitor`, or `POLICY_ENFORCEMENT=monitor`) observes and flags, never blocks. Flag beats env. |
| `--listen` | `:5433` | Proxy listen address |
| `--upstream` | `localhost:5432` | Upstream PostgreSQL address |
| `--policies` | `./policies.yaml` | Policy file path |

| Env Var | Default | Description |
|---------|---------|-------------|
| `POLICY_ENFORCEMENT` | `monitor` | `enforce` (block) or `monitor` (log only) |

### Monitor Mode (Sidecar)

| Env Var | Default | Description |
|---------|---------|-------------|
| `DATABASE_URL` | **(required)** | PostgreSQL connection string |
| `PORT` | `8080` | Dashboard port |
| `POLICY_FILE` | `./policies.yaml` | Policy file path |
| `POLICY_ENFORCEMENT` | `monitor` | `enforce` or `monitor` |
| `SLACK_WEBHOOK_URL` | — | Slack webhook for alerts |
| `THROTTLE_ENABLED` | `false` | Enable auto-throttling |
| `RDS_HOURLY_COST` | `0.50` | Hourly DB cost for attribution |

---

## MCP Server (AI-Native)

FaultWall exposes an MCP server so AI agents can self-monitor:

```json
{
  "mcpServers": {
    "faultwall": {
      "command": "./faultwall",
      "args": ["--mcp"],
      "env": { "DATABASE_URL": "postgres://..." }
    }
  }
}
```

10 tools: `list_tenants`, `get_tenant`, `get_noisy_tenants`, `get_costs`, `throttle_tenant`, `get_health`, `get_anomalies`, `get_predictions`, and more.

---

## Make the proxy the only path to the database

FaultWall can only enforce what goes through it. **If an agent has any other route to the database, it bypasses FaultWall.** After installing, close the other routes:

**1. Rotate the database password so only the proxy knows it.** Whatever password your agents (or their config, CI secrets, `.env` files) used before is now a way around the proxy. Set a new one and give it to the proxy only:

```sql
-- as an admin, on the real database
ALTER ROLE faultwall_proxy WITH PASSWORD 'a-new-long-random-password';
```

```bash
# on the FaultWall host only
FW_UPSTREAM_USER=faultwall_proxy FW_UPSTREAM_PASSWORD='a-new-long-random-password' faultwall --proxy ...
```

Agents connect with their FaultWall agent key (`postgresql://<agent>:<fw_ak_...>@<proxy>/<db>`), which Postgres rejects if it's tried directly. If agents used to share an application login, rotate that one too, or `ALTER ROLE ... NOLOGIN` it.

**2. Allow network access to the database from the proxy host only.**

- **Cloud (RDS, Cloud SQL, Azure, Supabase, Neon):** restrict the database's security group / authorized networks / firewall to the FaultWall host's address (or its security group). Remove `0.0.0.0/0` and any agent subnets.
- **Self-managed:** in `pg_hba.conf`, accept the proxy's address and reject the rest, then reload:

  ```
  # TYPE  DATABASE  USER             ADDRESS          METHOD
  host    all       faultwall_proxy  10.0.1.20/32     scram-sha-256   # FaultWall host
  host    all       all              0.0.0.0/0        reject
  host    all       all              ::/0             reject
  ```

  Keep any admin or migration access on separate, named rules that agents can't use.

The proxy logs a startup hint about DB-port reachability (F9), and REAL-F9 flags sessions that reach the DB without going through it. These are hints, not proof. Verify the network rules yourself.

**3. Give read-only agents a read-only database role.** With a role set, Postgres rejects the agent's writes on its own, independent of FaultWall's rules. Create one NOLOGIN role per agent (or per access level), grant it only what the agent needs, and grant the role to the proxy's login so the proxy can switch to it:

```sql
-- read-only role for one agent
CREATE ROLE fw_ro_support_agent NOLOGIN;
GRANT USAGE ON SCHEMA public TO fw_ro_support_agent;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO fw_ro_support_agent;
-- tables created later (run as the role that creates them)
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO fw_ro_support_agent;

-- let the proxy's login switch to it
GRANT fw_ro_support_agent TO faultwall_proxy;
```

Then set the agent's **Database role** to `fw_ro_support_agent` on the Agents page. The page suggests `fw_ro_<agent>` when writes are blocked. Narrow the grants further (specific tables or columns instead of `ALL TABLES`) if the agent needs less. Don't do this for "ask first" agents, since approved writes need write grants. Two caveats. Keep the proxy's login (`faultwall_proxy`) a plain role, not a superuser, so the agent's role is the only source of its rights. And `SECURITY DEFINER` functions the role can execute still run with their owner's rights, so review those, or revoke `EXECUTE` from the role.

## Known Limitations & Hard Requirements

- **DB-port isolation is REQUIRED.** FaultWall is a proxy. If agents can reach the upstream Postgres port directly (bypassing the proxy), every SQL-level rule in this repo is void and PII is exposed. Network policy / security groups / firewall rules MUST allow only the FaultWall proxy to reach the upstream DB port. At startup the proxy runs a best-effort TCP-dial probe (F9) and logs a warning describing what it observed; this is a topology hint, not proof of isolation. Disable with `FW_DB_ISOLATION_CHECK=false` if you've already verified isolation externally.
- **Identity spoofing:** `application_name` is fully spoofable. Set `auth_token: <secret>` per agent in `policies.yaml` and have the agent send `agent:<id>:mission:<m>:token:<secret>`. To make tokenless agents fail-closed at the proxy, set `FW_REQUIRE_AUTH_TOKEN=true`. JWT-based identity attestation is on the roadmap.
- **SSL/TLS:** Proxy mode currently denies SSL negotiation (client retries plaintext). For production with remote databases requiring TLS, use a TLS-terminating proxy in front of FaultWall.
- **Approvals hold locks taken earlier in the txn:** with `action: hold` (see [docs/APPROVALS.md](docs/APPROVALS.md)), a held statement has not reached Postgres, but locks that earlier statements in the same transaction took stay held until the decision. Keep hold timeouts short; the approver sees `in_txn` and the txn age.
- **Fail-open:** If FaultWall's policy engine crashes, the query is forwarded (fail-open for availability). Configurable fail-closed mode is planned.

---

## Roadmap

- [x] Inline L7 proxy mode
- [x] Simple Query Protocol interception
- [x] Extended Query Protocol interception (Parse/Bind/Execute)
- [x] Per-agent, per-mission YAML policies
- [x] 17 blocked PostgreSQL functions by default
- [x] Real-time dashboard
- [x] Monitor mode (sidecar)
- [x] Security profiles (permissive, standard, strict) with custom profile support
- [x] Full SQL parser coverage (115 pg_query_go statement types)
- [ ] TLS/SSL passthrough
- [ ] JWT-based agent identity
- [ ] Connection pooling
- [ ] Health check endpoint for proxy
- [ ] eBPF kernel-level identity attestation (enterprise)
- [ ] MySQL support
- [ ] Kubernetes operator

---

## Contributing

```bash
git clone https://github.com/shreyasXV/faultwall
cd faultwall
go build -o faultwall .
go test ./...
```

---

## License

MIT — see [LICENSE](LICENSE).

---

<p align="center">
  <strong>Built by <a href="https://github.com/shreyasXV">Shreyas Shubham</a></strong><br>
  <a href="https://faultwall.com">faultwall.com</a> · <a href="https://twitter.com/FaultWall">@FaultWall</a>
</p>
