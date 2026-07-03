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

## Configuration

### Proxy Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--proxy` | — | Enable proxy mode |
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

## Known Limitations & Hard Requirements

- **DB-port isolation is REQUIRED.** FaultWall is a proxy. If agents can reach the upstream Postgres port directly (bypassing the proxy), every SQL-level rule in this repo is void and PII is exposed. Network policy / security groups / firewall rules MUST allow only the FaultWall proxy to reach the upstream DB port. At startup the proxy runs a best-effort TCP-dial probe (F9) and logs a warning describing what it observed; this is a topology hint, not proof of isolation. Disable with `FW_DB_ISOLATION_CHECK=false` if you've already verified isolation externally.
- **Identity spoofing:** `application_name` is fully spoofable. Set `auth_token: <secret>` per agent in `policies.yaml` and have the agent send `agent:<id>:mission:<m>:token:<secret>`. To make tokenless agents fail-closed at the proxy, set `FW_REQUIRE_AUTH_TOKEN=true`. JWT-based identity attestation is on the roadmap.
- **SSL/TLS:** Proxy mode currently denies SSL negotiation (client retries plaintext). For production with remote databases requiring TLS, use a TLS-terminating proxy in front of FaultWall.
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
