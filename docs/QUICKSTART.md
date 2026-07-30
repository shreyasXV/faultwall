# FaultWall Quickstart

Get FaultWall protecting an AI agent against your Postgres in 3 commands.

## Install

### One-line install (Linux/Mac)

```bash
curl -fsSL https://raw.githubusercontent.com/shreyasXV/faultwall/main/install.sh | bash
```

### Docker

```bash
docker pull ghcr.io/shreyasxv/faultwall:main
```

### From source

```bash
git clone https://github.com/shreyasXV/faultwall
cd faultwall
go build -o faultwall .
```

## 1. Scaffold a policy

```bash
faultwall init                  # balanced (default) — safe starter
faultwall init --strict         # read-only agents (no writes)
faultwall init --permissive     # blocks only catastrophic ops
```

This creates `faultwall.yaml` in the current directory. Open it and:

- Rename `my-agent` to the name your agent will use in its `application_name`
- Adjust `tables:` to the tables the agent actually needs
- Review `blocked_operations` and `blocked_tables`

## 2. Start the proxy

```bash
faultwall --proxy \
  --listen :5433 \
  --upstream localhost:5432 \
  --policies faultwall.yaml
```

FaultWall now sits between your agent (port 5433) and Postgres (port 5432). Every SQL query gets parsed, checked against the policy, and either allowed through or blocked before reaching the database.

## 3. Point your agent at port 5433

Your agent's Postgres connection string should target `:5433` and set `application_name` to identify itself:

```bash
faultwall agent-url --agent my-agent --mission default
# → postgres://postgres:postgres@localhost:5433/postgres?application_name=agent:my-agent:mission:default
```

Copy that into whatever your agent uses for `DATABASE_URL`.

### LangChain example

```python
import os
os.environ["DATABASE_URL"] = (
    "postgresql://postgres:postgres@localhost:5433/postgres"
    "?application_name=agent:my-agent:mission:research"
)
```

### Raw psql

```bash
psql "postgres://postgres:postgres@localhost:5433/postgres?application_name=agent:my-agent:mission:default"
```

## What it looks like when a query gets blocked

FaultWall logs blocks to stderr and returns a standard Postgres error to the client:

```
  [BLOCKED] agent=my-agent mission=default
    query: DROP TABLE users;
    reason: operation 'DROP' in blocked_operations
```

The client sees:

```
ERROR: FaultWall blocked query — operation DROP not permitted for agent my-agent
```

## Troubleshooting

**Q: Queries aren't being blocked even though they're in `blocked_operations`.**
A: Check the agent's `application_name`. It must start with `agent:<name>:mission:<mission>`. Without that, FaultWall treats the connection as "unidentified" and applies the `unidentified:` policy at the bottom of the file (default: `monitor` = log but allow).

**Q: `default_policy: deny` is blocking even allowed tables.**
A: Your agent name in the policy file must match the name in `application_name` exactly. Case-sensitive. Check `faultwall --proxy` logs for `agent=<actual-name>`.

**Q: FaultWall hangs on startup.**
A: Postgres isn't reachable at `--upstream`. FaultWall does a connection check on startup — verify with `psql --host localhost --port 5432`.

**Q: I want to see every query, not just blocks.**
A: Set `unidentified.policy: log` or add an `-v` flag when running the proxy. All queries hit the audit log.

## Next

- Full policy reference: [`policies.yaml`](../policies.yaml) — the canonical example with every option documented
- Dashboard: `DATABASE_URL=postgres://... faultwall --proxy` also starts the HTTP dashboard on `:8080`
- MCP server for autonomous agents: `faultwall --mcp`
