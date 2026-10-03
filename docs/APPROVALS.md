# Live-query approvals (`action: hold`)

Risky statements don't have to be blocked outright. FaultWall can **pause** them
in the proxy until a person approves or denies them, from the hosted dashboard,
from Slack, or from the local API.

```yaml
# policies.yaml
approvals:
  timeout: 120s          # no decision in time = deny (default 120s; FW_HOLD_TIMEOUT overrides)
  # mode: always         # also hold in monitor mode (default: holds only in enforce mode)
  # redact_query: true   # send only the literal-stripped statement to the control plane
  rules:
    - name: writes-to-orders
      action: hold
      agents: [support-agent]       # empty or "*" = every agent
      operations: [UPDATE, DELETE]  # empty = any; WRITE = INSERT/UPDATE/DELETE/MERGE/TRUNCATE
      tables: [orders]              # empty = any table; schema-agnostic
```

Rules match on the **parsed** statement, not a regex. For writes, the table is
the statement's write target, found by walking the AST, so a write hidden in a
CTE (`WITH x AS (UPDATE orders ...) SELECT ...`) or in `EXPLAIN ANALYZE` is still
held. `UPDATE customers ... FROM orders` is not held by an `orders` rule,
because it reads `orders` but writes `customers`.

Quick try: `faultwall try postgres://... --hold 'UPDATE,DELETE:orders'`, then
`POST http://127.0.0.1:8080/api/holds/{id}/approve` (or `/deny`).
Env shorthand: `FW_HOLD_RULES='UPDATE,DELETE:orders;WRITE@support-agent'`.

## What the agent sees

| Outcome | Client gets | Notes |
|---|---|---|
| Approved | the normal result | Runs as if it had never paused |
| Denied | `42501 [BLOCKED by FaultWall] UPDATE on orders was held for approval and denied by dana@acme.com: <reason>. It did not run.` | Inside a txn, the txn is aborted for real (next statement gets `25P02`, `ROLLBACK` works) |
| Timeout | `42501 ... nobody decided within 2m0s, so it was denied by default` | Default deny |
| Ctrl-C / `cancel()` | `57014 canceling statement due to user request` | The CancelRequest is matched to the held connection by BackendKeyData |
| Client hangs up / ctx deadline | nothing (conn gone) | The held statement is dropped and **never** runs, even if approved later |

## How it works (wire level)

- A per-connection reader goroutine owns the client socket, so a Terminate or
  EOF while a statement is held is seen at once.
- Extended protocol: the whole Parse/Bind/Describe/Execute group up to Sync is
  buffered **before** any of it reaches Postgres. That means the client's
  `statement_timeout` doesn't start counting during the hold, and cached
  prepared statements (Bind/Execute only) are matched via the statement
  tracker, so they can't bypass a hold. A pipelined batch with several held
  statements produces one hold ("N statements, decided together").
- Deny: the held Execute is pointed at a portal that doesn't exist
  (`fwhold_<id>`). For simple `Q`, the query is replaced with a cast that fails on
  the same marker. Postgres raises the error, aborts the txn if there is one,
  skips to the client's Sync and reports the real txn status. The relay then
  rewrites that one error into the FaultWall message.
- Earlier statements in the same transaction keep their locks while a later one
  is held. The approver is shown `in_txn` and the txn age.

## Where decisions come from

1. **Control plane** (when enrolled: `~/.faultwall/config.toml` `[control_plane]`
   url + token). The hold is POSTed to `/v1/holds` and the proxy long-polls
   `/v1/holds/{id}/wait`. The dashboard queue and Slack both decide there. The
   proxy's own timer stays authoritative. Outcomes the proxy decided itself
   (timeout, cancel, client gone, local API) are reported back via
   `/v1/holds/{id}/resolve`, so the queue and Slack never show a stale "pending".
2. **Local API** (always on, the fallback, and the only path in `try` mode
   without a control plane): `GET /api/holds`, `POST /api/holds/{id}/approve|deny`
   with optional `{"by":"...","reason":"..."}`. Protected by `FAULTWALL_API_TOKEN`
   when that is set.

`FAULTWALL_APPROVALS=local` keeps holds on the box (no control plane).

**Privacy:** a hold sends the statement text to the control plane, because the
approver must see what they're approving. This is the one exception to
metadata-only telemetry, and it only applies to statements that matched a hold
rule. Use `redact_query: true` to send the literal-stripped form instead.

## Tests

- Unit: `go test -run 'Hold|Gate|RewriteUpstream' .`
- E2E matrix (psql, psycopg3, pgx, asyncpg): see `tests/approvals/README.md`.
