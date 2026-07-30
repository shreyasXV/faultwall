# FaultWall Compatibility

FaultWall is a transparent L7 proxy that sits between your application (or AI agent) and PostgreSQL. Because it speaks the native Postgres wire protocol, it works with standard Postgres and every major managed provider. This page lists tested platforms, the one client-side config flag you may need, and realistic performance numbers.

**Last validated:** 2026-04-27 against PostgreSQL 16 and 17.

## Supported platforms

| Platform | Status | Notes |
|---|---|---|
| Self-hosted PostgreSQL 16 / 17 | Supported | No special config |
| PgBouncer (transaction & session mode) | Supported | Transparent through the pooler |
| AWS RDS for PostgreSQL | Supported | Set `channel_binding=disable`(see below) |
| AWS Aurora PostgreSQL | Supported | Set `channel_binding=disable`|
| Neon (serverless) | Supported | Set `channel_binding=disable`; SNI routing works out of the box |
| Supabase (pooler endpoint) | Supported | Leave `channel_binding`at its default; see notes below |

FaultWall negotiates the PostgreSQL wire-protocol SSLRequest handshake with the upstream, so managed providers that require TLS connect cleanly.

## Client configuration

FaultWall terminates TLS from your client and opens a separate TLS session to the upstream database. SCRAM-SHA-256-PLUS (channel binding) cryptographically ties authentication to a single TLS channel, so it cannot pass through any transparent TLS proxy. Every SCRAM-aware driver exposes a `channel_binding` flag to handle this. This is a property of the proxy model and applies to PgBouncer, ProxySQL, and other L7 Postgres proxies the same way.

Set the flag per provider:

| Provider | `sslmode` | `channel_binding` |
|---|---|---|
| Self-hosted Postgres | `require` (if TLS) or `disable` | any |
| PgBouncer | match upstream | `disable` |
| AWS RDS / Aurora | `require` | `disable` |
| Neon | `require` | `disable` |
| Supabase (pooler) | `require` | leave unset / `prefer` (Supabase rejects `disable`) |

Example connection string for RDS:

```
postgresql://user:pass@faultwall:5433/db?sslmode=require&channel_binding=disable
```

Or via environment variables:

```bash
PGSSLMODE=require
PGCHANNELBINDING=disable
```

Supported by libpq 13+, pgx, psycopg 3, JDBC, and node-postgres.

## Performance

FaultWall adds a fixed per-query cost for parsing and policy evaluation. On real cloud-latency paths, that cost is sub-millisecond and the throughput impact is small.

| Path | TPS | Avg latency | Overhead |
|---|---|---|---|
| Through FaultWall → cloud Postgres (RDS) | 11,006 | 0.91ms | +0.14ms / -15% TPS |
| Through FaultWall → localhost Postgres | 15,520 | 0.64ms | +0.49ms |

Benchmarked with `pgbench -c 10 -j 2 -T 15 -S`.

For typical AI-agent workloads (1–10 queries per second per agent, latency dominated by the model), the overhead is invisible. For very high-throughput OLTP co-located with the database, deploy FaultWall as a sidecar on the same host to minimize the fixed cost.

## Provider-specific notes

### AWS RDS / Aurora

Connect with `sslmode=require&channel_binding=disable`. Policy enforcement and the attack suite pass identically to self-hosted Postgres. On cloud latency the proxy overhead is roughly +0.14ms.

### Neon

Connect with `sslmode=require&channel_binding=disable`. SNI-based routing works without extra configuration.

### Supabase

Use the **pooler endpoint** (`aws-<n>-<region>.pooler.supabase.com:5432` or `:6543`), not the direct endpoint. Leave `channel_binding` at its default. Supabase's Supavisor pooler rejects `channel_binding=disable`.

Policy enforcement works end to end through the pooler, and agent identity (`PGAPPNAME`) is preserved.

Two operational notes:

- **Use long-lived connections.** Most agent frameworks hold one persistent connection per session, which works reliably. Workloads that open and close a new connection for every query can intermittently hit a Supavisor authentication error on rapid reconnect. Connection pooling on FaultWall's upstream side is on the roadmap to remove this entirely.
- **The direct endpoint is IPv6-only** on Supabase free-tier projects. Use the pooler endpoint (IPv4-compatible), add the paid IPv4 add-on, or run FaultWall on an IPv6-reachable host.

## Reproducing these results

Test artifacts are checked into `tests/compat/`:

- `compat_test.sh`, `attack_suite.sh` — connectivity and attack harnesses
- `seed.sql` — test schema and data
- `policies.yaml` — test policy
- `compat-*.log`, `attack-*.log` — raw run output
