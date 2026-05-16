# RFC-001: Policy Auto-Generation & Query Weight Model (QWM)

**Authors:** Shreyas (CTO), Soumya (eBPF / ML)
**Status:** Draft, in design
**Target repos:** `faultwall-ebpf` (private — both features land here), `faultwall` (public, integration touchpoints)
**Owner of this doc:** Shreyas writes, Soumya drafts the PRs.
**Goal of this doc:** give Soumya enough context on the existing codebase + eBPF layer that he can open two PRs without having to reverse-engineer anything, and give us a shared spec to review against.

---

## 0. Why these two features

Today FaultWall ships two strong capabilities:

1. **Static policy enforcement** — humans write YAML, the proxy enforces it. Works, but doesn't scale: every new agent + every new app means a human authoring rules from scratch.
2. **Post-mortem observability** — eBPF tells us what *did* happen at the kernel level (CPU, IO, lock waits, runaway queries). Powerful, but reactive.

What's missing is the bridge between "we observed traffic" and "we have a policy" and "we can predict harm before the query hits the DB." That's the two features in this doc:

- **Feature A — Policy Auto-Generation:** monitor for N days → cluster queries by fingerprint → propose a YAML policy → human reviews → publish.
- **Feature B — Query Weight Model (QWM):** sub-1ms ML scorer that flags queries likely to cause infra harm, trained on data the monitor mode collects, with eBPF-derived labels as ground truth.

These are **complementary**, not redundant: policy auto-gen handles *known* query shapes (fingerprint allowlist), QWM handles the long tail of LLM-generated novel SQL that fingerprinting can't pattern-match.

---

## 1. Background — what already exists

Before any new code, here's the state of the world. Soumya, read this section carefully — a lot of plumbing is already in place and the PRs should reuse it, not rebuild.

### 1.1 Public repo: `faultwall` (Go, MIT)

Single binary, ~20 Go files at the repo root. Key modules:

| File | Purpose | Relevant to this RFC |
|---|---|---|
| `proxy.go` | Inline L7 proxy. Speaks pgproto3, parses every Simple + Extended query before forwarding to Postgres. | **Yes** — both features hook in here. |
| `parser.go` | Wraps `pg_query_go/v6` (real Postgres C parser). Returns `ParsedQuery{Operation, Tables, Functions, ...}`. | **Yes** — fingerprinting upgrade lands here. |
| `policy.go` | YAML loader + `EvaluateQuery()`. Profiles: permissive / standard / strict + per-agent overrides. ~26 KB. | **Yes** — auto-gen emits this YAML format. |
| `collector.go` | Runs every 10s against `pg_stat_statements`, builds `QueryStat{QueryFingerprint, Calls, MeanTimeMs, ...}`. **Already has a `fingerprintQuery()` function** (regex-based). | **Yes** — we replace its regex fingerprint with `pg_query.Fingerprint()`. |
| `history.go` | Per-query event log written from the proxy. | **Yes** — auto-gen reads from here. |
| `predictor.go` | Existing simple anomaly predictor (rule-based). | **Yes** — QWM v1 lives next to this, eventually replaces it. |
| `anomaly.go`, `detector.go`, `tuner.go` | Statistical baselines for query latency. | **Reference** — feature engineering ideas. |
| `mcp.go` | MCP server exposing tenant health to agents. | Not directly touched. |
| `dashboard.go`, `templates/` | Self-hosted dashboard. | Touched in phase 3 (review UI). |

**Existing fingerprint code (`collector.go:43`):**
```go
func fingerprintQuery(query string) string {
    result := paramRe.ReplaceAllString(query, "$?")          // $1 → $?
    result = stringLiteralRe.ReplaceAllString(result, "'?'") // 'foo' → '?'
    result = numericLiteralRe.ReplaceAllString(result, "?")  // 47 → ?
    result = whitespaceRe.ReplaceAllString(strings.TrimSpace(result), " ")
    return result
}
```
This is regex-only. It's fine for `pg_stat_statements` rollups but it's brittle for our use case: it doesn't normalize identifier casing, doesn't handle `$1` vs literal `1` as the same shape, and breaks on multi-statement queries. **Both new features require an AST-level fingerprint, so step zero of either PR is upgrading this.**

**Existing policy YAML schema (`policies.yaml`):**
```yaml
default_policy: deny
blocked_functions: [pg_read_file, dblink_exec, ...]
profiles:
  standard:
    extends: standard
    blocked_categories: [DCL, DDL, ADMIN, EXTENSION, FUNCTION]
    conditions: [DELETE must include WHERE, UPDATE must include WHERE]
agents:
  analytics-agent:
    profile: standard
    profile_overrides:
      allow: [SELECT]
      block: [DELETE, UPDATE]
    blocked_tables: [users.password_hash, users.ssn]
    missions:
      reporting:
        allowed_tables: [orders, products]
```

Auto-gen writes this format. Anything we propose has to round-trip through the existing loader unchanged.

### 1.2 Private repo: `faultwall-ebpf` (still branded SchemaGhost internally)

What's actually shipped, per memory and prior validation on EC2:

- **~130 LOC of C** with **USDT (Userland Statically Defined Tracing) probes** wired into Postgres + **kernel tracepoints** for `sched_switch`, `block_rq_issue`, `block_rq_complete`, lock acquisition.
- Per-query **CPU time + IO bytes + lock-wait time** attribution at the kernel level. <1% overhead validated under load.
- Multi-tenant observability dashboard backed by this data.
- Auto-throttling of runaway queries (statistical anomaly trigger → SIGTERM at the connection level).
- MCP server for agents to query tenant health.
- Slack alerts for outliers.
- Statistical anomaly detection (baselines, no ML).

**What's NOT there yet:**
- No persistent labeled training set. Anomaly events are detected and alerted but not stored as `(query_fingerprint, features, label)` tuples for ML.
- No ML inference path. Everything is rule-based / threshold-based.
- No userspace handle that the proxy can call into for real-time query scoring under 1ms.

The eBPF layer is our **ground truth oracle**: it knows, after the fact, whether a query actually caused harm. That makes it the perfect label generator for QWM.

### 1.3 What runs in production today, query lifecycle

```
Agent
  │  (libpq / psycopg / pg JS)
  ▼
faultwall proxy (pgproto3) ──► parser.go (pg_query_go AST)
                              │
                              ▼
                        policy.go EvaluateQuery()
                              │
                  ┌───────────┴───────────┐
                  │                       │
              ALLOW                    DENY
                  │                       │
                  ▼                    error to client
          Postgres backend
                  │
                  ▼
          eBPF probes (USDT + tracepoints, private repo)
                  │
                  ▼
          per-query CPU/IO/lock metrics
                  │
                  ▼
          anomaly detector → Slack / throttle
```

**Both new features fit cleanly into this pipeline:**
- Auto-gen reads from `history.go` (allow/deny events) + `collector.go` (fingerprints) + the eBPF metrics stream.
- QWM inserts a 4th decision step between `policy.go` and ALLOW: `if QWM(query, infra_state) > threshold → flag/block`.

---

## 2. Feature A — Policy Auto-Generation

### 2.1 Flow (agreed in Discord)

```
[Day 0]   user deploys faultwall in MONITOR mode
[Day 0-7] proxy logs every query: (agent_id, fingerprint, tables, ops, latency, eBPF metrics)
[Day 7]   `faultwall policy generate --window 7d` runs
            ├─ groups events by (agent_id, fingerprint)
            ├─ classifies each group: SAFE / RISKY / UNKNOWN
            ├─ emits draft policies.yaml.proposed
[Day 7+]  human opens dashboard /policy/review
            ├─ inline diff vs current policies.yaml
            ├─ approve / reject / edit per-agent, per-fingerprint
[Day 7+]  human clicks Publish → atomic write + proxy hot-reload
```

### 2.2 Data model

New table (or JSONL file in `~/.faultwall/`, behind an interface so we can swap):

```go
type FingerprintObservation struct {
    AgentID         string
    Fingerprint     string    // pg_query.Fingerprint() output, hex
    NormalizedSQL   string    // the canonical form, for human review
    Operation       string    // SELECT / INSERT / ...
    Tables          []string
    Functions       []string
    FirstSeen       time.Time
    LastSeen        time.Time
    Count           int64
    P50LatencyMs    float64
    P95LatencyMs    float64
    RowsTouchedP95  int64     // from eBPF
    LockWaitMsP95   float64   // from eBPF
    IOBytesP95      int64     // from eBPF
    Verdict         string    // empty until classified
}
```

### 2.3 Classifier (deterministic, no ML for v1)

Per `(agent_id, fingerprint)` group:

```
SAFE if:
  - count >= MIN_OCCURRENCES (default 50)
  - operation in {SELECT, INSERT}
  - tables ∩ sensitive_tables = ∅   (sensitive_tables = anything matching *.password, *.ssn, *.token, *.secret heuristic + user-marked)
  - p95_latency < 1s
  - no eBPF anomaly events tied to this fingerprint in window
  - functions ∩ blocked_functions = ∅

RISKY if:
  - operation in {DELETE, UPDATE, DROP, TRUNCATE}, OR
  - hits sensitive table, OR
  - p95_latency > 5s, OR
  - any eBPF anomaly tied to this fingerprint
  → never auto-allow, always require human

UNKNOWN otherwise → human review
```

### 2.4 Output: draft `policies.yaml.proposed`

```yaml
# Auto-generated by faultwall policy generate
# Window: 2026-05-09 to 2026-05-16
# Total fingerprints observed: 1,247
# Auto-classified SAFE: 892 / RISKY: 41 / UNKNOWN: 314

agents:
  analytics-agent:
    description: "Auto-generated from 7-day monitor window"
    profile: strict
    allowed_fingerprints:        # NEW field, additive to existing schema
      - hash: "a3f2c8e1"
        sql: "SELECT * FROM orders WHERE user_id = $? AND created_at > $?"
        seen: 4821
        verdict: safe
      - hash: "b7d1e9f4"
        sql: "SELECT count(*) FROM products WHERE category = $?"
        seen: 891
        verdict: safe
    pending_review:              # NEW field, surfaced in dashboard
      - hash: "c4a8b2d6"
        sql: "DELETE FROM sessions WHERE expires_at < now()"
        seen: 12
        verdict: risky
        reason: "DELETE on sessions table, never seen before in this agent"
```

### 2.5 Schema changes to `policy.go`

Additive, no breakage:
- `AgentPolicy.AllowedFingerprints []FingerprintRule`
- `AgentPolicy.PendingReview []FingerprintRule` (informational, never enforced)
- `EvaluateQuery()` short-circuits to ALLOW if `fingerprint(query) ∈ AllowedFingerprints` AND existing profile checks would also pass (defense in depth — fingerprint match is *additive* allow, never *override* deny).

### 2.6 PR scope (Soumya, this is the first PR)

**Repo: `faultwall-ebpf`** (per Soumya's call — both features go here, public repo gets the integration commit only when ready)

1. New package `policygen/`:
   - `fingerprint.go` — wraps `pg_query.Fingerprint()`, replaces `collector.go:fingerprintQuery()`.
   - `observation.go` — the data model + JSONL writer.
   - `classifier.go` — the SAFE/RISKY/UNKNOWN logic.
   - `generator.go` — emits `policies.yaml.proposed`.
2. New CLI subcommand `faultwall policy generate --window 7d --in /var/log/faultwall/observations.jsonl --out ./policies.yaml.proposed`.
3. Hook into proxy: every successful query writes a `FingerprintObservation` row.
4. Hook into eBPF post-mortem: anomaly events attach their fingerprint, written to the same store.
5. Tests:
   - golden test: feed N queries → assert deterministic YAML output.
   - round-trip test: load auto-generated YAML through existing `policy.go` loader.

### 2.7 Out of scope for this PR
- Dashboard review UI (phase 3).
- Multi-tenant control plane (phase 3).
- Diff/merge tooling against existing policies.yaml (phase 2).

---

## 3. Feature B — Query Weight Model (QWM)

### 3.1 Premise

LLM-generated SQL is unbounded — fingerprinting cannot enumerate it. We need a model that, given a query + current infra state, predicts probability of harm in **<1ms** so we don't break our latency moat.

Soumya's framing is exactly right:
> eBPF gives a post mortem. QWM can start as initial flag and grow into preventing queries from running.

### 3.2 Model: logistic regression, per-tenant

Why LR for v1:
- Inference is a single dot product + sigmoid → microseconds, not milliseconds.
- Interpretable: every flag comes with feature contributions ("flagged because: high active_connections + JOIN on unindexed column + agent has no prior history with this fingerprint").
- Trains on small data; we don't need 1M samples per tenant.
- Easy to ship to a single Go binary (no ONNX, no torch dep).

### 3.3 Features (v1, ~12 dimensions)

| Feature | Source | Why |
|---|---|---|
| `fingerprint_id_topK_onehot` | `pg_query.Fingerprint()`, top-K most frequent per tenant | captures known-query baseline |
| `is_novel_fingerprint` | bool, fingerprint never seen before | catches LLM novelty |
| `op_type` | parser.go ParsedQuery.Operation | DELETE/UPDATE inherently riskier |
| `touches_sensitive_table` | parser.go Tables ∩ sensitive_set | PII risk |
| `n_joins` | AST count | join explosion risk |
| `has_subquery` | AST flag | nested risk |
| `active_connections_now` | collector.go Overview | infra load |
| `avg_query_time_60s` | collector.go rolling | infra load |
| `time_of_day_bucket` | clock | weekend-batch vs business hours |
| `agent_id_onehot` | proxy session | per-agent baseline |
| `recent_anomaly_rate_agent` | eBPF, last 1h | agent currently misbehaving |
| `current_lock_contention` | eBPF, last 60s | infra load (kernel signal) |

The last two are why this lives in the eBPF repo — userspace alone can't get them cheaply.

### 3.4 Label generation (where eBPF earns its keep)

Every query that runs gets a post-hoc label from the eBPF data:

```
label = 1 (HARM) if any of:
  - p95-exceeding lock_wait_ms (>500ms)
  - rows_touched > tenant_threshold (default 100k)
  - caused throttle/SIGTERM
  - caused query_time > tenant p99 by >3σ
  - block_io_bytes > tenant threshold

label = 0 otherwise
```

This is the dataset. We don't need humans labeling anything — eBPF labels for free, continuously.

### 3.5 Training

- Per-tenant, retrained weekly via cron (or on demand).
- Stored as `~/.faultwall/qwm/<tenant_id>.weights.json` — just a vector of floats + intercept + feature schema version.
- Cold-start: until tenant has ≥1000 observations, fall back to a global model trained on aggregated open-source workloads (we ship a default).

### 3.6 Inference path (the <1ms requirement)

```go
// proxy.go, after policy.EvaluateQuery returns ALLOW
score := qwm.Score(parsedQuery, infraState)  // <100µs target
if score > tenant.Config.QWMBlockThreshold {
    // v1: just flag, do not block
    history.LogFlag(query, score, qwm.TopFeatures(score))
    metrics.QWMFlags.Inc()
    // forward to DB anyway
}
forwardToDB(query)
```

Concrete latency budget:
- AST parse: already done by policy step, free.
- Feature vector build: ~20µs (mostly hash lookups).
- Dot product over ~50 weights: ~5µs.
- Sigmoid: ~1µs.
- Total: well under 100µs. We have 9× headroom on our 1ms target.

### 3.7 Rollout (three stages, opt-in)

1. **Shadow mode** (default): score every query, log it, never act on it. Operator gets a daily report: "QWM would have flagged 47 queries this week. Here are the top 10 with explanations."
2. **Flag mode**: write flag to `history.go`, surface in dashboard with "QWM thinks this query will hurt you" + top contributing features. Still doesn't block.
3. **Enforce mode** (opt-in per tenant, gated on >90% precision over their last 30 days of shadow data): high-confidence flags become DENY.

### 3.8 PR scope (Soumya, second PR — can land in parallel with PR 1)

**Repo: `faultwall-ebpf`**

1. New package `qwm/`:
   - `features.go` — feature extraction from `ParsedQuery` + infra state.
   - `model.go` — LR weights struct, Score() method, Train() method.
   - `labels.go` — eBPF event → label mapping.
   - `store.go` — load/save `<tenant>.weights.json`.
2. New CLI subcommand `faultwall qwm train --tenant <id> --window 30d`.
3. Background ticker in main proxy: every Sunday 02:00 UTC, retrain all tenants.
4. Proxy hook: shadow-mode scoring on every ALLOW path, written to `history.go`.
5. Tests:
   - synthetic dataset → assert weights converge.
   - inference benchmark: assert p99 < 200µs over 10k queries.
   - integration test: shadow mode does not change any decisions.

### 3.9 Out of scope for v1
- Anything beyond logistic regression (no GBM, no neural).
- Cross-tenant model sharing (privacy-sensitive, defer).
- Online learning / streaming updates (batch retraining only).
- Feature drift monitoring (phase 3).

---

## 4. Sequencing

```
PR 1: AST fingerprint upgrade        (small, prereq for both features)
PR 2: Policy auto-gen                 (Feature A, Soumya owns)
PR 3: QWM (shadow mode only)          (Feature B, Soumya owns)
─── merge + dogfood for 2 weeks on our own infra ───
PR 4: Dashboard review UI for both    (Shreyas owns, public repo)
PR 5: QWM flag mode                   (Soumya, after shadow data looks clean)
PR 6: Website e2e (per Soumya)        (after both features tested in prod)
─── decision point: turn QWM enforce mode on for design partners ───
```

PR 1 and PR 2 can be one PR if Soumya prefers. PR 3 is independent and can land in parallel.

---

## 5. Open questions for review

1. **Storage backend for observations / labels.** JSONL on disk for v1, or do we want SQLite from day one? (Shreyas leaning JSONL for simplicity, SQLite when we hit ~10M rows.)
2. **Sensitive table heuristic.** Auto-detect via column name regex (`*password*`, `*ssn*`, `*token*`, `*secret*`)? Or require user to mark? Probably both: auto-detect + dashboard flag.
3. **Default QWM threshold.** 0.7 too aggressive? 0.9 too cautious? Pick based on shadow-mode data from our own deployment first.
4. **eBPF data export format.** Currently the eBPF layer holds metrics in-memory + Slack alerts. We need a stable shape for QWM labels + auto-gen consumption. Soumya: propose the schema in the PR.
5. **Multi-statement queries.** Fingerprint each statement separately, or treat as a single fingerprint? Lean: separate, then group by transaction.

---

## 6. Non-goals

- We are not building a general-purpose ML platform. Logistic regression, weekly batch retrain, done.
- We are not blocking anything in v1. Shadow → flag → opt-in enforce. We earn the right to block by being right >90% of the time on the operator's own data.
- We are not inventing new policy syntax. The auto-gen output round-trips through the existing `policies.yaml` loader — anything we add is additive (`allowed_fingerprints`, `pending_review`).
- We are not coupling the two features at the code level. Auto-gen is deterministic and shippable without QWM. QWM is shippable in shadow mode without auto-gen. They share the fingerprint primitive and that's it.

---

## 7. Success criteria

**Feature A (Auto-gen):**
- After 7-day monitor on our own dev DB, `faultwall policy generate` produces a YAML that, when published, blocks zero of our legitimate queries and would have caught at least one of our red-team adversarial queries.
- Generation completes in <10s on 1M observation events.
- Generated YAML loads cleanly through existing `policy.go` with no schema migration.

**Feature B (QWM):**
- Shadow-mode inference p99 < 200µs.
- After 30 days of shadow on our dev DB, precision on auto-labeled "harm" events ≥ 80% at threshold 0.7.
- One design partner agrees to run shadow mode in their staging by end of Q3.

---

## 8. Action items

- [ ] Soumya: open PR 1 (AST fingerprint upgrade) in `faultwall-ebpf`, with the public-repo migration plan in the PR description.
- [ ] Soumya: open PR 2 (policy auto-gen) — can stack on PR 1.
- [ ] Soumya: open PR 3 (QWM shadow mode) — independent, parallel.
- [ ] Shreyas: review schema additions to `policy.go`, make sure backward compat holds.
- [ ] Shreyas: dogfood plan — point our own staging proxy at this branch for 2 weeks once PR 2 + PR 3 merge.
- [ ] Both: revisit this doc after PRs land, update §5 open questions with what we learned.

---

*This doc is the source of truth for these two features until the PRs are merged. Edit in place, don't fork.*
