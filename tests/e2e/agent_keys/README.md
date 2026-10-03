# Agent keys E2E (proxy + control plane + real Postgres)

Scratch setup used on 2026-10-03 (local PG16 on 127.0.0.1:5544):

1. Control plane (feat/agent-keys) on a scratch DB with migrations 0001-0006 + 0009:
   `FWCP_LISTEN=127.0.0.1:18091 FWCP_DATABASE_URL=postgres://...@127.0.0.1:5544/fwk_cp_scratch FWCP_GOTRUE_JWT_SECRET=<test secret in cp.py> controlplane`
2. `python3 cp.py POST /v1/dashboard/provision '{}'`, then `POST /v1/dashboard/tokens` (tenant token) and
   `POST /v1/dashboard/agents '{"name":"support-agent","proxy_host":"127.0.0.1:15433","database":"fwk_up_scratch"}'` (save `.key` to /tmp/fwk-e2e/key1).
3. Proxy (this branch), enforce mode, syncing every 3s:
   `FAULTWALL_CONTROL_PLANE_URL=http://127.0.0.1:18091 FAULTWALL_CONTROL_PLANE_TOKEN=<tenant token> FW_POLICY_SYNC_INTERVAL=3s FW_UPSTREAM_USER=<db user> faultwall --proxy --listen 127.0.0.1:15433 --upstream 127.0.0.1:5544 --policies policies.yaml --mode enforce`
   (policies.yaml defines `legacy-bot` with a mission `m` for the backward-compat check.)
4. `/tmp/fw-pyvenv/bin/python e2e.py` (psycopg 3.3 + psql 16). `last-run.txt` is the 19/19 run.
