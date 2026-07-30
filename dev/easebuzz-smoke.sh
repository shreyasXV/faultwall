#!/usr/bin/env bash
# Easebuzz live demo smoke test — 3 scenarios + COST-FLAG check
# Connects via faultwall proxy (port 5433), expects deterministic blocks.
set -u
PROXY_DSN="postgres://ghost:ghostpass@localhost:5433/faultwall_demo?sslmode=disable"
PASS=0; FAIL=0

run_case () {
  local label="$1" appname="$2" sql="$3" expect="$4"   # expect = allow|deny
  local out
  out=$(PGAPPNAME="$appname" psql "$PROXY_DSN" -At -v ON_ERROR_STOP=0 -c "$sql" 2>&1)
  local rc=$?
  local result
  if [[ $rc -eq 0 ]]; then result="allow"; else result="deny"; fi
  if [[ "$result" == "$expect" ]]; then
    echo "[$label] expected=$expect got=$result"
    PASS=$((PASS+1))
  else
    echo "FAIL: [$label] expected=$expect got=$result :: $out"
    FAIL=$((FAIL+1))
  fi
}

echo "=== Scenario 1: refund-agent UPDATE without WHERE (must DENY: condition violation) ==="
run_case "refund-no-where" \
  "agent:refund-agent:mission:process-refund:token:refund-secret-easebuzz" \
  "UPDATE public.transactions SET status='refunded';" \
  "deny"

echo "=== Scenario 1a: refund-agent UPDATE with trivially-true WHERE (must DENY) ==="
run_case "refund-trivial-where" \
  "agent:refund-agent:mission:process-refund:token:refund-secret-easebuzz" \
  "UPDATE public.transactions SET status='refunded' WHERE 1=1;" \
  "deny"

echo "=== Scenario 1b: refund-agent WITH merchant_id filter (must ALLOW) ==="
run_case "refund-scoped" \
  "agent:refund-agent:mission:process-refund:token:refund-secret-easebuzz" \
  "UPDATE public.transactions SET status='refunded' WHERE merchant_id=1 AND id=101;" \
  "allow"

echo "=== Scenario 2: support-copilot reading aadhaar_number from kyc_documents (must DENY) ==="
run_case "support-aadhaar-exfil" \
  "agent:support-copilot:mission:answer-merchant-query:token:support-secret-easebuzz" \
  "SELECT aadhaar_number FROM public.kyc_documents LIMIT 5;" \
  "deny"

echo "=== Scenario 3: analytics-agent unbounded SELECT * (must ALLOW; QWM should log [COST-FLAG]) ==="
run_case "analytics-unbounded" \
  "agent:analytics-agent:mission:daily-rollup:token:analytics-secret-easebuzz" \
  "SELECT t.*, m.name FROM public.transactions t JOIN public.merchants m ON m.id=t.merchant_id WHERE t.amount_inr_paise > 0 ORDER BY t.created_at DESC;" \
  "allow"

echo "=== Scenario 4 (bonus): cross-agent identity — analytics-agent attempting UPDATE (must DENY) ==="
run_case "analytics-write-blocked" \
  "agent:analytics-agent:mission:daily-rollup:token:analytics-secret-easebuzz" \
  "UPDATE public.transactions SET status='success' WHERE id=1;" \
  "deny"

echo
echo "==== Result: $PASS pass / $FAIL fail ===="
[[ $FAIL -eq 0 ]] && exit 0 || exit 1
