#!/usr/bin/env bash
set -euo pipefail

# ── FaultWall Demo — 5 Attack Scenarios ──

PROXY_HOST="${PROXY_HOST:-localhost}"
PROXY_PORT="${PROXY_PORT:-5433}"
PG_USER="${PG_USER:-ghost}"
PG_PASS="${PG_PASS:-ghostpass}"
PG_DB="${PG_DB:-faultwall_demo}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

PASS=0
FAIL=0

banner() {
    echo ""
    echo -e "${CYAN}${BOLD}╔══════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}${BOLD}║ FaultWall Demo — Attack Scenarios ║${RESET}"
    echo -e "${CYAN}${BOLD}╚══════════════════════════════════════════════════╝${RESET}"
    echo ""
}

wait_for_proxy() {
    echo -e "${YELLOW}⏳ Waiting for proxy at ${PROXY_HOST}:${PROXY_PORT}...${RESET}"
    for i in $(seq 1 30); do
        if PGPASSWORD="$PG_PASS" psql -h "$PROXY_HOST" -p "$PROXY_PORT" -U "$PG_USER" -d "$PG_DB" \
            -o /dev/null -c "SELECT 1" \
            --set=application_name="agent:demo-agent:mission:read-feedback:token:demo-secret-789" 2>/dev/null; then
            echo -e "${GREEN} Proxy is ready!${RESET}"
            echo ""
            return 0
        fi
        sleep 1
    done
    echo -e "${RED}Proxy not ready after 30s${RESET}"
    exit 1
}

run_query() {
    local app_name="$1"
    local query="$2"
    PGPASSWORD="$PG_PASS" psql -h "$PROXY_HOST" -p "$PROXY_PORT" -U "$PG_USER" -d "$PG_DB" \
        --set=application_name="$app_name" \
        -c "$query" 2>&1 || true
}

test_case() {
    local num="$1"
    local icon="$2"
    local label="$3"
    local app_name="$4"
    local query="$5"
    local expect_blocked="$6"

    echo -e "${BOLD}── Test ${num}: ${icon} ${label} ──${RESET}"
    echo -e "   Agent:  ${CYAN}${app_name}${RESET}"
    echo -e "   Query:  ${CYAN}${query}${RESET}"

    result=$(run_query "$app_name" "$query")

    if echo "$result" | grep -qi "BLOCKED by FaultWall\|FATAL.*BLOCKED\|server closed the connection\|connection.*refused"; then
        actual="BLOCKED"
    else
        actual="ALLOWED"
    fi

    if [ "$expect_blocked" = "BLOCKED" ]; then
        expected_icon="BLOCKED"
        expected_label="BLOCKED"
    else
        expected_icon=""
        expected_label="ALLOWED"
    fi

    echo -e "   Expected: ${expected_icon} ${expected_label}"

    if [ "$actual" = "$expect_blocked" ]; then
        if [ "$actual" = "BLOCKED" ]; then
            echo -e "Actual: ${RED}BLOCKED${RESET} ${GREEN}PASS${RESET}"
        else
            echo -e "Actual: ${GREEN}ALLOWED${RESET} ${GREEN}PASS${RESET}"
        fi
        PASS=$((PASS + 1))
    else
        if [ "$actual" = "BLOCKED" ]; then
            echo -e "Actual: ${RED}BLOCKED${RESET} ${RED}FAIL${RESET}"
        else
            echo -e "Actual: ${GREEN}ALLOWED${RESET} ${RED}FAIL${RESET}"
        fi
        FAIL=$((FAIL + 1))
    fi
    echo ""
}

summary() {
    echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
    echo -e "${BOLD}  Summary: ${GREEN}${PASS} passed${RESET}, ${RED}${FAIL} failed${RESET} out of 5 tests"
    echo -e "${BOLD}══════════════════════════════════════════════════${RESET}"
    echo ""
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}

# ── Main ──

banner
wait_for_proxy

# Test 1: ALLOWED — Legitimate read
test_case 1 """ALLOWED — Legitimate read"\
    "agent:cursor-ai:mission:summarize-feedback:token:cursor-secret-123" \
    "SELECT * FROM feedback LIMIT 5" \
    "ALLOWED"

# Test 2: BLOCKED — DROP TABLE attack
test_case 2 "BLOCKED""BLOCKED — DROP TABLE attack"\
    "agent:cursor-ai:mission:summarize-feedback:token:cursor-secret-123" \
    "DROP TABLE users" \
    "BLOCKED"

# Test 3: BLOCKED — Rogue agent (not in policy)
test_case 3 "BLOCKED""BLOCKED — Rogue agent"\
    "agent:rogue-bot:mission:steal-data" \
    "SELECT * FROM users" \
    "BLOCKED"

# Test 4: BLOCKED — Dangerous function
test_case 4 "BLOCKED""BLOCKED — Dangerous function"\
    "agent:cursor-ai:mission:summarize-feedback:token:cursor-secret-123" \
    "SELECT pg_read_file('/etc/passwd')" \
    "BLOCKED"

# Test 5: BLOCKED — Auth token mismatch
test_case 5 "BLOCKED""BLOCKED — Auth token mismatch"\
    "agent:cursor-ai:mission:summarize-feedback:token:wrong-token" \
    "SELECT 1" \
    "BLOCKED"

summary
