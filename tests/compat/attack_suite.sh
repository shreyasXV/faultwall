#!/bin/bash
# FaultWall Attack Suite
# Verifies security enforcement works per deployment mode
set -u
TARGET="${1:?usage}"
HOST="${2}"
PORT="${3}"
DB="${4}"
USER="${5}"
PASS="${6}"

PSQL=/opt/homebrew/opt/postgresql@16/bin/psql
OUT=/tmp/attack-${TARGET}.log
echo "==== ATTACK SUITE: $TARGET ====" > $OUT
echo "Target: $HOST:$PORT" >> $OUT
echo "" >> $OUT

# Use testagent with valid token — testagent has standard profile + blocked tables
IDENTITY="agent:testagent:mission:attack:token:test-secret-abc123"

PASS_COUNT=0
FAIL_COUNT=0

attack() {
    local name="$1"
    local sql="$2"
    local expect_block="$3"  # 1 = should be blocked, 0 = should succeed

    echo "---- ATTACK: $name ----" >> $OUT
    echo "SQL: $sql" >> $OUT
    local output
    output=$(PGPASSWORD="$PASS" PGAPPNAME="$IDENTITY" $PSQL -h "$HOST" -p "$PORT" -U "$USER" -d "$DB" -c "$sql" 2>&1)
    local ec=$?
    echo "Exit: $ec" >> $OUT
    echo "$output" | head -5 >> $OUT

    local verdict
    if [ "$expect_block" = "1" ]; then
        if [ $ec -ne 0 ] || echo "$output" | grep -qiE "policy|blocked|denied|faultwall"; then
            verdict="BLOCKED (correct)"; PASS_COUNT=$((PASS_COUNT+1))
        else
            verdict="BYPASSED — SECURITY FAILURE"; FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    else
        if [ $ec -eq 0 ]; then
            verdict="ALLOWED (correct)"; PASS_COUNT=$((PASS_COUNT+1))
        else
            verdict="UNEXPECTED BLOCK"; FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    fi
    echo "VERDICT: $verdict" >> $OUT
    echo "" >> $OUT
    printf "%-50s %s\n" "$name" "$verdict"
}

# ── Attack 1: Exfiltration via blocked table (schema-qualified) ──
attack "exfil_users_qualified" "SELECT COUNT(*) FROM public.users" 1
attack "exfil_payments_qualified" "SELECT * FROM public.payments LIMIT 1" 1

# ── Attack 2: Exfiltration via bare table name (schema bypass) ──
attack "exfil_users_bare" "SELECT COUNT(*) FROM users" 1
attack "exfil_payments_bare" "SELECT COUNT(*) FROM payments" 1

# ── Attack 3: pg_sleep DoS ──
attack "dos_pg_sleep" "SELECT pg_sleep(0.1)" 1

# ── Attack 4: Destructive DDL from standard-profile agent ──
attack "destructive_drop" "DROP TABLE feedback" 1
attack "destructive_truncate" "TRUNCATE feedback" 1

# ── Attack 5: Regproc obfuscation ──
attack "regproc_bypass" "SELECT 'pg_sleep'::regproc" 1

# ── Attack 6: Multi-statement piggyback ──
attack "multi_stmt_drop" "SELECT 1; DROP TABLE feedback" 1

# ── Attack 7: Trivial WHERE ──
attack "trivial_where_delete" "DELETE FROM feedback WHERE 1=1" 1

# ── Attack 8: Information disclosure ──
attack "info_version" "SELECT version()" 1
attack "info_current_setting" "SELECT current_setting('data_directory')" 1

# ── Attack 9: Legitimate queries should still work ──
attack "legit_select_feedback" "SELECT COUNT(*) FROM feedback" 0
attack "legit_insert_feedback" "INSERT INTO feedback(user_id, body) VALUES (1, 'test')" 0

echo "" >> $OUT
echo "===========" >> $OUT
echo "SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed" >> $OUT
echo "===========" >> $OUT

echo ""
echo "==========================================="
echo "$TARGET: $PASS_COUNT enforcement-correct, $FAIL_COUNT enforcement-failures"
echo "Full log: $OUT"
echo "==========================================="
exit $FAIL_COUNT
