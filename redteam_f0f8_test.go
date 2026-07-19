package main

import (
	"strings"
	"testing"
)

// redteam_f0f8_test.go — regression tests for the 9 parser-bypass families
// (F0–F8) documented in faultwall-agentic-attack/results/VERIFIED_BREACHES.md.
//
// Each case feeds the EXACT attack SQL through ParseQuery + the policy engine.
// Crucially, each family isolates the SMUGGLED element (a nested operation,
// table, or function that the report says never reaches the policy check) and
// asserts BOTH:
//   (a) ParseQuery surfaces that element (parsed.Operations/Tables/Functions), and
//   (b) a policy that blocks ONLY that smuggled element produces a violation.
//
// This prevents "passing for the wrong reason": e.g. F0's outer INSERT is not
// itself blocked here, so the block can only come from the hidden UPDATE on
// public.users actually surfacing. Before the parser tree-walk fix these are
// RED; after the fix they are GREEN.

func f0f8Identity() *AgentIdentity {
	return &AgentIdentity{AgentID: "attacker", MissionID: ""}
}

// engineBlocking builds an enforce-mode engine whose "attacker" agent blocks
// exactly the given operations/tables (legacy no-profile path) and whose global
// config blocks the given functions. Anything not listed is allowed, so a
// violation proves the smuggled element surfaced.
func engineBlocking(blockedOps, blockedTables, blockedFuncs []string) *PolicyEngine {
	return &PolicyEngine{
		enforcement: "enforce",
		config: &PolicyConfig{
			DefaultPolicy:    "deny",
			BlockedFunctions: blockedFuncs,
			Agents: map[string]AgentPolicy{
				"attacker": {
					BlockedOperations: blockedOps,
					BlockedTables:     blockedTables,
				},
			},
		},
	}
}

func hasStr(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}

func hasStrContains(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(strings.ToLower(s), strings.ToLower(want)) {
			return true
		}
	}
	return false
}

func TestRedTeamF0toF8(t *testing.T) {
	identity := f0f8Identity()

	tests := []struct {
		family string
		desc   string
		query  string
		// engine blocks ONLY the smuggled element (outer/wrapper op is allowed).
		engine *PolicyEngine
		// check verifies ParseQuery surfaced the smuggled element.
		check func(t *testing.T, p *ParsedQuery)
		// wantReasonContains: the violation reason substring proving the block
		// came from the smuggled element.
		wantReasonContains string
	}{
		{
			family: "F0",
			desc:   "CTE-on-INSERT hides UPDATE of blocked users table (priv-esc + hash leak)",
			query:  `WITH products AS (UPDATE public.users SET role='admin' WHERE email='alice@example.com' RETURNING password_hash AS ph) INSERT INTO public.feedback(customer_name,message,rating) SELECT 'x',ph,1 FROM products RETURNING message`,
			// INSERT (outer) is ALLOWED; only the hidden UPDATE + users table blocked.
			engine: engineBlocking([]string{"UPDATE"}, []string{"public.users"}, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStr(p.Operations, "UPDATE") {
					t.Errorf("F0: hidden UPDATE op not surfaced; Operations=%v", p.Operations)
				}
				if !hasStrContains(p.Tables, "users") {
					t.Errorf("F0: hidden public.users table not surfaced; Tables=%v", p.Tables)
				}
			},
			wantReasonContains: "blocked",
		},
		{
			family: "F0b",
			desc:   "CTE-on-INSERT reads blocked users table (SELECT CTE exfil)",
			query:  `WITH products AS (SELECT password_hash AS ph FROM public.users) INSERT INTO public.feedback(customer_name,message,rating) SELECT 'hack', ph, 1 FROM products RETURNING message`,
			// INSERT allowed; only users table blocked.
			engine: engineBlocking(nil, []string{"public.users"}, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStrContains(p.Tables, "users") {
					t.Errorf("F0b: hidden public.users table not surfaced; Tables=%v", p.Tables)
				}
			},
			wantReasonContains: "blocked_table",
		},
		{
			family: "F1",
			desc:   "MERGE WHEN MATCHED THEN DELETE hides DELETE operation",
			query:  `MERGE INTO public.feedback f USING public.feedback s ON f.id=s.id WHEN MATCHED THEN DELETE`,
			// MERGE (outer) allowed; only the smuggled DELETE action blocked.
			engine: engineBlocking([]string{"DELETE"}, nil, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStr(p.Operations, "DELETE") {
					t.Errorf("F1: MERGE action DELETE not surfaced; Operations=%v", p.Operations)
				}
			},
			wantReasonContains: "blocked_operation",
		},
		{
			family: "F1b",
			desc:   "MERGE exfil copies password_hash out of blocked users table",
			query:  `MERGE INTO public.feedback f USING public.users u ON f.id=u.id WHEN MATCHED THEN UPDATE SET message=u.password_hash`,
			// MERGE allowed; only users table blocked (source relation).
			engine: engineBlocking(nil, []string{"public.users"}, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStrContains(p.Tables, "users") {
					t.Errorf("F1b: users source table not surfaced; Tables=%v", p.Tables)
				}
			},
			wantReasonContains: "blocked_table",
		},
		{
			family: "F2",
			desc:   "DO block body runs blocked pg_sleep",
			query:  `DO $$ BEGIN PERFORM pg_sleep(0); END $$`,
			// DO (outer) allowed; only the pg_sleep function blocked.
			engine: engineBlocking(nil, nil, []string{"pg_sleep"}),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStrContains(p.Functions, "pg_sleep") {
					t.Errorf("F2: pg_sleep inside DO body not surfaced; Functions=%v", p.Functions)
				}
			},
			wantReasonContains: "blocked_function",
		},
		{
			family: "F3",
			desc:   "SubLink Testexpr hides blocked version() function",
			query:  `SELECT version() NOT IN (SELECT 'x')`,
			engine: engineBlocking(nil, nil, []string{"version"}),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStrContains(p.Functions, "version") {
					t.Errorf("F3: version() in SubLink Testexpr not surfaced; Functions=%v", p.Functions)
				}
			},
			wantReasonContains: "blocked_function",
		},
		{
			family: "F4",
			desc:   "EXECUTE argument expression hides blocked version()",
			query:  `EXECUTE pv(version())`,
			// EXECUTE (outer) allowed; only version() blocked.
			engine: engineBlocking(nil, nil, []string{"version"}),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStrContains(p.Functions, "version") {
					t.Errorf("F4: version() in EXECUTE args not surfaced; Functions=%v", p.Functions)
				}
			},
			wantReasonContains: "blocked_function",
		},
		{
			family: "F5",
			desc:   "SELECT ... INTO hides DDL (CREATE of new relation)",
			query:  `SELECT id INTO TEMP pw_sh FROM public.orders`,
			// SELECT allowed, orders table allowed; only the hidden CREATE blocked.
			engine: engineBlocking([]string{"CREATE"}, nil, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStr(p.Operations, "CREATE") {
					t.Errorf("F5: SELECT INTO hidden CREATE not surfaced; Operations=%v", p.Operations)
				}
			},
			wantReasonContains: "blocked_operation",
		},
		{
			family: "F6",
			desc:   "leading SET ROLE (blocked DCL) must not be silently stripped",
			query:  `SET ROLE agent_user; SELECT 1`,
			// SELECT allowed; only the leading SET_ROLE blocked.
			engine: engineBlocking([]string{"SET_ROLE"}, nil, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStr(p.Operations, "SET_ROLE") {
					t.Errorf("F6: leading SET ROLE not surfaced (stripped?); Operations=%v", p.Operations)
				}
			},
			wantReasonContains: "blocked_operation",
		},
		{
			family: "F7",
			desc:   "EXPLAIN ANALYZE + CTE-DELETE hides DELETE on blocked articles",
			query:  `EXPLAIN ANALYZE WITH d AS (DELETE FROM public.articles RETURNING id) SELECT 1`,
			// EXPLAIN/SELECT allowed, articles allowed; only the hidden DELETE op blocked.
			engine: engineBlocking([]string{"DELETE"}, nil, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStr(p.Operations, "DELETE") {
					t.Errorf("F7: EXPLAIN inner CTE DELETE not surfaced; Operations=%v", p.Operations)
				}
			},
			wantReasonContains: "blocked_operation",
		},
		{
			family: "F8",
			desc:   "TABLESAMPLE argument hides blocked pg_backend_pid()",
			query:  `SELECT count(*) FROM public.feedback TABLESAMPLE SYSTEM(pg_backend_pid()*0.0)`,
			engine: engineBlocking(nil, nil, []string{"pg_backend_pid"}),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStrContains(p.Functions, "pg_backend_pid") {
					t.Errorf("F8: pg_backend_pid in TABLESAMPLE arg not surfaced; Functions=%v", p.Functions)
				}
			},
			wantReasonContains: "blocked_function",
		},
		{
			family: "F-CTE",
			desc:   "general data-modifying CTE on SELECT hides DELETE",
			query:  `WITH d AS (DELETE FROM public.articles RETURNING id) SELECT * FROM d`,
			// SELECT allowed, articles allowed; only the hidden DELETE op blocked.
			engine: engineBlocking([]string{"DELETE"}, nil, nil),
			check: func(t *testing.T, p *ParsedQuery) {
				if !hasStr(p.Operations, "DELETE") {
					t.Errorf("F-CTE: CTE DELETE op not surfaced; Operations=%v", p.Operations)
				}
			},
			wantReasonContains: "blocked_operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.family+"_"+tt.desc, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if tt.check != nil {
				tt.check(t, parsed)
			}
			v := tt.engine.CheckQuery(identity, tt.query, 12345)
			if v == nil {
				t.Fatalf("%s BYPASS — query was ALLOWED but must be BLOCKED\n  SQL: %s\n  parsed.Operations=%v tables=%v functions=%v serverInfo=%v",
					tt.family, tt.query, parsed.Operations, parsed.Tables, parsed.Functions, parsed.ServerInfoFuncs)
			}
			if tt.wantReasonContains != "" && !strings.Contains(v.Reason, tt.wantReasonContains) {
				t.Errorf("%s blocked but reason %q does not contain %q\n  SQL: %s\n  parsed.Operations=%v tables=%v functions=%v",
					tt.family, v.Reason, tt.wantReasonContains, tt.query, parsed.Operations, parsed.Tables, parsed.Functions)
			}
		})
	}
}

// TestFailClosedOnParserPanic locks in the fail-closed fix (proxy.go
// safeCheckQueryWithContext, commit cd32477): if CheckQueryWithContext panics,
// the proxy must return a non-nil BLOCKED violation rather than allowing the
// query through.
func TestFailClosedOnParserPanic(t *testing.T) {
	// Use a nil PolicyEngine receiver to force a panic inside the checker
	// (checkQueryImpl dereferences pe.mu). safeCheckQueryWithContext must
	// recover and return a blocked violation.
	var pe *PolicyEngine
	identity := &AgentIdentity{AgentID: "attacker"}

	violation, _ := safeCheckQueryWithContext(pe, identity, "SELECT 1", nil)
	if violation == nil {
		t.Fatal("fail-closed regression: panic in policy check returned nil violation (query ALLOWED)")
	}
	if violation.Action != "blocked" {
		t.Errorf("fail-closed: expected Action=blocked, got %q (reason=%q)", violation.Action, violation.Reason)
	}
	if !strings.Contains(strings.ToLower(violation.Reason), "panic") {
		t.Errorf("fail-closed: expected panic reason, got %q", violation.Reason)
	}
}
