package main

import "testing"

// Regression tests for docs/compatibility.md bug #3:
// When an agent carries a mission ID not in their missions map, and
// default_policy is "allow", CheckQuery must NOT return nil early —
// global checks (function blocklist, regproc cast, etc) must still run.
//
// Attack pattern reproduced in the Apr 27 compatibility audit across
// local, RDS, and Neon:
//   PGAPPNAME=agent:testagent:mission:attack:token:tok \
//     psql -c "SELECT pg_sleep(9999)"
// where testagent has profile=standard, auth_token=tok, but no "attack"
// entry in their missions map. Before this fix, pg_sleep returned the
// function result (bypass). After: pg_sleep is blocked by the global
// BlockedFunctions check.

func TestMissionEarlyReturn_GlobalBlocklistStillApplies(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy:    "allow",
			BlockedFunctions: []string{"pg_sleep", "pg_read_file", "lo_export"},
			Agents: map[string]AgentPolicy{
				"testagent": {
					AuthToken: "tok",
					Profile:   "standard",
					// Note: no "attack" mission defined — this is the bug repro
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.feedback"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "allow"},
		},
		enforcement: "enforce",
	}

	// Agent sends a mission not in their map. Pre-fix: CheckQuery returned
	// nil at the early-return, skipping the global BlockedFunctions check.
	identity := &AgentIdentity{
		AgentID:   "testagent",
		MissionID: "attack",
		Token:     "tok",
	}

	dangerous := []struct {
		name  string
		query string
	}{
		{"pg_sleep bypass", "SELECT pg_sleep(0.1)"},
		{"pg_read_file bypass", "SELECT pg_read_file('/etc/passwd')"},
		{"lo_export bypass", "SELECT lo_export(1234, '/tmp/pwn')"},
	}
	for _, tc := range dangerous {
		t.Run(tc.name, func(t *testing.T) {
			v := pe.CheckQuery(identity, tc.query, 0)
			if v == nil {
				t.Errorf("global blocked_function not applied for unknown-mission agent; query %q leaked", tc.query)
			} else if v.Reason == "" || (v.Reason[:8] != "blocked_" && v.Reason != "unrecognized_operation") {
				t.Errorf("unexpected violation reason for %q: %q", tc.query, v.Reason)
			}
		})
	}
}

// When default_policy=deny, the old behavior (block the unknown mission)
// must be preserved — this is a tightening fix, not a loosening fix.
func TestMissionUnknown_DefaultDenyStillBlocks(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "deny",
			Agents: map[string]AgentPolicy{
				"testagent": {
					AuthToken: "tok",
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.feedback"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "allow"},
		},
		enforcement: "enforce",
	}
	identity := &AgentIdentity{AgentID: "testagent", MissionID: "attack", Token: "tok"}
	v := pe.CheckQuery(identity, "SELECT 1", 0)
	if v == nil {
		t.Fatal("default_policy=deny must block unknown mission, got allow")
	}
	if v.Reason != "no_mission_policy" {
		t.Errorf("expected reason=no_mission_policy, got %q", v.Reason)
	}
}

// Known mission under default-allow: mission-scoped checks run normally.
// Regression check for the refactored control flow.
func TestMissionKnown_TableRestrictionStillApplies(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents: map[string]AgentPolicy{
				"testagent": {
					AuthToken: "tok",
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.feedback"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "allow"},
		},
		enforcement: "enforce",
	}
	identity := &AgentIdentity{AgentID: "testagent", MissionID: "read", Token: "tok"}

	// Allowed table: passes
	if v := pe.CheckQuery(identity, "SELECT * FROM public.feedback", 0); v != nil {
		t.Errorf("allowed table should pass, got %+v", v)
	}
	// Disallowed table: mission-scoped block fires
	v := pe.CheckQuery(identity, "SELECT * FROM public.secrets", 0)
	if v == nil {
		t.Fatal("non-mission table should be blocked")
	}
	if v.Reason != "table_not_in_mission" {
		t.Errorf("expected reason=table_not_in_mission, got %q", v.Reason)
	}
}

// Empty mission ID (agent without mission) under default-allow: everything
// passes unless a global check triggers. Regression check for control flow.
func TestNoMission_GlobalBlocklistStillApplies(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy:    "allow",
			BlockedFunctions: []string{"pg_sleep"},
			Agents: map[string]AgentPolicy{
				"testagent": {AuthToken: "tok"},
			},
			Unidentified: UnidentifiedPolicy{Policy: "allow"},
		},
		enforcement: "enforce",
	}
	identity := &AgentIdentity{AgentID: "testagent", Token: "tok"}
	if v := pe.CheckQuery(identity, "SELECT pg_sleep(0.1)", 0); v == nil {
		t.Error("global blocked_function must apply to no-mission agent")
	}
	if v := pe.CheckQuery(identity, "SELECT 1", 0); v != nil {
		t.Errorf("normal query must pass for no-mission agent, got %+v", v)
	}
}

// F2 regression: mission allowed-tables wildcards must work.
// Before the fix, isTableAllowed did exact-match only, so the "public.*"
// entry that `faultwall init` generates matched nothing and locked an
// identified agent out of every table (table_not_in_mission).
func TestMissionWildcard_AllowsSchemaGlob(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents: map[string]AgentPolicy{
				"testagent": {
					AuthToken: "tok",
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.*", "analytics.*"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "deny"},
		},
		enforcement: "enforce",
	}
	id := &AgentIdentity{AgentID: "testagent", MissionID: "read", Token: "tok"}

	for _, q := range []string{
		"SELECT * FROM public.messages",
		"SELECT * FROM public.users",
		"SELECT * FROM analytics.events",
	} {
		if v := pe.CheckQuery(id, q, 0); v != nil && v.Reason == "table_not_in_mission" {
			t.Errorf("wildcard public.*/analytics.* should allow %q, got block %+v", q, v)
		}
	}
	// A table outside the allowed schemas must still be blocked.
	if v := pe.CheckQuery(id, "SELECT * FROM secret.keys", 0); v == nil || v.Reason != "table_not_in_mission" {
		t.Errorf("secret.keys is outside public.*/analytics.* — expected table_not_in_mission, got %+v", v)
	}
}

// F2: bare "*" allows any table.
func TestMissionWildcard_StarAllowsAll(t *testing.T) {
	if !isTableAllowed("public.anything", []string{"*"}) {
		t.Error(`bare "*" should allow any table`)
	}
	if !isTableAllowed("weird.schema.table", []string{"*"}) {
		t.Error(`bare "*" should allow any table (multi-dot)`)
	}
}

// F1 regression: an unidentified connection (no agent: identity) must be
// denied when unidentified.policy == "deny" (the new secure-by-default).
func TestUnidentified_DenyBlocksAnonymousRead(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents:        map[string]AgentPolicy{},
			Unidentified:  UnidentifiedPolicy{Policy: "deny"},
		},
		enforcement: "enforce",
	}
	// identity == nil simulates a connection with no agent: prefix.
	v := pe.CheckQuery(nil, "SELECT id, name FROM public.users", 0)
	if v == nil {
		t.Fatal("unidentified connection under policy=deny must be blocked")
	}
	if v.Reason != "unidentified_connection" {
		t.Errorf("expected reason=unidentified_connection, got %q", v.Reason)
	}
}
