package main

import "testing"

// F6 (benchmark ident-01): an agent using the legacy blocked_operations list
// (no profile) must not be able to SET ROLE / GRANT just because the list
// omitted it. DCL is default-deny in legacy mode, including when trailed by
// another statement.
func TestF6LegacyModeDefaultDeniesDCL(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{Agents: map[string]AgentPolicy{
		"demo-agent": {
			AuthToken:         "tok",
			Missions:          map[string]MissionPolicy{"m": {Tables: []string{"public.feedback"}}},
			BlockedOperations: []string{"DROP"},
		},
	}})
	ident := &AgentIdentity{AgentID: "demo-agent", MissionID: "m", Token: "tok"}
	for _, q := range []string{
		"SET ROLE agent_user; SELECT 1",
		"SET ROLE agent_user",
		"SET SESSION AUTHORIZATION agent_user; SELECT 1",
		"SELECT 1; SET ROLE agent_user",
	} {
		if v := pe.CheckQueryWithParsed(ident, ParseQuery(q), q, 0); v == nil {
			t.Errorf("expected block for %q", q)
		}
	}
	for _, q := range []string{"SELECT count(*) FROM public.feedback", "SET statement_timeout = 1000; SELECT count(*) FROM public.feedback"} {
		if v := pe.CheckQueryWithParsed(ident, ParseQuery(q), q, 0); v != nil {
			t.Errorf("expected allow for %q, got %s", q, v.Reason)
		}
	}
}
