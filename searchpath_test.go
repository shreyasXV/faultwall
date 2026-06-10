package main

import (
	"reflect"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// REAL-F2: search_path-aware ALLOW path
// ─────────────────────────────────────────────────────────────────────────────

// withRealF2 toggles the gate around fn and restores prior state.
func withRealF2(t *testing.T, on bool, fn func()) {
	t.Helper()
	prev := IsSearchPathAwareAllowOn()
	defer setSearchPathAwareAllow(prev)
	setSearchPathAwareAllow(on)
	// Shipped F2 must be ON for the search-path path to consult the
	// schema list at all (the gate is only consulted when normalize=true
	// or when the unqualified table reaches isTableAllowedWithContext via
	// CheckQuery — which always passes the live shipped flag). We toggle
	// it explicitly to keep tests self-contained.
	prevShipped := IsUnqualifiedAllowNormalizationOn()
	defer setUnqualifiedAllowNormalization(prevShipped)
	setUnqualifiedAllowNormalization(true)
	fn()
}

// (1) search_path=["public"], bare "feedback" matches allow ["public.*"].
func TestRealF2_Contract1_PublicSearchPath_PublicStarAllow(t *testing.T) {
	withRealF2(t, true, func() {
		if !isTableAllowedWithContext("feedback", []string{"public.*"}, true, []string{"public"}) {
			t.Error("contract 1: bare 'feedback' must match allow=[public.*] with search_path=[public]")
		}
	})
}

// (2) search_path=["myschema"], bare "feedback" matches allow ["myschema.*"].
func TestRealF2_Contract2_NonPublicSearchPath_MatchingSchemaStarAllow(t *testing.T) {
	withRealF2(t, true, func() {
		if !isTableAllowedWithContext("feedback", []string{"myschema.*"}, true, []string{"myschema"}) {
			t.Error("contract 2: bare 'feedback' must match allow=[myschema.*] with search_path=[myschema]")
		}
	})
}

// (3) search_path=["myschema"], bare "feedback" does NOT match ["public.users"].
func TestRealF2_Contract3_NonPublicSearchPath_PublicUsersOnly(t *testing.T) {
	withRealF2(t, true, func() {
		if isTableAllowedWithContext("feedback", []string{"public.users"}, true, []string{"myschema"}) {
			t.Error("contract 3: bare 'feedback' must NOT match allow=[public.users] with search_path=[myschema]")
		}
	})
}

// (4) search_path=["myschema","public"], bare "feedback" matches allow
// ["public.feedback"] via the second entry.
func TestRealF2_Contract4_SecondEntryResolves(t *testing.T) {
	withRealF2(t, true, func() {
		if !isTableAllowedWithContext("feedback", []string{"public.feedback"}, true, []string{"myschema", "public"}) {
			t.Error("contract 4: search_path=[myschema,public] must allow 'feedback' via public.feedback")
		}
	})
}

// (5) BLOCK path: search_path=["secret"], bare "keys" must still be blocked
// when blocklist contains "secret.keys". This proves we never loosen
// blocking through the search-path-aware path.
func TestRealF2_Contract5_BlockNotLoosened(t *testing.T) {
	withRealF2(t, true, func() {
		if !isTableBlockedWithContext("keys", []string{"secret.keys"}, []string{"secret"}) {
			t.Error("contract 5: bare 'keys' must remain blocked under blocklist=[secret.keys] with search_path=[secret]")
		}
	})
}

// (6) parser smoke tests.
func TestRealF2_Contract6_Parser(t *testing.T) {
	st := NewSearchPathState()
	if !reflect.DeepEqual(st.Schemas(), []string{"public"}) {
		t.Fatalf("default search_path should be [public], got %v", st.Schemas())
	}
	if !st.ApplySearchPathStatement("SET search_path TO a, b;") {
		t.Fatal("expected SET search_path TO a, b to be recognized")
	}
	if !reflect.DeepEqual(st.Schemas(), []string{"a", "b"}) {
		t.Fatalf("expected [a b], got %v", st.Schemas())
	}
	if !st.ApplySearchPathStatement("RESET search_path") {
		t.Fatal("expected RESET search_path to be recognized")
	}
	if !reflect.DeepEqual(st.Schemas(), []string{"public"}) {
		t.Fatalf("RESET should return to [public], got %v", st.Schemas())
	}
	st.Set([]string{"x"})
	if !st.ApplySearchPathStatement("SET search_path TO DEFAULT") {
		t.Fatal("expected SET search_path TO DEFAULT to be recognized")
	}
	if !reflect.DeepEqual(st.Schemas(), []string{"public"}) {
		t.Fatalf("DEFAULT should restore [public], got %v", st.Schemas())
	}
}

// Parser: quoted identifiers preserve case. The matching downstream is
// case-insensitive but the parser must keep the user's spelling.
func TestRealF2_Parser_QuotedIdent(t *testing.T) {
	st := NewSearchPathState()
	st.ApplySearchPathStatement(`SET search_path TO "MySchema", "mixed Case"`)
	got := st.Schemas()
	want := []string{"MySchema", "mixed Case"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("quoted ident parse: got %v want %v", got, want)
	}
}

// Parser: `$user` is preserved; matching skips it.
func TestRealF2_Parser_DollarUser(t *testing.T) {
	st := NewSearchPathState()
	st.ApplySearchPathStatement(`SET search_path TO "$user", public`)
	got := st.Schemas()
	if len(got) != 2 || !strings.EqualFold(got[0], "$user") || got[1] != "public" {
		t.Errorf("$user parse: got %v want [$user public]", got)
	}
	// And the matcher must skip $user gracefully and still find public.feedback.
	withRealF2(t, true, func() {
		if !isTableAllowedWithContext("feedback", []string{"public.feedback"}, true, got) {
			t.Error("$user entry should be skipped, fallthrough to public must allow feedback")
		}
	})
}

// Parser: SET with `=` operator and SET LOCAL/SESSION qualifiers.
func TestRealF2_Parser_VariantSyntax(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"SET search_path = a", []string{"a"}},
		{"SET LOCAL search_path TO a, b", []string{"a", "b"}},
		{"SET SESSION search_path TO c", []string{"c"}},
		{"set search_path to A, B;", []string{"a", "b"}},
	}
	for _, tc := range cases {
		st := NewSearchPathState()
		if !st.ApplySearchPathStatement(tc.in) {
			t.Errorf("expected %q recognized", tc.in)
			continue
		}
		if !reflect.DeepEqual(st.Schemas(), tc.want) {
			t.Errorf("%q → %v, want %v", tc.in, st.Schemas(), tc.want)
		}
	}
}

// Parser: non-search_path queries leave state untouched.
func TestRealF2_Parser_NonMatchingQuery(t *testing.T) {
	st := NewSearchPathState()
	if st.ApplySearchPathStatement("SELECT * FROM feedback") {
		t.Error("SELECT must not be treated as a search_path mutation")
	}
	if st.ApplySearchPathStatement("SET application_name = 'x'") {
		t.Error("SET application_name must not be treated as a search_path mutation")
	}
	if !reflect.DeepEqual(st.Schemas(), []string{"public"}) {
		t.Errorf("state should be untouched, got %v", st.Schemas())
	}
}

// Fallback: gate OFF → behaves like shipped F2 (public-only normalization).
// search_path=["myschema"] is ignored; bare "feedback" matches "public.*"
// (because shipped F2 normalizes to public.feedback) and does NOT match
// "myschema.*" (the search-path-aware lookup is gated).
func TestRealF2_Fallback_GateOffBehavesLikeShippedF2(t *testing.T) {
	withRealF2(t, false, func() {
		// shipped F2 still normalizes to public.feedback for ALLOW
		if !isTableAllowedWithContext("feedback", []string{"public.*"}, true, []string{"myschema"}) {
			t.Error("gate OFF: shipped F2 should still allow feedback under public.* (public-only normalization)")
		}
		// search-path-aware match must NOT happen when gate is OFF
		if isTableAllowedWithContext("feedback", []string{"myschema.*"}, true, []string{"myschema"}) {
			t.Error("gate OFF: search-path-aware match must NOT engage")
		}
	})
}

// Fallback: with REAL-F2 OFF, the BLOCK path does not consider extra
// search_path schemas (it remains exactly the shipped behavior).
func TestRealF2_Fallback_BlockPathUnchanged(t *testing.T) {
	withRealF2(t, false, func() {
		// Without the gate, `keys` does not get cross-checked against
		// `secret.keys` via the search_path. Schema-agnostic match still
		// catches it though (legacy isTableBlocked behavior). Use a
		// blocklist that ONLY hits via the schema search to prove the
		// fallback does not engage.
		if isTableBlockedWithContext("public_keys_only_name", []string{"secret.public_keys_only_name"}, []string{"secret"}) {
			// The schema-agnostic leaf match in isTableBlocked already
			// catches "public_keys_only_name" against "secret.public_keys_only_name"
			// (leaf == leaf). So this test would always pass — but it
			// passes for the WRONG reason in fallback mode (legacy
			// schema-agnostic match), and for the right reason when the
			// gate is on. Document this with a non-leaf-collision case
			// below.
		}
		// A blocklist of "secret.somesecret" plus a query for "keys" — no
		// leaf collision, no schema-agnostic match. Without REAL-F2, this
		// must NOT block.
		if isTableBlockedWithContext("keys", []string{"secret.somesecret"}, []string{"secret"}) {
			t.Error("gate OFF: 'keys' must not block under blocklist=[secret.somesecret] (no leaf collision)")
		}
	})
	withRealF2(t, true, func() {
		// With REAL-F2 ON, the same query against a same-leaf blocklist
		// still works the same way (leaf-collision still catches it):
		if !isTableBlockedWithContext("keys", []string{"secret.keys"}, []string{"secret"}) {
			t.Error("gate ON: 'keys' must block under blocklist=[secret.keys] with search_path=[secret]")
		}
	})
}

// Self-check engages the guard on the canonical happy case and
// fallback-disables it when the contract breaks.
func TestRealF2_SelfCheckEngagesGuard(t *testing.T) {
	prev := IsSearchPathAwareAllowOn()
	defer setSearchPathAwareAllow(prev)
	setSearchPathAwareAllow(false)
	out := captureLog(t, func() { InitSearchPathAwareAllowGuard() })
	if !IsSearchPathAwareAllowOn() {
		t.Fatalf("self-check should pass on the canonical case — guard expected ON. log: %s", out)
	}
	if !strings.Contains(out, "REAL-F2 guard active") {
		t.Errorf("expected REAL-F2 guard-active log, got: %s", out)
	}
}

// Self-check failure path: inject a broken candidate-pass function via
// the test seam. The init function must flip the gate OFF and emit a
// clear WARNING; the proxy then falls back to shipped F2.
func TestRealF2_SelfCheckFailureFallsBack(t *testing.T) {
	prev := IsSearchPathAwareAllowOn()
	defer setSearchPathAwareAllow(prev)
	setSearchPathAwareAllow(true) // start ON to prove fallback flips it OFF

	// Inject a broken self-check seam: temporarily replace the
	// candidate-pass function via a known package-level seam. We expose
	// one for the test specifically so production code stays clean.
	prevSeam := searchPathAwareAllowSelfCheckPassFn
	defer func() { searchPathAwareAllowSelfCheckPassFn = prevSeam }()
	searchPathAwareAllowSelfCheckPassFn = func() bool { return false }

	out := captureLog(t, func() { InitSearchPathAwareAllowGuard() })
	if IsSearchPathAwareAllowOn() {
		t.Fatalf("broken self-check must DISABLE REAL-F2 guard. log: %s", out)
	}
	if !strings.Contains(out, "REAL-F2 self-check FAILED") {
		t.Errorf("expected REAL-F2 self-check FAILED warning, got: %s", out)
	}
}

// End-to-end through CheckQueryWithContext: SET search_path TO myschema
// followed by SELECT from feedback is allowed under a myschema.* mission
// and blocked under a public.*-only mission.
func TestRealF2_EndToEnd_SearchPathThenSelect(t *testing.T) {
	prev := IsSearchPathAwareAllowOn()
	prevShipped := IsUnqualifiedAllowNormalizationOn()
	defer func() {
		setSearchPathAwareAllow(prev)
		setUnqualifiedAllowNormalization(prevShipped)
	}()
	setSearchPathAwareAllow(true)
	setUnqualifiedAllowNormalization(true)

	make := func(missionTables []string) *PolicyEngine {
		return &PolicyEngine{
			config: &PolicyConfig{
				DefaultPolicy: "allow",
				Agents: map[string]AgentPolicy{
					"orm-agent": {
						AuthToken: "tok",
						Missions: map[string]MissionPolicy{
							"read": {Tables: missionTables},
						},
					},
				},
				Unidentified: UnidentifiedPolicy{Policy: "deny"},
			},
			enforcement: "enforce",
		}
	}
	id := &AgentIdentity{AgentID: "orm-agent", MissionID: "read", Token: "tok"}

	// agent SET search_path TO myschema → tracked
	st := NewSearchPathState()
	st.ApplySearchPathStatement("SET search_path TO myschema")

	// (a) Allowed under myschema.*
	pe := make([]string{"myschema.*"})
	v := pe.CheckQueryWithContext(id, ParseQuery("SELECT * FROM feedback"), "SELECT * FROM feedback", 0, &QueryContext{SearchPath: st.Schemas()})
	if v != nil && v.Reason == "table_not_in_mission" {
		t.Errorf("e2e (a): myschema.* must allow unqualified feedback under search_path=[myschema], got %+v", v)
	}

	// (b) Blocked under public.* only
	pe2 := make([]string{"public.*"})
	v2 := pe2.CheckQueryWithContext(id, ParseQuery("SELECT * FROM feedback"), "SELECT * FROM feedback", 0, &QueryContext{SearchPath: st.Schemas()})
	if v2 == nil || v2.Reason != "table_not_in_mission" {
		t.Errorf("e2e (b): public.*-only must block unqualified feedback under search_path=[myschema], got %+v", v2)
	}
}

// Backward compatibility: the existing CheckQuery / CheckQueryWithParsed
// callers (no QueryContext) still behave as the shipped F2 does.
func TestRealF2_BackwardCompat_NilContext(t *testing.T) {
	prev := IsSearchPathAwareAllowOn()
	prevShipped := IsUnqualifiedAllowNormalizationOn()
	defer func() {
		setSearchPathAwareAllow(prev)
		setUnqualifiedAllowNormalization(prevShipped)
	}()
	setSearchPathAwareAllow(true)
	setUnqualifiedAllowNormalization(true)

	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents: map[string]AgentPolicy{
				"orm-agent": {
					AuthToken: "tok",
					Missions: map[string]MissionPolicy{
						"read": {Tables: []string{"public.*"}},
					},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "deny"},
		},
		enforcement: "enforce",
	}
	id := &AgentIdentity{AgentID: "orm-agent", MissionID: "read", Token: "tok"}
	// No QueryContext (legacy CheckQuery): public-only fallback applies,
	// bare feedback under public.* must be allowed (the shipped F2 fix).
	if v := pe.CheckQuery(id, "SELECT * FROM feedback", 0); v != nil && v.Reason == "table_not_in_mission" {
		t.Errorf("backward-compat: legacy CheckQuery must still allow bare feedback under public.*, got %+v", v)
	}
}
