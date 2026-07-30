package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// realWorldDiff is the shape APA actually produces when it promotes a
// fingerprint: the added lines carry the raw observed query, including a
// literal, because observation.go stores the raw query string in `sql:`.
const realWorldDiff = `diff --git a/policies.yaml b/policies.yaml
index dd36cd9..029df31 100644
--- a/policies.yaml
+++ b/policies.yaml
@@ -3,3 +3,8 @@ agents:
   analytics:
     allowed_tables:
       - public.users
+    allowed_fingerprints:
+      - hash: a1b2c3
+        sql: SELECT email, ssn FROM public.users WHERE email = 'ceo@acme.com'
+        seen: 42
+        verdict: allow
`

func TestRedactSQLFromYAMLDiffStripsQueryText(t *testing.T) {
	got := redactSQLFromYAMLDiff(realWorldDiff)

	for _, leak := range []string{"ssn", "ceo@acme.com", "WHERE", "SELECT email"} {
		if strings.Contains(got, leak) {
			t.Errorf("redacted diff still leaks %q:\n%s", leak, got)
		}
	}
	if !strings.Contains(got, redactedSQLSentinel) {
		t.Errorf("expected redaction sentinel in output:\n%s", got)
	}
	// Reviewable metadata must survive so the dashboard stays useful.
	for _, keep := range []string{"hash: a1b2c3", "seen: 42", "verdict: allow", "allowed_fingerprints"} {
		if !strings.Contains(got, keep) {
			t.Errorf("redaction destroyed reviewable metadata %q:\n%s", keep, got)
		}
	}
	if containsSQLValue(got) {
		t.Error("containsSQLValue still reports SQL content after redaction")
	}
}

func TestRedactSQLHandlesQuotedAndBlockScalars(t *testing.T) {
	cases := []struct {
		name  string
		diff  string
		leaks []string
	}{
		{
			name:  "double quoted",
			diff:  "+        sql: \"DELETE FROM payments WHERE card = '4111111111111111'\"\n",
			leaks: []string{"4111111111111111", "DELETE"},
		},
		{
			name:  "single quoted",
			diff:  "+        sql: 'UPDATE users SET ssn = 123'\n",
			leaks: []string{"ssn", "UPDATE"},
		},
		{
			name: "block scalar",
			diff: "+        sql: |\n+          SELECT *\n+          FROM public.patients\n+          WHERE mrn = 'MRN-99'\n+        seen: 7\n",
			leaks: []string{"patients", "MRN-99", "SELECT"},
		},
		{
			name:  "list item form",
			diff:  "+      - sql: DROP TABLE audit_log\n",
			leaks: []string{"DROP TABLE", "audit_log"},
		},
		{
			name:  "context line not just added line",
			diff:  "         sql: SELECT secret FROM vault\n",
			leaks: []string{"secret", "vault"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := redactSQLFromYAMLDiff(tc.diff)
			for _, leak := range tc.leaks {
				if strings.Contains(got, leak) {
					t.Errorf("leak %q survived redaction:\n%s", leak, got)
				}
			}
			if containsSQLValue(got) {
				t.Errorf("containsSQLValue true after redaction:\n%s", got)
			}
		})
	}
}


func TestRedactSQLIdempotent(t *testing.T) {
	once := redactSQLFromYAMLDiff(realWorldDiff)
	twice := redactSQLFromYAMLDiff(once)
	if once != twice {
		t.Errorf("redaction not idempotent:\nonce:\n%s\ntwice:\n%s", once, twice)
	}
}

func TestRedactSQLEmptyDiff(t *testing.T) {
	if got := redactSQLFromYAMLDiff(""); got != "" {
		t.Errorf("expected empty output for empty diff, got %q", got)
	}
}

// TestRedactSQLLeavesNonSQLKeysAlone guards against the regex being too greedy:
// a key that merely ends in "sql" (or a table named sql_audit) must survive.
func TestRedactSQLLeavesNonSQLKeysAlone(t *testing.T) {
	in := "+    blocked_tables:\n+      - public.sql_audit\n+    normalized_sql_enabled: true\n"
	got := redactSQLFromYAMLDiff(in)
	if got != in {
		t.Errorf("redaction touched non-sql keys:\nwant:\n%s\ngot:\n%s", in, got)
	}
}

// TestAPAWirePayloadCarriesNoQueryText is the end-to-end guard: build the exact
// JSON the client posts and assert no query text survives anywhere in the bytes.
func TestAPAWirePayloadCarriesNoQueryText(t *testing.T) {
	p := apaProposalPayload{
		InstallationID: "inst-1",
		AgentID:        "analytics",
		Title:          "promote 2 fingerprints",
		YAMLDiff:       redactSQLFromYAMLDiff(realWorldDiff),
		Confidence:     0.88,
		DiffLines:      5,
	}
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	wire := string(b)
	for _, leak := range []string{"ssn", "ceo@acme.com", "SELECT email", "merged_yaml"} {
		if strings.Contains(wire, leak) {
			t.Errorf("wire payload leaks %q:\n%s", leak, wire)
		}
	}
}
