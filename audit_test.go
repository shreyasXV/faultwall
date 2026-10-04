package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var updateAuditGolden = flag.Bool("update-audit-golden", false, "rewrite tests/e2e/audit/testdata/*.golden")

// sampleAuditReport is a synthetic report (no database needed) that covers
// the interesting cases: owned tables, secret columns, a column-level grant,
// a view over password_hash, RLS, dblink, a weird table name.
func sampleAuditReport() *AuditReport {
	rep := newAuditReport(AuditTarget{Host: "db.internal", Port: "5432"})
	rep.Target.Database = "shop"
	rep.Target.ServerVersion = "16.4"
	rep.Target.ConnectedAs = "app_user"
	rep.GeneratedAt = "2026-10-04T00:00:00Z"
	rep.FaultwallVersion = "test"
	rep.Role = AuditRole{Name: "app_user", CanLogin: true, MemberOf: []string{"readers"}, ElevatedVia: []string{},
		Predefined: map[string]bool{}}
	for _, p := range auditPredefinedRoles {
		rep.Role.Predefined[p] = false
	}
	rep.Schemas = []AuditSchema{{Name: "public", Owner: "postgres", Usage: true, Create: true}}
	all := AuditPrivs{Select: true, Insert: true, Update: true, Delete: true, Truncate: true, References: true, Trigger: true}
	ro := AuditPrivs{Select: true}
	add := func(name string, p AuditPrivs, owned bool, cols ...string) {
		t := AuditTable{Schema: "public", Name: name, Kind: "table", Owner: "app_user", OwnedByRole: owned, SchemaUsage: true,
			Privileges: p, SelectAnyColumn: p.Select, PublicPrivileges: []string{}, SecretColumns: []string{}}
		if !owned {
			t.Owner = "admin"
		}
		for _, c := range cols {
			sel := p.Select
			if strings.HasPrefix(c, "+") { // column-level SELECT only
				c = c[1:]
				sel = true
				t.SelectAnyColumn = true
			}
			rep.columns = append(rep.columns, auditCol{Schema: "public", Table: name, Column: c, Kind: "table", Select: sel, Insert: p.Insert, Update: p.Update})
			if isSecretColumn(c) {
				t.SecretColumns = append(t.SecretColumns, c)
				rep.SecretColumns = append(rep.SecretColumns, AuditColumn{Schema: "public", Table: name, Column: c, Kind: "table",
					Select: sel, Insert: p.Insert, Update: p.Update, ViaTableGrant: p.Select && sel})
			}
		}
		rep.Tables = append(rep.Tables, t)
	}
	add("users", all, true, "id", "email", "password_hash")
	add("orders", all, true, "id", "total", "status")
	add("tickets", all, true, "id", "subject")
	add("ledger", ro, false, "id", "entry")
	add("Weird \"Name\"", all, true, "id", "Mixed Case", "select", "api_token")
	add("audit_log", AuditPrivs{}, false, "+id", "+event", "actor_ssn")
	rep.Tables[2].RLSEnabled, rep.Tables[2].RLSPolicies = true, 1
	rep.Views = []AuditView{
		{Schema: "public", Name: "user_logins", Kind: "view", Owner: "app_user", Select: true, SelectAnyColumn: true, ReadsSecret: []string{"public.users.password_hash"}},
		{Schema: "public", Name: "order_totals", Kind: "view", Owner: "app_user", Select: true, SelectAnyColumn: true, ReadsSecret: []string{}},
	}
	rep.columns = append(rep.columns,
		auditCol{Schema: "public", Table: "user_logins", Column: "id", Kind: "view", Select: true},
		auditCol{Schema: "public", Table: "user_logins", Column: "password_hash", Kind: "view", Select: true},
		auditCol{Schema: "public", Table: "order_totals", Column: "total", Kind: "view", Select: true},
	)
	rep.Functions = []AuditFunction{
		{Schema: "pg_catalog", Name: "pg_read_file", Args: "filename text", Execute: false},
		{Schema: "public", Name: "dblink", Args: "text", Execute: true, GrantedToPublic: true},
		{Schema: "public", Name: "dblink_exec", Args: "text", Execute: true, GrantedToPublic: true},
		{Schema: "pg_catalog", Name: "pg_terminate_backend", Args: "pid integer, timeout bigint", Execute: true, GrantedToPublic: true},
	}
	rep.Extensions = []AuditExtension{{Name: "dblink", Version: "1.2", Schema: "public"}}
	rep.sequences = []auditSeq{{TableSchema: "public", Table: "tickets", Schema: "public", Name: "tickets_id_seq"}}
	rep.Sessions = AuditSessions{Open: 3, ApplicationNames: 1}
	rep.existing = map[string]bool{}
	computeAuditSummary(rep)
	buildAuditFindings(rep)
	return rep
}

func TestAuditQuoteIdentMatchesPostgres(t *testing.T) {
	// expected values are what SELECT quote_ident(x) returns on PG 16
	cases := map[string]string{
		"users":         "users",
		"_x1":           "_x1",
		"Users":         `"Users"`,
		"Weird Table":   `"Weird Table"`,
		`a"quote`:       `"a""quote"`,
		"select":        `"select"`,
		"user":          `"user"`,
		"order":         `"order"`,
		"name":          "name", // unreserved keyword: bare
		"1abc":          `"1abc"`,
		"":              `""`,
		"café":          `"café"`,
		"x;drop table":  `"x;drop table"`,
		"a.b":           `"a.b"`,
		`"`:             `""""`,
		"current_user":  `"current_user"`,
		"fw_agent_test": "fw_agent_test",
	}
	for in, want := range cases {
		if got := auditQuoteIdent(in); got != want {
			t.Errorf("auditQuoteIdent(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestAuditSecretColumnParity(t *testing.T) {
	// audit must flag exactly what the proxy flags: it calls isSecretColumn
	// directly. Pin a few names so a drift in either is visible.
	for _, c := range []string{"password_hash", "api_token", "token", "client_secret", "ssn", "user_ssn", "api_key", "private_key", "passwords", "card_token"} {
		if !isSecretColumn(c) {
			t.Errorf("%s should be secret", c)
		}
	}
	for _, c := range []string{"lessons", "tokenizer_version", "id", "email", "assessment"} {
		if isSecretColumn(c) {
			t.Errorf("%s should not be secret", c)
		}
	}
	rep := sampleAuditReport()
	for _, c := range rep.columns {
		if c.Kind == "view" {
			continue
		}
		listed := false
		for _, s := range rep.SecretColumns {
			if s.Table == c.Table && s.Column == c.Column {
				listed = true
			}
		}
		if listed != isSecretColumn(c.Column) {
			t.Errorf("%s.%s listed=%v isSecretColumn=%v", c.Table, c.Column, listed, isSecretColumn(c.Column))
		}
	}
}

func TestAuditSummaryCounts(t *testing.T) {
	s := sampleAuditReport().Summary
	if s.Tables != 6 || s.Delete != 4 || s.Truncate != 4 || s.Owned != 4 || s.Select != 6 {
		t.Fatalf("summary = %+v", s)
	}
	if s.SecretColumnsReadable != 2 { // users.password_hash, Weird.api_token; actor_ssn has no column grant
		t.Fatalf("secret readable = %d", s.SecretColumnsReadable)
	}
	// dblink* counts; pg_terminate_backend doesn't (no pg_signal_backend, own sessions only)
	if s.SensitiveViewsReadable != 1 || s.DangerousFunctionsExec != 1 {
		t.Fatalf("views=%d funcs=%d", s.SensitiveViewsReadable, s.DangerousFunctionsExec)
	}
}

var auditHypeWords = []string{"comprehensive", "robust", "seamless", "seamlessly", "cutting-edge", "powerful",
	"effortless", "revolutionary", "best-in-class", "world-class", "game-changing", "unparalleled", "leverage", "supercharge"}

func checkAuditCopy(t *testing.T, what, out string) {
	t.Helper()
	if strings.ContainsAny(out, "\u2014\u2013") {
		t.Errorf("%s contains an em/en dash", what)
	}
	lower := strings.ToLower(out)
	for _, w := range auditHypeWords {
		if regexp.MustCompile(`\b` + regexp.QuoteMeta(w) + `\b`).MatchString(lower) {
			t.Errorf("%s contains hype word %q", what, w)
		}
	}
	for _, r := range out {
		if r >= 0x1F300 || (r >= 0x2600 && r <= 0x27BF) {
			t.Errorf("%s contains emoji %q", what, r)
			break
		}
	}
	if n := strings.Count(out, auditReadURL); n != 1 {
		t.Errorf("%s mentions the read URL %d times, want 1", what, n)
	}
}

func TestAuditTextFormat(t *testing.T) {
	rep := sampleAuditReport()
	out := renderAuditText(rep, false)
	checkAuditCopy(t, "report", out)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if lines[len(lines)-1] != auditCTA {
		t.Errorf("last line = %q, want the CTA", lines[len(lines)-1])
	}
	if !strings.Contains(out, "Summary\n  app_user can DELETE on 4 of 6 tables, UPDATE 4, INSERT 4, TRUNCATE 4, and read 2 secret columns (users.password_hash, ") {
		t.Errorf("summary line 1 missing:\n%s", out)
	}
	if !strings.Contains(out, "Superuser: no. Bypasses RLS: no.") {
		t.Error("superuser/RLS line missing")
	}
	for _, want := range []string{
		"(enforced by Postgres)", "(enforced by Faultwall", "public.user_logins reads public.users.password_hash",
		"dblink*", "Writes without a WHERE clause", "Per-agent identity on a shared login",
		"3 sessions are open as app_user", "public.audit_log.actor_ssn: no SELECT",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q", want)
		}
	}
	// every finding carries one of the two labels
	for _, f := range rep.Findings {
		if f.Label != labelPostgres && f.Label != labelFaultwall {
			t.Errorf("finding %s has label %q", f.ID, f.Label)
		}
		if (f.EnforcedBy == "postgres") != (f.Label == labelPostgres) {
			t.Errorf("finding %s: enforced_by %q vs label %q", f.ID, f.EnforcedBy, f.Label)
		}
	}
	for _, id := range []string{"no_where", "row_cap", "approval", "agent_identity", "query_shape"} {
		found := false
		for _, f := range rep.Findings {
			if f.ID == id && f.EnforcedBy == "faultwall" {
				found = true
			}
		}
		if !found {
			t.Errorf("missing Faultwall control %s", id)
		}
	}
}

func TestAuditJSONGolden(t *testing.T) {
	rep := sampleAuditReport()
	var buf bytes.Buffer
	if err := writeAuditJSON(&buf, rep); err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if m["schema_version"] != float64(auditSchemaVersion) {
		t.Fatalf("schema_version = %v", m["schema_version"])
	}
	compareAuditGolden(t, "report.json.golden", buf.Bytes())
}

func TestAuditFixGolden(t *testing.T) {
	rep := sampleAuditReport()
	out, err := buildAuditFix(rep, &auditOptions{Fix: true, Agent: "Support Bot", Writes: []string{"tickets"}})
	if err != nil {
		t.Fatal(err)
	}
	compareAuditGolden(t, "fix.sql.golden", []byte(out))
}

func compareAuditGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("tests", "e2e", "audit", "testdata", name)
	if *updateAuditGolden {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test -run Audit -update-audit-golden)", err)
	}
	if !bytes.Equal(want, got) {
		t.Errorf("%s differs from golden. Got:\n%s", name, got)
	}
}

// fixStatementLines returns the SQL (non-comment) part of each line, with
// quoted identifiers blanked so a table named "Drop" can't confuse the check.
func fixStatementLines(out string) []string {
	quoted := regexp.MustCompile(`"(?:[^"]|"")*"`)
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		l = quoted.ReplaceAllString(l, `"x"`)
		if i := strings.Index(l, "--"); i >= 0 {
			l = l[:i]
		}
		if strings.TrimSpace(l) != "" {
			lines = append(lines, strings.TrimSpace(l))
		}
	}
	return lines
}

func TestAuditFixNeverRevokesAltersOrDrops(t *testing.T) {
	rep := sampleAuditReport()
	opts := []*auditOptions{
		{Fix: true},
		{Fix: true, Agent: "drop table users"},
		{Fix: true, NewRole: "Revoke Me", Writes: []string{"orders", "users", "Weird \"Name\""}},
		{Fix: true, Agent: "x", ProxyRole: "faultwall_proxy"},
	}
	rep.existing["faultwall_proxy"] = true
	bad := regexp.MustCompile(`(?i)\b(REVOKE|ALTER|DROP|DELETE\s+FROM|TRUNCATE\s|UPDATE\s+\S+\s+SET|INSERT\s+INTO|SET\s+ROLE|OWNER\s+TO|SUPERUSER|BYPASSRLS|CREATEROLE)\b`)
	for _, o := range opts {
		out, err := buildAuditFix(rep, o)
		if err != nil {
			t.Fatalf("%+v: %v", o, err)
		}
		// anywhere in the output, comments included, except inside the
		// role name the user chose
		role := auditFixRoleName(o)
		scrubbed := strings.ReplaceAll(strings.ReplaceAll(out, auditQuoteIdent(role), "R"), role, "R")
		for _, w := range []string{"REVOKE", "ALTER", "DROP"} {
			if strings.Contains(strings.ToUpper(scrubbed), w) {
				t.Errorf("--fix output contains %q:\n%s", w, out)
			}
		}
		for _, l := range fixStatementLines(out) {
			if bad.MatchString(l) {
				t.Errorf("forbidden statement in --fix output: %s", l)
			}
			// every statement is one of the allowed shapes
			if !(l == "BEGIN;" || l == "COMMIT;" || strings.HasPrefix(l, "CREATE ROLE ") || strings.HasPrefix(l, "GRANT ")) {
				t.Errorf("unexpected statement: %s", l)
			}
			// statements may only name the new role as grantee, never an existing one
			if strings.HasPrefix(l, "GRANT ") && strings.Contains(l, " TO app_user") {
				t.Errorf("grant to existing role: %s", l)
			}
		}
		if strings.Count(out, "CREATE ROLE") != 2 { // the statement + the commented LOGIN variant
			t.Errorf("want one CREATE ROLE (+1 commented), got:\n%s", out)
		}
		if !strings.Contains(out, auditFixHeader) || !strings.Contains(out, "-- Still requires Faultwall\n") {
			t.Error("missing Rev 4 header or Still requires Faultwall section")
		}
		checkAuditCopy(t, "fix", out)
	}
}

func TestAuditFixRefusesExistingRole(t *testing.T) {
	rep := sampleAuditReport()
	rep.existing["fw_agent_agent"] = true
	if _, err := buildAuditFix(rep, &auditOptions{Fix: true}); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("want already-exists error, got %v", err)
	}
	if _, err := buildAuditFix(rep, &auditOptions{Fix: true, NewRole: "app_user"}); err == nil {
		t.Fatal("--fix must refuse to target the audited role")
	}
	if _, err := buildAuditFix(rep, &auditOptions{Fix: true, Agent: "x", ProxyRole: "nope"}); err == nil {
		t.Fatal("--fix must refuse a proxy role that doesn't exist")
	}
}

func TestAuditFixGrantRules(t *testing.T) {
	rep := sampleAuditReport()
	out, err := buildAuditFix(rep, &auditOptions{Fix: true, Agent: "support"})
	if err != nil {
		t.Fatal(err)
	}
	must := []string{
		"CREATE ROLE fw_agent_support NOLOGIN;",
		"--    CREATE ROLE fw_agent_support LOGIN PASSWORD",
		"GRANT USAGE ON SCHEMA public TO fw_agent_support;",
		"GRANT SELECT (id, email) ON public.users TO fw_agent_support;  -- leaves out password_hash",
		"GRANT SELECT ON public.orders TO fw_agent_support;",
		"GRANT SELECT ON public.ledger TO fw_agent_support;",
		`GRANT SELECT (id, "Mixed Case", "select") ON public."Weird ""Name""" TO fw_agent_support;  -- leaves out api_token`,
		"GRANT SELECT (id, event) ON public.audit_log TO fw_agent_support;  -- leaves out actor_ssn",
		"GRANT SELECT ON public.order_totals TO fw_agent_support;",
		"--    public.user_logins (view reads public.users.password_hash)",
		"-- None. Add --writes",
	}
	for _, m := range must {
		if !strings.Contains(out, m) {
			t.Errorf("missing %q in:\n%s", m, out)
		}
	}
	for _, l := range fixStatementLines(out) {
		if regexp.MustCompile(`\b(INSERT|UPDATE|DELETE)\b`).MatchString(l) {
			t.Errorf("write grant without --writes: %s", l)
		}
		if strings.Contains(l, "password_hash") || strings.Contains(l, "user_logins") {
			t.Errorf("secret leaked into grant: %s", l)
		}
	}
	out, err = buildAuditFix(rep, &auditOptions{Fix: true, Agent: "support", Writes: []string{"tickets", "public.users"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range []string{
		"GRANT INSERT, UPDATE, DELETE ON public.tickets TO fw_agent_support;",
		"GRANT USAGE ON SEQUENCE public.tickets_id_seq TO fw_agent_support;",
		"GRANT INSERT (id, email), UPDATE (id, email) ON public.users TO fw_agent_support;  -- leaves out password_hash",
		"GRANT DELETE ON public.users TO fw_agent_support;",
	} {
		if !strings.Contains(out, m) {
			t.Errorf("missing %q", m)
		}
	}
	if strings.Contains(out, "ON public.orders TO fw_agent_support;\nGRANT INSERT") || strings.Contains(out, "DELETE ON public.orders") {
		t.Error("writes granted on a table not in --writes")
	}
	if _, err := buildAuditFix(rep, &auditOptions{Fix: true, Writes: []string{"nope"}}); err == nil {
		t.Error("unknown --writes table should fail")
	}
}

func TestAuditAgentRoleName(t *testing.T) {
	cases := map[string]string{"": "fw_agent_agent", "support": "fw_agent_support", "Support Bot!": "fw_agent_support_bot",
		"a--b": "fw_agent_a_b", strings.Repeat("x", 80): "fw_agent_" + strings.Repeat("x", 54)}
	for in, want := range cases {
		if got := auditAgentRoleName(in); got != want {
			t.Errorf("auditAgentRoleName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAuditParseArgs(t *testing.T) {
	env := func(k string) string {
		if k == "DATABASE_URL" {
			return "postgres://env@h/db"
		}
		return ""
	}
	o, err := parseAuditArgs([]string{"--role", "app", "--json"}, env)
	if err != nil || o.DSN != "postgres://env@h/db" || o.Role != "app" || !o.JSON {
		t.Fatalf("%+v %v", o, err)
	}
	o, err = parseAuditArgs([]string{"postgres://x@h/db", "--fix", "--agent=bot", "--writes", "orders, tickets"}, env)
	if err != nil || o.DSN != "postgres://x@h/db" || o.Agent != "bot" || len(o.Writes) != 2 || o.Writes[1] != "tickets" {
		t.Fatalf("%+v %v", o, err)
	}
	if _, err := parseAuditArgs([]string{"--writes", "x"}, env); err == nil {
		t.Error("--writes without --fix should fail")
	}
	if _, err := parseAuditArgs(nil, func(string) string { return "" }); err == nil {
		t.Error("no DSN should fail")
	}
	if _, err := parseAuditArgs([]string{"--bogus"}, env); err == nil {
		t.Error("unknown flag should fail")
	}
	if _, err := parseAuditArgs([]string{"--help"}, env); err != errAuditHelp {
		t.Error("--help")
	}
}

func TestAuditDSNReadOnlyParams(t *testing.T) {
	d, err := auditDSN("postgres://u:p@h:5432/db?sslmode=disable", true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(d, "default_transaction_read_only=on") || !strings.Contains(d, "application_name=faultwall-audit") {
		t.Fatalf("dsn = %s", d)
	}
	d, _ = auditDSN("host=h user=u dbname=db", true)
	if !strings.Contains(d, "default_transaction_read_only=on") {
		t.Fatalf("kv dsn = %s", d)
	}
	if _, err := auditDSN("mysql://x", true); err == nil {
		t.Error("non-postgres URL should fail")
	}
}

func TestAuditHelpMentionsSafety(t *testing.T) {
	h := auditUsage()
	for _, w := range []string{"Read-only", "No network calls", "never prints REVOKE", "DATABASE_URL", "--fix", "--role", "--json"} {
		if !strings.Contains(h, w) {
			t.Errorf("help missing %q", w)
		}
	}
	checkAuditCopy(t, "help", h+"\n"+auditReadURL)
}

// pg_cancel/terminate_backend are only flagged when the role can signal
// other sessions (pg_signal_backend or superuser).
func TestAuditSignalFunctionsOnlyWithSignalBackend(t *testing.T) {
	rep := sampleAuditReport()
	if fn := auditExecutableFunctionNames(rep); strings.Contains(strings.Join(fn, ","), "pg_terminate_backend") {
		t.Fatalf("flagged without pg_signal_backend: %v", fn)
	}
	rep.Role.Predefined["pg_signal_backend"] = true
	if fn := auditExecutableFunctionNames(rep); !strings.Contains(strings.Join(fn, ","), "pg_terminate_backend") {
		t.Fatalf("not flagged with pg_signal_backend: %v", fn)
	}
}

// --fix: PUBLIC-inherited rights are listed (never revoked), the Faultwall
// section describes the NEW role and its writable tables, and column-level
// grants come with the SELECT * caveat.
func TestAuditFixPublicInheritedAndNewRoleControls(t *testing.T) {
	rep := sampleAuditReport()
	rep.Schemas[0].PublicCreate = true
	out, err := buildAuditFix(rep, &auditOptions{Fix: true, Agent: "support", Writes: []string{"tickets"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"-- Still inherited through PUBLIC (affects every role, review with your DBA)",
		"EXECUTE on public.dblink* (granted to PUBLIC).",
		"CREATE on schema public: it can create tables and functions there.",
		"for fw_agent_support (enforced by Faultwall):",
		"Writes without a WHERE clause: fw_agent_support can UPDATE or DELETE every row of public.tickets in one statement.",
		"SELECT * fails for fw_agent_support (permission denied).",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("--fix missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "app_user can UPDATE or DELETE every row") {
		t.Errorf("--fix Faultwall section must describe the new role, not the audited one:\n%s", out)
	}
	if strings.Contains(out, "pg_terminate_backend") {
		t.Errorf("own-session signal functions should not be listed:\n%s", out)
	}
	ro, err := buildAuditFix(rep, &auditOptions{Fix: true, Agent: "reader"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ro, "every row of") || !strings.Contains(ro, "Row-count caps: Postgres can't limit how many rows one SELECT by fw_agent_reader returns") {
		t.Errorf("read-only role controls wrong:\n%s", ro)
	}
}
