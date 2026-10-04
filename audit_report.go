package main

// audit_report.go: findings (each labeled "enforced by Postgres" or
// "not enforced by audit or Postgres grants", with proxy availability) and the human-readable report for
// `faultwall audit`.

import (
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"
)

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// listSome joins up to max items and adds "+N more".
func listSome(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(", +%d more", len(items)-max)
}

func (c AuditColumn) FullName() string { return c.Schema + "." + c.Table + "." + c.Column }

// shortCol drops the schema for public tables (summary line only).
func (c AuditColumn) shortName() string {
	if c.Schema == "public" {
		return c.Table + "." + c.Column
	}
	return c.FullName()
}

func (t AuditTable) FullName() string { return t.Schema + "." + t.Name }
func (v AuditView) FullName() string  { return v.Schema + "." + v.Name }

func readableSecretColumns(rep *AuditReport) []AuditColumn {
	var out []AuditColumn
	for _, c := range rep.SecretColumns {
		if c.Select {
			out = append(out, c)
		}
	}
	return out
}

func sensitiveViews(rep *AuditReport) []AuditView {
	var out []AuditView
	for _, v := range rep.Views {
		if (v.Select || v.SelectAnyColumn) && len(v.ReadsSecret) > 0 {
			out = append(out, v)
		}
	}
	return out
}

func tablesWhere(rep *AuditReport, f func(AuditTable) bool) []string {
	var out []string
	for _, t := range rep.Tables {
		if f(t) {
			out = append(out, t.FullName())
		}
	}
	return out
}

func addFinding(rep *AuditReport, id string, faultwall bool, text string) {
	f := AuditFinding{ID: id, EnforcedBy: "postgres", Label: labelPostgres, Text: text}
	if faultwall {
		f.EnforcedBy, f.Label = "faultwall", labelFaultwall
		if a, ok := auditControlStatus[id]; ok {
			f.Availability = a.level
			f.Text += " " + a.text
		}
	}
	rep.Findings = append(rep.Findings, f)
}

// auditControlStatus says what the FaultWall proxy in THIS release does about
// each control Postgres can't express. Keep it true for the shipped binary:
// "proxy" only for things policy.go/proxy.go enforce today.
var auditControlStatus = map[string]struct{ level, text string }{
	"no_where":       {"proxy", "FaultWall proxy today, in enforce mode: the standard and strict profiles block UPDATE and DELETE without a WHERE."},
	"row_cap":        {"partial", "FaultWall proxy today: max_rows limits the rows one statement returns. A cap on rows changed is planned, not in this release."},
	"approval":       {"planned", "Planned in the FaultWall app, not in this release: writes that pause until a person approves."},
	"agent_identity": {"partial", "FaultWall proxy today: each agent is named by application_name, with an optional per-agent auth_token. Per-agent keys are planned in the FaultWall app."},
	"query_shape":    {"proxy", "FaultWall proxy today, in enforce mode: block by operation, table, column and function per agent."},
}

// buildAuditFindings fills rep.Findings from the collected data. Postgres
// findings first (a native grant can fix them), then the controls Postgres
// can't express.
func buildAuditFindings(rep *AuditReport) {
	rep.Findings = []AuditFinding{}
	r := rep.Role
	s := rep.Summary
	n := r.Name

	// role attributes
	if r.Superuser {
		addFinding(rep, "superuser", false, n+" is a superuser: it can read and change everything, run OS commands (COPY ... PROGRAM) and skip every grant and RLS policy.")
	}
	if r.BypassRLS {
		addFinding(rep, "bypass_rls", false, n+" has BYPASSRLS: row-level security policies don't apply to it.")
	}
	if r.CreateRole {
		addFinding(rep, "create_role", false, n+" has CREATEROLE: it can create roles and grant itself membership in non-superuser roles.")
	}
	if r.CreateDB {
		addFinding(rep, "create_db", false, n+" has CREATEDB: it can create new databases.")
	}
	if r.Replication {
		addFinding(rep, "replication", false, n+" has REPLICATION: it can stream every change in the cluster.")
	}
	if len(r.ElevatedVia) > 0 {
		addFinding(rep, "elevated_membership", false, n+" is a member of "+strings.Join(r.ElevatedVia, "; ")+" and can SET ROLE to it.")
	}
	var pre []string
	for _, p := range auditPredefinedRoles {
		if r.Predefined[p] && !r.Superuser {
			pre = append(pre, p)
		}
	}
	if len(pre) > 0 {
		addFinding(rep, "predefined_roles", false, n+" is a member of "+strings.Join(pre, ", ")+".")
	}

	// writes, ownership
	if s.Delete > 0 {
		addFinding(rep, "delete", false, fmt.Sprintf("DELETE on %d of %d tables.", s.Delete, s.Tables))
	}
	if s.Update > 0 {
		addFinding(rep, "update", false, fmt.Sprintf("UPDATE on %d of %d tables.", s.Update, s.Tables))
	}
	if s.Insert > 0 {
		addFinding(rep, "insert", false, fmt.Sprintf("INSERT on %d of %d tables.", s.Insert, s.Tables))
	}
	if s.Truncate > 0 {
		addFinding(rep, "truncate", false, fmt.Sprintf("TRUNCATE on %d of %d tables: %s.", s.Truncate, s.Tables,
			listSome(tablesWhere(rep, func(t AuditTable) bool { return t.Privileges.Truncate }), 5)))
	}
	if s.Owned > 0 {
		addFinding(rep, "owner", false, fmt.Sprintf("Owns %d of %d tables, so it can ALTER or DROP them and change their grants.", s.Owned, s.Tables))
	}
	if s.Trigger > 0 {
		addFinding(rep, "trigger", false, fmt.Sprintf("TRIGGER on %d tables: it can attach code that runs on other users' writes.", s.Trigger))
	}

	// RLS
	if s.RLSTables > 0 {
		var off []string
		for _, t := range rep.Tables {
			if t.RLSEnabled && !t.RLSApplies {
				why := "owner"
				if r.Superuser {
					why = "superuser"
				} else if r.BypassRLS {
					why = "BYPASSRLS"
				}
				off = append(off, t.FullName()+" ("+why+")")
			}
		}
		if len(off) > 0 {
			addFinding(rep, "rls_not_applied", false, fmt.Sprintf("RLS is on for %d %s but does not apply to %s on %d: %s.",
				s.RLSTables, plural(s.RLSTables, "table", "tables"), n, len(off), listSome(off, 5)))
		} else {
			addFinding(rep, "rls_applied", false, fmt.Sprintf("RLS is on for %d %s and applies to %s.", s.RLSTables, plural(s.RLSTables, "table", "tables"), n))
		}
	}

	// secrets
	if sc := readableSecretColumns(rep); len(sc) > 0 {
		var names []string
		for _, c := range sc {
			names = append(names, c.FullName())
		}
		addFinding(rep, "secret_columns", false, fmt.Sprintf("Can SELECT %d secret-looking %s: %s.", len(sc), plural(len(sc), "column", "columns"), listSome(names, 8)))
	}
	if sv := sensitiveViews(rep); len(sv) > 0 {
		var names []string
		for _, v := range sv {
			names = append(names, v.FullName()+" (reads "+strings.Join(v.ReadsSecret, ", ")+")")
		}
		addFinding(rep, "sensitive_views", false, fmt.Sprintf("Can read %d %s that %s secret-looking columns: %s. Mark these sensitive too.",
			len(sv), plural(len(sv), "view", "views"), plural(len(sv), "reads", "read"), listSome(names, 5)))
	}

	// functions, files, extensions
	if fn := auditExecutableFunctionNames(rep); len(fn) > 0 {
		addFinding(rep, "dangerous_functions", false, fmt.Sprintf("Can EXECUTE %d dangerous %s: %s.", len(fn), plural(len(fn), "function", "functions"), listSome(fn, 8)))
	}
	if rep.ServerFiles.CopyProgram {
		addFinding(rep, "copy_program", false, "Can run COPY ... PROGRAM, which runs shell commands on the database server.")
	}
	if rep.ServerFiles.ReadFiles || rep.ServerFiles.WriteFiles {
		var w []string
		if rep.ServerFiles.ReadFiles {
			w = append(w, "read")
		}
		if rep.ServerFiles.WriteFiles {
			w = append(w, "write")
		}
		addFinding(rep, "server_files", false, "Can "+strings.Join(w, " and ")+" files on the database server (COPY ... FROM/TO a file).")
	}
	if len(rep.Extensions) > 0 {
		var names []string
		for _, e := range rep.Extensions {
			x := e.Name
			if e.Usage != nil {
				x += " (usage: " + yesNo(*e.Usage) + ")"
			}
			names = append(names, x)
		}
		addFinding(rep, "extensions", false, "Extensions that reach outside the database are installed: "+strings.Join(names, ", ")+".")
	}
	var createIn []string
	for _, sc := range rep.Schemas {
		if sc.Create {
			createIn = append(createIn, sc.Name)
		}
	}
	if len(createIn) > 0 {
		addFinding(rep, "schema_create", false, "Can CREATE objects (tables, functions) in "+plural(len(createIn), "schema ", "schemas ")+listSome(createIn, 6)+".")
	}
	if rep.Database.Create {
		addFinding(rep, "database_create", false, "Can CREATE new schemas in database "+rep.Target.Database+".")
	}
	if s.TablesGrantedToPublic > 0 {
		addFinding(rep, "public_grants", false, fmt.Sprintf("%d %s granted to PUBLIC, so every role on the server gets them.", s.TablesGrantedToPublic, plural(s.TablesGrantedToPublic, "table has privileges", "tables have privileges")))
	}

	// controls Postgres can't express
	for _, c := range auditFaultwallControls(rep) {
		addFinding(rep, c.id, true, c.text)
	}
}

type auditControl struct{ id, text string }

// auditFaultwallControls lists what a grant can't express, with numbers from
// this role where they help.
func auditFaultwallControls(rep *AuditReport) []auditControl {
	s := rep.Summary
	n := rep.Role.Name
	writable := 0
	for _, t := range rep.Tables {
		if t.Privileges.Update || t.Privileges.Delete {
			writable++
		}
	}
	var out []auditControl
	if writable > 0 {
		out = append(out, auditControl{"no_where", fmt.Sprintf("Writes without a WHERE clause: %s can UPDATE or DELETE every row of %d %s in one statement. A grant can't require a WHERE.", n, writable, plural(writable, "table", "tables"))})
	} else {
		out = append(out, auditControl{"no_where", "Writes without a WHERE clause: a grant that allows UPDATE or DELETE can't require a WHERE."})
	}
	out = append(out,
		auditControl{"row_cap", "Row-count caps: Postgres has no per-statement limit on rows read or changed."},
		auditControl{"approval", "Approval before a write: Postgres can't pause a statement until a person approves it."},
	)
	id := fmt.Sprintf("Per-agent identity on a shared login: every agent that connects as %s looks the same to Postgres.", n)
	if rep.Sessions.Open > 0 {
		id += fmt.Sprintf(" %d %s open as %s right now (%d application_name %s).", rep.Sessions.Open,
			plural(rep.Sessions.Open, "session is", "sessions are"), n, rep.Sessions.ApplicationNames,
			plural(rep.Sessions.ApplicationNames, "value", "values"))
	}
	out = append(out, auditControl{"agent_identity", id})
	shape := "Query-shape rules: Postgres can't refuse a statement by its shape (a SELECT with no LIMIT, a bulk export, a query that joins every table)."
	if s.SensitiveViewsReadable > 0 || s.SecretColumnsReadable > 0 {
		shape += " It also can't tell a sensitive read through a view or function from a plain one."
	}
	out = append(out, auditControl{"query_shape", shape})
	return out
}

// renderAuditText is the default human report.
func renderAuditText(rep *AuditReport, all bool) string {
	var b strings.Builder
	r := rep.Role
	t := rep.Target

	fmt.Fprintf(&b, "faultwall audit: role %s on database %s at %s:%s (PostgreSQL %s)\n", r.Name, t.Database, t.Host, t.Port, t.ServerVersion)
	if t.ConnectedAs != r.Name {
		fmt.Fprintf(&b, "Connected as %s, checking role %s.\n", t.ConnectedAs, r.Name)
	}
	b.WriteString("Read-only: nothing was changed. No network calls besides this database connection.\n\n")

	// 3-line summary
	b.WriteString("Summary\n")
	b.WriteString("  " + auditSummaryLine1(rep) + "\n")
	b.WriteString("  " + auditSummaryLine2(rep) + "\n")
	fmt.Fprintf(&b, "  Superuser: %s. Bypasses RLS: %s. Create role: %s. Create DB: %s. Replication: %s.\n\n",
		yesNo(r.Superuser), yesNo(r.BypassRLS), yesNo(r.CreateRole), yesNo(r.CreateDB), yesNo(r.Replication))

	b.WriteString("Fixable with Postgres grants (enforced by Postgres)\n")
	np := 0
	for _, f := range rep.Findings {
		if f.EnforcedBy == "postgres" {
			b.WriteString("  - " + f.Text + "\n")
			np++
		}
	}
	if np == 0 {
		b.WriteString("  - Nothing found.\n")
	}
	b.WriteString("  Run faultwall audit --fix for SQL that creates a narrower role for one agent.\n\n")

	b.WriteString("Not enforced by audit or Postgres grants (what the FaultWall proxy does today, and what is planned)\n")
	for _, f := range rep.Findings {
		if f.EnforcedBy == "faultwall" {
			b.WriteString("  - " + f.Text + "\n")
		}
	}
	b.WriteString("\n")

	// role detail
	b.WriteString("Role\n")
	member := "none"
	if len(r.MemberOf) > 0 {
		member = listSome(r.MemberOf, 10)
	}
	fmt.Fprintf(&b, "  member of: %s\n", member)
	var pre []string
	for _, p := range auditPredefinedRoles {
		pre = append(pre, p+"="+yesNo(r.Predefined[p]))
	}
	fmt.Fprintf(&b, "  built-in roles: %s\n", strings.Join(pre, " "))
	fmt.Fprintf(&b, "  COPY ... PROGRAM: %s. Read server files: %s. Write server files: %s.\n\n",
		yesNo(rep.ServerFiles.CopyProgram), yesNo(rep.ServerFiles.ReadFiles), yesNo(rep.ServerFiles.WriteFiles))

	// tables
	limit := 20
	if all || len(rep.Tables) <= limit {
		limit = len(rep.Tables)
		fmt.Fprintf(&b, "Tables (%d)\n", len(rep.Tables))
	} else {
		fmt.Fprintf(&b, "Tables (%d, riskiest %d shown, --all for every table)\n", len(rep.Tables), limit)
	}
	tables := append([]AuditTable(nil), rep.Tables...)
	if limit < len(tables) {
		sort.SliceStable(tables, func(i, j int) bool { return auditTableRisk(tables[i]) > auditTableRisk(tables[j]) })
		tables = tables[:limit]
		sort.SliceStable(tables, func(i, j int) bool { return tables[i].FullName() < tables[j].FullName() })
	}
	if len(tables) > 0 {
		tw := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  table\tprivileges\towner\tRLS\tsecret columns")
		for _, tb := range tables {
			rls := "off"
			if tb.RLSEnabled {
				rls = "on"
				if tb.RLSForced {
					rls += ", forced"
				}
				if tb.RLSApplies {
					rls += ", applies"
				} else {
					rls += ", not applied"
				}
			}
			sec := "-"
			if len(tb.SecretColumns) > 0 {
				sec = strings.Join(tb.SecretColumns, ", ")
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", tb.FullName(), auditPrivString(tb), auditOwnerString(tb), rls, sec)
		}
		tw.Flush()
	}
	b.WriteString("\n")

	if sc := rep.SecretColumns; len(sc) > 0 {
		readable := readableSecretColumns(rep)
		fmt.Fprintf(&b, "Secret-looking columns (%d found, %d readable)\n", len(sc), len(readable))
		for _, c := range sc {
			how := "no SELECT"
			if c.Select {
				how = "SELECT"
				if !c.ViaTableGrant {
					how += " (column grant)"
				}
			}
			if c.Update {
				how += ", UPDATE"
			}
			kind := ""
			if !auditIsTableKind(c.Kind) {
				kind = " [" + c.Kind + "]"
			}
			fmt.Fprintf(&b, "  %s%s: %s\n", c.FullName(), kind, how)
		}
		b.WriteString("\n")
	}
	if sv := sensitiveViews(rep); len(sv) > 0 {
		fmt.Fprintf(&b, "Views that read secret-looking columns (%d readable)\n", len(sv))
		for _, v := range sv {
			fmt.Fprintf(&b, "  %s reads %s\n", v.FullName(), strings.Join(v.ReadsSecret, ", "))
		}
		b.WriteString("\n")
	}
	if fn := auditExecutableFunctionNames(rep); len(fn) > 0 {
		fmt.Fprintf(&b, "Dangerous functions it can EXECUTE (%d)\n  %s\n\n", len(fn), strings.Join(fn, ", "))
	}

	b.WriteString(auditCTA + "\n")
	return b.String()
}

func auditSummaryLine1(rep *AuditReport) string {
	s := rep.Summary
	n := rep.Role.Name
	var parts []string
	if s.Delete > 0 {
		parts = append(parts, fmt.Sprintf("DELETE on %d of %d tables", s.Delete, s.Tables))
	} else {
		parts = append(parts, fmt.Sprintf("DELETE on 0 of %d tables", s.Tables))
	}
	parts = append(parts, fmt.Sprintf("UPDATE %d", s.Update), fmt.Sprintf("INSERT %d", s.Insert), fmt.Sprintf("TRUNCATE %d", s.Truncate))
	sc := readableSecretColumns(rep)
	sec := fmt.Sprintf("read %d secret %s", len(sc), plural(len(sc), "column", "columns"))
	if len(sc) > 0 {
		var names []string
		for _, c := range sc {
			names = append(names, c.shortName())
		}
		sec += " (" + listSome(names, 3) + ")"
	}
	return n + " can " + strings.Join(parts, ", ") + ", and " + sec + "."
}

func auditSummaryLine2(rep *AuditReport) string {
	s := rep.Summary
	parts := []string{fmt.Sprintf("Owns %d (can ALTER/DROP)", s.Owned)}
	parts = append(parts, fmt.Sprintf("%d %s secret columns", s.SensitiveViewsReadable, plural(s.SensitiveViewsReadable, "view reads", "views read")))
	fn := auditExecutableFunctionNames(rep)
	f := fmt.Sprintf("%d dangerous %s executable", len(fn), plural(len(fn), "function", "functions"))
	if len(fn) > 0 {
		f += " (" + listSome(fn, 3) + ")"
	}
	parts = append(parts, f)
	if s.RLSTables > 0 {
		parts = append(parts, fmt.Sprintf("RLS applies on %d of %d RLS tables", s.RLSAppliesToRole, s.RLSTables))
	}
	return strings.Join(parts, ". ") + "."
}

func auditPrivString(t AuditTable) string {
	p := t.Privileges
	var out []string
	add := func(ok bool, s string) {
		if ok {
			out = append(out, s)
		}
	}
	add(p.Select, "SELECT")
	if !p.Select && t.SelectAnyColumn {
		out = append(out, "SELECT(cols)")
	}
	add(p.Insert, "INSERT")
	add(p.Update, "UPDATE")
	add(p.Delete, "DELETE")
	add(p.Truncate, "TRUNCATE")
	add(p.References, "REFERENCES")
	add(p.Trigger, "TRIGGER")
	if len(out) == 0 {
		if !t.SchemaUsage {
			return "none (no schema USAGE)"
		}
		return "none"
	}
	return strings.Join(out, " ")
}

func auditOwnerString(t AuditTable) string {
	if t.OwnedByRole {
		return "yes (can DROP)"
	}
	return "no (" + t.Owner + ")"
}

func auditTableRisk(t AuditTable) int {
	p := t.Privileges
	r := 0
	if t.OwnedByRole {
		r += 16
	}
	if p.Truncate {
		r += 8
	}
	if p.Delete {
		r += 4
	}
	if p.Update {
		r += 2
	}
	if len(t.SecretColumns) > 0 && p.Select {
		r += 12
	}
	if t.RLSEnabled && !t.RLSApplies {
		r += 6
	}
	return r
}
