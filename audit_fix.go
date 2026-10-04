package main

// audit_fix.go: `faultwall audit --fix`. Prints SQL that creates a NEW
// per-agent role with the read access the audited role has, minus
// secret-looking columns, and lists what still requires Faultwall.
//
// Hard rules (audit_fix_test.go enforces them):
//   - Prints only. Nothing here talks to the database.
//   - Never REVOKE, never ALTER, never DROP. Existing users and roles are never
//     changed; if the new role's name is taken, --fix refuses.
//   - No write grants unless --writes names the tables.
//   - Every identifier goes through auditQuoteIdent (Postgres quote_ident rules).

import (
	"fmt"
	"sort"
	"strings"
)

// pgReservedKeywords are the keywords Postgres' quote_ident() quotes (every
// category except UNRESERVED_KEYWORD), from pg_get_keywords() on PG 16.
var pgReservedKeywords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`all analyse analyze and any array as asc asymmetric authorization
between bigint binary bit boolean both case cast char character check coalesce collate collation
column concurrently constraint create cross current_catalog current_date current_role
current_schema current_time current_timestamp current_user dec decimal default deferrable desc
distinct do else end except exists extract false fetch float for foreign freeze from full grant
greatest group grouping having ilike in initially inner inout int integer intersect interval into
is isnull join json_array json_arrayagg json_object json_objectagg json_scalar json_serialize
json_query json_value json_exists json_table merge_action lateral leading least left like limit
localtime localtimestamp national natural nchar none normalize not notnull null nullif numeric
offset on only or order out outer overlaps overlay placing position precision primary real
references returning right row select session_user setof similar smallint some substring
symmetric system_user table tablesample then time timestamp to trailing treat trim true union
unique user using values varchar variadic verbose when where window with xmlattributes xmlconcat
xmlelement xmlexists xmlforest xmlnamespaces xmlparse xmlpi xmlroot xmlserialize xmltable`) {
		pgReservedKeywords[w] = true
	}
}

// auditQuoteIdent mirrors Postgres quote_ident(): the name is left bare only if it
// starts with a lowercase letter or underscore, has only lowercase letters,
// digits and underscores, and isn't a non-unreserved keyword. Otherwise it is
// double-quoted with embedded quotes doubled.
func auditQuoteIdent(s string) string {
	safe := s != ""
	for i, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r == '_':
		case r >= '0' && r <= '9':
			if i == 0 {
				safe = false
			}
		default:
			safe = false
		}
		if !safe {
			break
		}
	}
	if safe && !pgReservedKeywords[s] {
		return s
	}
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func quoteQualified(schema, name string) string {
	return auditQuoteIdent(schema) + "." + auditQuoteIdent(name)
}

// auditAgentRoleName builds fw_agent_<agent> from a free-form agent name.
func auditAgentRoleName(agent string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(strings.TrimSpace(agent)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	a := strings.Trim(b.String(), "_")
	for strings.Contains(a, "__") {
		a = strings.ReplaceAll(a, "__", "_")
	}
	if a == "" {
		a = "agent"
	}
	name := "fw_agent_" + a
	if len(name) > 63 {
		name = name[:63]
	}
	return name
}

func auditFixRoleName(o *auditOptions) string {
	if o.NewRole != "" {
		return o.NewRole
	}
	return auditAgentRoleName(o.Agent)
}

// auditFixRoleNames are the roles whose existence --fix must check.
func auditFixRoleNames(o *auditOptions) []string {
	if !o.Fix {
		return nil
	}
	out := []string{auditFixRoleName(o)}
	if o.ProxyRole != "" {
		out = append(out, o.ProxyRole)
	}
	return out
}

type fixRel struct {
	schema, name, kind string
	tableSelect        bool // table-level SELECT
	cols               []auditCol
	secret             []string
	readsSecret        []string // views only
	rls                bool
}

// buildAuditFix returns the --fix SQL. It never runs it.
func buildAuditFix(rep *AuditReport, o *auditOptions) (string, error) {
	role := auditFixRoleName(o)
	if len(role) > 63 {
		return "", fmt.Errorf("role name %q is longer than 63 bytes", role)
	}
	if rep.existing[role] || role == rep.Role.Name || role == rep.Target.ConnectedAs {
		return "", fmt.Errorf("role %q already exists. --fix only creates new roles and never changes existing ones. Pick another name with --agent NAME or --new-role NAME", role)
	}
	if o.ProxyRole != "" && !rep.existing[o.ProxyRole] {
		return "", fmt.Errorf("proxy role %q does not exist on this server (check --proxy-role)", o.ProxyRole)
	}
	qr := auditQuoteIdent(role)

	// group columns by relation, keeping catalog order
	rels := map[string]*fixRel{}
	var order []string
	for _, c := range rep.columns {
		k := c.Schema + "\x00" + c.Table
		fr := rels[k]
		if fr == nil {
			fr = &fixRel{schema: c.Schema, name: c.Table, kind: c.Kind}
			rels[k] = fr
			order = append(order, k)
		}
		fr.cols = append(fr.cols, c)
		if isSecretColumn(c.Column) {
			fr.secret = append(fr.secret, c.Column)
		}
	}
	for _, t := range rep.Tables {
		if fr := rels[t.Schema+"\x00"+t.Name]; fr != nil {
			fr.tableSelect = t.Privileges.Select
			fr.rls = t.RLSEnabled
		}
	}
	for _, v := range rep.Views {
		if fr := rels[v.Schema+"\x00"+v.Name]; fr != nil {
			fr.tableSelect = v.Select
			fr.readsSecret = v.ReadsSecret
		}
	}

	// --writes: resolve names
	writes := map[string]bool{}
	for _, w := range o.Writes {
		k, err := auditResolveTable(rep, w)
		if err != nil {
			return "", err
		}
		writes[k] = true
	}

	var grants []string
	var skipped []string
	var rlsTables []string
	schemas := map[string]bool{}
	for _, k := range order {
		fr := rels[k]
		var allowed []string
		for _, c := range fr.cols {
			if c.Select && !isSecretColumn(c.Column) {
				allowed = append(allowed, c.Column)
			}
		}
		qn := quoteQualified(fr.schema, fr.name)
		if len(fr.readsSecret) > 0 {
			skipped = append(skipped, fmt.Sprintf("%s.%s (view reads %s)", fr.schema, fr.name, strings.Join(fr.readsSecret, ", ")))
			continue
		}
		if len(allowed) == 0 {
			continue
		}
		schemas[fr.schema] = true
		if fr.rls {
			rlsTables = append(rlsTables, fr.schema+"."+fr.name)
		}
		if fr.tableSelect && len(fr.secret) == 0 {
			grants = append(grants, fmt.Sprintf("GRANT SELECT ON %s TO %s;", qn, qr))
		} else {
			note := ""
			if len(fr.secret) > 0 {
				note = "  -- leaves out " + strings.Join(fr.secret, ", ")
			}
			grants = append(grants, fmt.Sprintf("GRANT SELECT (%s) ON %s TO %s;%s", auditQuoteCols(allowed), qn, qr, note))
		}
	}

	var writeGrants []string
	if len(writes) > 0 {
		keys := make([]string, 0, len(writes))
		for k := range writes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fr := rels[k]
			if fr == nil {
				continue
			}
			schemas[fr.schema] = true
			qn := quoteQualified(fr.schema, fr.name)
			var nonSecret []string
			for _, c := range fr.cols {
				if !isSecretColumn(c.Column) {
					nonSecret = append(nonSecret, c.Column)
				}
			}
			if len(fr.secret) == 0 {
				writeGrants = append(writeGrants, fmt.Sprintf("GRANT INSERT, UPDATE, DELETE ON %s TO %s;", qn, qr))
			} else {
				cols := auditQuoteCols(nonSecret)
				writeGrants = append(writeGrants,
					fmt.Sprintf("GRANT INSERT (%s), UPDATE (%s) ON %s TO %s;  -- leaves out %s", cols, cols, qn, qr, strings.Join(fr.secret, ", ")),
					fmt.Sprintf("GRANT DELETE ON %s TO %s;", qn, qr))
			}
			for _, s := range rep.sequences {
				if s.TableSchema == fr.schema && s.Table == fr.name {
					writeGrants = append(writeGrants, fmt.Sprintf("GRANT USAGE ON SEQUENCE %s TO %s;", quoteQualified(s.Schema, s.Name), qr))
				}
			}
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "-- faultwall audit --fix: new per-agent role %s\n", role)
	b.WriteString("-- " + auditFixHeader + "\n")
	fmt.Fprintf(&b, "-- Based on what %s can read in database %s. Printed only, nothing was run.\n", rep.Role.Name, rep.Target.Database)
	b.WriteString("-- Run it as an admin after reading it. It creates one new role and grants to it.\n")
	fmt.Fprintf(&b, "-- It does not change %s or any other existing role, so your app keeps working.\n", rep.Role.Name)
	b.WriteString("-- Secret-looking columns are left out with column-level grants. Views that read them are left out.\n\n")

	b.WriteString("BEGIN;\n\n")
	b.WriteString("-- 1. The role. NOLOGIN: FaultWall's proxy switches to it (db_role on the Agents page).\n")
	b.WriteString("--    For an agent that connects to Postgres directly instead, use this line in place of the next one:\n")
	fmt.Fprintf(&b, "--    CREATE ROLE %s LOGIN PASSWORD 'choose-a-long-random-password';\n", qr)
	fmt.Fprintf(&b, "CREATE ROLE %s NOLOGIN;\n\n", qr)

	if o.ProxyRole != "" {
		b.WriteString("-- Let FaultWall's proxy login switch to the new role.\n")
		fmt.Fprintf(&b, "GRANT %s TO %s;\n\n", qr, auditQuoteIdent(o.ProxyRole))
	} else {
		b.WriteString("-- To use it through FaultWall, let the proxy's login switch to it, then set the agent's\n")
		b.WriteString("-- Database role on the Agents page (or rerun with --proxy-role NAME):\n")
		fmt.Fprintf(&b, "--    GRANT %s TO faultwall_proxy;\n\n", qr)
	}

	b.WriteString("-- 2. Schema access.\n")
	sk := make([]string, 0, len(schemas))
	for s := range schemas {
		sk = append(sk, s)
	}
	sort.Strings(sk)
	for _, s := range sk {
		fmt.Fprintf(&b, "GRANT USAGE ON SCHEMA %s TO %s;\n", auditQuoteIdent(s), qr)
	}
	if len(sk) == 0 {
		b.WriteString("-- (none: the audited role can't read any table)\n")
	}
	b.WriteString("\n")

	fmt.Fprintf(&b, "-- 3. Read access (%d tables and views).\n", len(grants))
	for _, g := range grants {
		b.WriteString(g + "\n")
	}
	if len(skipped) > 0 {
		b.WriteString("-- Left out because they read secret-looking columns:\n")
		for _, s := range skipped {
			b.WriteString("--    " + s + "\n")
		}
	}
	b.WriteString("\n")

	b.WriteString("-- 4. Writes.\n")
	if len(writeGrants) == 0 {
		b.WriteString("-- None. Add --writes 'orders,tickets' to grant INSERT, UPDATE, DELETE on just those tables.\n")
	} else {
		for _, g := range writeGrants {
			b.WriteString(g + "\n")
		}
	}
	b.WriteString("\n")

	if len(rlsTables) > 0 {
		b.WriteString("-- Row-level security is on for " + listSome(rlsTables, 6) + ".\n")
		fmt.Fprintf(&b, "-- Policies apply to %s only if they are written TO PUBLIC or name it. Check them before relying on it.\n\n", role)
	}

	b.WriteString("COMMIT;\n\n")

	b.WriteString("-- Still requires Faultwall\n")
	b.WriteString("-- These controls can't be written as Postgres grants (enforced by Faultwall):\n")
	for _, c := range auditFaultwallControls(rep) {
		b.WriteString("--   - " + auditSanitizeFixComment(c.text) + "\n")
	}
	b.WriteString("--\n-- " + auditCTA + "\n")
	return b.String(), nil
}

// auditSanitizeFixComment keeps the forbidden words out of --fix output, even
// in comments, so a grep for them is a reliable check.
func auditSanitizeFixComment(s string) string {
	r := strings.NewReplacer("ALTER or DROP", "change or remove", "ALTER/DROP", "change/remove")
	return r.Replace(s)
}

func auditQuoteCols(cols []string) string {
	q := make([]string, len(cols))
	for i, c := range cols {
		q[i] = auditQuoteIdent(c)
	}
	return strings.Join(q, ", ")
}

// auditResolveTable finds a --writes entry ("table" or "schema.table").
func auditResolveTable(rep *AuditReport, name string) (string, error) {
	schema, table := "", name
	if i := strings.LastIndexByte(name, '.'); i > 0 {
		schema, table = name[:i], name[i+1:]
	}
	var hits []string
	for _, t := range rep.Tables {
		if t.Name == table && (schema == "" || t.Schema == schema) {
			hits = append(hits, t.Schema+"\x00"+t.Name)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("--writes: no table named %q", name)
	case 1:
		return hits[0], nil
	default:
		return "", fmt.Errorf("--writes: %q matches tables in more than one schema, use schema.table", name)
	}
}
