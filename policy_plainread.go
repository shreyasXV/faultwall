package main

// policy_plainread.go — "protected operation" classification after the
// offline window expires (V1-SPEC Rev 4 + POLICY-WIRE-CONTRACT Rev B4).
//
// A statement stays allowed after expiry only when it is a plain read:
//   - SELECT, SHOW, or EXPLAIN (without ANALYZE) of a SELECT;
//   - no data-modifying CTE, no SELECT INTO, no FOR UPDATE/SHARE/NO KEY
//     UPDATE/KEY SHARE;
//   - every function is on the builtin allowlist AND resolves to pg_catalog:
//     either written pg_catalog.fn, or unqualified with no same-named function
//     in the catalog snapshot (functions defined outside pg_catalog /
//     information_schema, taken at every accepted sync);
//   - no user-defined operator from the snapshot whose symbol appears in the
//     query (implicit comparisons from ORDER BY / GROUP BY / DISTINCT / IN /
//     CASE / USING / min/max count as comparison operators);
//   - no snapshot at all = no function/operator exception;
//   - no read of a sensitive table/column, no SELECT * (or t.* / whole-row
//     reference) on a table with any sensitive column.
// Transaction control (BEGIN/COMMIT/ROLLBACK/SAVEPOINT/RELEASE) is not an
// operation and is let through, so a client can always end a transaction.

import (
	"encoding/json"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// plainReadFunctions is the contract's builtin allowlist.
var plainReadFunctions = map[string]bool{
	"count": true, "sum": true, "avg": true, "min": true, "max": true,
	"now": true, "current_date": true, "current_timestamp": true,
	"coalesce": true, "nullif": true, "lower": true, "upper": true,
	"length": true, "trim": true, "date_trunc": true, "abs": true,
	"round": true, "greatest": true, "least": true,
}

// comparisonOps are the operators implicit comparisons resolve to.
var comparisonOps = []string{"=", "<", ">", "<=", ">=", "<>"}

// catalogSnapshot is the persisted list of non-catalog functions/operators.
type catalogSnapshot struct {
	Database  string   `json:"database"`
	Functions []string `json:"functions"`
	Operators []string `json:"operators"`
	Types     []string `json:"types"`
	// ImplicitCasts counts implicit casts backed by a non-catalog function:
	// those can run user code inside an allowlisted function's argument.
	ImplicitCasts int    `json:"implicit_casts"`
	TakenAt       string `json:"taken_at"`

	fn, op, typ map[string]bool
}

func (s *catalogSnapshot) index() {
	if s == nil || s.fn != nil {
		return
	}
	s.fn, s.op, s.typ = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, f := range s.Functions {
		s.fn[strings.ToLower(f)] = true
	}
	for _, o := range s.Operators {
		s.op[o] = true
	}
	for _, t := range s.Types {
		s.typ[strings.ToLower(t)] = true
	}
}

// plainReadInput is everything the classifier needs besides the query.
type plainReadInput struct {
	Snapshot  *catalogSnapshot // nil = no snapshot (no function/operator exception)
	Sensitive []SensitiveMark
}

// plainReadVerdict: Plain=true means allowed after expiry.
type plainReadVerdict struct {
	Plain  bool
	Reason string // why it is protected
}

func protectedBecause(why string) plainReadVerdict { return plainReadVerdict{Reason: why} }

type prWalk struct {
	in        plainReadInput
	snap      *catalogSnapshot
	reason    string
	funcs     int  // function calls seen (any)
	argFuncs  int  // function calls with arguments
	ops       []string
	implicit  bool // implicit comparison operator use
	tables    []prTable
	cols      []string // column names referenced (lowercase, last field)
	singleRef []string // single-field column refs (could be a whole-row ref)
	star      bool     // any * / t.* in a target or column ref
}

type prTable struct{ schema, name, alias string }

// classifyPlainRead decides whether query is a plain read.
func classifyPlainRead(query string, in plainReadInput) plainReadVerdict {
	raw, err := pg_query.ParseToJSON(sanitizeQuery(query))
	if err != nil {
		return protectedBecause("statement could not be parsed")
	}
	var tree struct {
		Stmts []struct {
			Stmt map[string]interface{} `json:"stmt"`
		} `json:"stmts"`
	}
	if err := json.Unmarshal([]byte(raw), &tree); err != nil {
		return protectedBecause("statement could not be parsed")
	}
	if len(tree.Stmts) == 0 {
		return plainReadVerdict{Plain: true}
	}
	w := &prWalk{in: in, snap: in.Snapshot}
	w.snap.index()
	reads := 0
	for _, s := range tree.Stmts {
		for typ, body := range s.Stmt {
			m, _ := body.(map[string]interface{})
			switch typ {
			case "TransactionStmt":
				switch str(m["kind"]) {
				case "TRANS_STMT_BEGIN", "TRANS_STMT_START", "TRANS_STMT_COMMIT", "TRANS_STMT_ROLLBACK",
					"TRANS_STMT_SAVEPOINT", "TRANS_STMT_RELEASE", "TRANS_STMT_ROLLBACK_TO":
					continue
				default:
					return protectedBecause("two-phase transaction command")
				}
			case "VariableShowStmt":
				reads++
				continue
			case "SelectStmt":
				reads++
				w.node(typ, m)
			case "ExplainStmt":
				reads++
				for _, o := range list(m["options"]) {
					if de := child(o, "DefElem"); de != nil && strings.EqualFold(str(de["defname"]), "analyze") && defElemTrue(de) {
						return protectedBecause("EXPLAIN ANALYZE runs the statement")
					}
				}
				q, _ := m["query"].(map[string]interface{})
				if child(q, "SelectStmt") == nil {
					return protectedBecause("EXPLAIN of a non-SELECT statement")
				}
				w.walk(q)
			default:
				return protectedBecause(stmtLabel(typ) + " is not a plain read")
			}
			if w.reason != "" {
				return protectedBecause(w.reason)
			}
		}
	}
	_ = reads
	return w.finish(query)
}

func stmtLabel(typ string) string {
	t := strings.TrimSuffix(typ, "Stmt")
	switch typ {
	case "InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt":
		return strings.ToUpper(t)
	case "VariableSetStmt":
		return "SET"
	}
	return t
}

func (w *prWalk) fail(why string) {
	if w.reason == "" {
		w.reason = why
	}
}

// prSafeNodes are expression/clause node types a plain read may contain.
// Anything else (XML/JSON constructors, TABLESAMPLE, table functions, ...)
// makes the statement protected.
var prSafeNodes = map[string]bool{
	"SelectStmt": true, "ResTarget": true, "ColumnRef": true, "A_Star": true,
	"String": true, "Integer": true, "Float": true, "Boolean": true, "BitString": true,
	"A_Const": true, "ParamRef": true, "A_Expr": true, "BoolExpr": true, "NullTest": true,
	"BooleanTest": true, "FuncCall": true, "SQLValueFunction": true, "TypeCast": true,
	"TypeName": true, "RangeVar": true, "Alias": true, "JoinExpr": true, "RangeSubselect": true,
	"SubLink": true, "CaseExpr": true, "CaseWhen": true, "CoalesceExpr": true, "MinMaxExpr": true,
	"SortBy": true, "WithClause": true, "CommonTableExpr": true, "List": true,
	"A_Indirection": true, "A_Indices": true, "A_ArrayExpr": true, "RowExpr": true,
	"WindowDef": true, "CollateClause": true, "GroupingSet": true, "RangeFunction": true,
	"NamedArgExpr": true, "SetToDefault": true,
}

// walk visits a JSON value; keys starting upper-case are node wrappers.
func (w *prWalk) walk(v interface{}) {
	if w.reason != "" {
		return
	}
	switch x := v.(type) {
	case map[string]interface{}:
		for k, val := range x {
			if k == "" {
				continue
			}
			if k[0] >= 'A' && k[0] <= 'Z' {
				m, _ := val.(map[string]interface{})
				w.node(k, m)
				continue
			}
			switch k {
			case "lockingClause":
				if len(list(val)) > 0 {
					w.fail("locking read (FOR UPDATE/SHARE)")
				}
			case "intoClause":
				w.fail("SELECT INTO creates a table")
			case "over":
				w.implicit = true
			}
			w.walk(val)
		}
	case []interface{}:
		for _, e := range x {
			w.walk(e)
		}
	}
}

func (w *prWalk) node(typ string, m map[string]interface{}) {
	if w.reason != "" {
		return
	}
	switch typ {
	case "InsertStmt", "UpdateStmt", "DeleteStmt", "MergeStmt":
		w.fail("data-modifying statement (" + stmtLabel(typ) + ")")
		return
	}
	if !prSafeNodes[typ] {
		w.fail("unsupported expression in a read after expiry (" + typ + ")")
		return
	}
	switch typ {
	case "SelectStmt":
		if len(list(m["sortClause"])) > 0 || len(list(m["groupClause"])) > 0 || len(list(m["distinctClause"])) > 0 ||
			len(list(m["windowClause"])) > 0 || (str(m["op"]) != "" && str(m["op"]) != "SETOP_NONE") {
			w.implicit = true
		}
	case "FuncCall":
		w.funcCall(m)
	case "SQLValueFunction":
		switch str(m["op"]) {
		case "SVFOP_CURRENT_DATE", "SVFOP_CURRENT_TIMESTAMP", "SVFOP_CURRENT_TIMESTAMP_N":
		default:
			w.fail("function " + strings.ToLower(strings.TrimPrefix(str(m["op"]), "SVFOP_")) + " is not on the plain-read allowlist")
		}
	case "A_Expr":
		w.aExpr(m)
	case "SubLink":
		names := list(m["operName"])
		if len(names) > 0 {
			w.opName(names)
		} else if t := str(m["subLinkType"]); t == "ANY_SUBLINK" || t == "ALL_SUBLINK" {
			w.ops = append(w.ops, "=")
		}
	case "CaseExpr":
		if m["arg"] != nil {
			w.ops = append(w.ops, "=")
		}
	case "MinMaxExpr":
		w.implicit = true
	case "JoinExpr":
		if b, _ := m["isNatural"].(bool); b || len(list(m["usingClause"])) > 0 {
			w.ops = append(w.ops, "=")
		}
		for _, u := range list(m["usingClause"]) {
			if s := child(u, "String"); s != nil {
				w.cols = append(w.cols, strings.ToLower(str(s["sval"])))
			}
		}
	case "TypeCast":
		tn, _ := m["typeName"].(map[string]interface{})
		w.typeName(tn)
	case "RangeVar":
		t := prTable{schema: strings.ToLower(str(m["schemaname"])), name: strings.ToLower(str(m["relname"]))}
		if a, ok := m["alias"].(map[string]interface{}); ok {
			t.alias = strings.ToLower(str(a["aliasname"]))
		}
		w.tables = append(w.tables, t)
	case "ColumnRef":
		fields := list(m["fields"])
		for _, f := range fields {
			if child(f, "A_Star") != nil {
				w.star = true
			}
		}
		if n := len(fields); n > 0 {
			if s := child(fields[n-1], "String"); s != nil {
				name := strings.ToLower(str(s["sval"]))
				w.cols = append(w.cols, name)
				if n == 1 {
					w.singleRef = append(w.singleRef, name)
				}
			}
		}
	case "ResTarget":
		// SELECT * appears as ColumnRef{A_Star}; handled there.
	}
	w.walk(m)
}

func (w *prWalk) funcCall(m map[string]interface{}) {
	names := strList(m["funcname"])
	w.funcs++
	if len(list(m["args"])) > 0 {
		w.argFuncs++
	}
	if b, _ := m["agg_distinct"].(bool); b {
		w.implicit = true
	}
	if len(list(m["agg_order"])) > 0 {
		w.implicit = true
	}
	if len(names) == 0 {
		w.fail("function call without a name")
		return
	}
	fn := strings.ToLower(names[len(names)-1])
	schema := ""
	if len(names) > 1 {
		schema = strings.ToLower(names[len(names)-2])
	}
	// TRIM(...) is parsed as pg_catalog.btrim/ltrim/rtrim (SQL syntax form).
	if str(m["funcformat"]) == "COERCE_SQL_SYNTAX" && schema == "pg_catalog" {
		switch fn {
		case "btrim", "ltrim", "rtrim":
			fn = "trim"
		}
	}
	if fn == "min" || fn == "max" {
		w.implicit = true
	}
	if !plainReadFunctions[fn] {
		w.fail("function " + fn + " is not on the plain-read allowlist")
		return
	}
	switch {
	case schema == "pg_catalog" && len(names) == 2:
		// explicitly pg_catalog: resolves to the builtin.
	case schema == "" && len(names) == 1:
		if w.snap == nil {
			w.fail("function " + fn + ": no catalog snapshot, so it can't be shown to resolve to pg_catalog")
			return
		}
		if w.snap.fn[fn] {
			w.fail("function " + fn + " has a same-named function outside pg_catalog")
			return
		}
	default:
		w.fail("function " + strings.Join(names, ".") + " is not in pg_catalog")
	}
}

func (w *prWalk) aExpr(m map[string]interface{}) {
	names := list(m["name"])
	switch str(m["kind"]) {
	case "AEXPR_BETWEEN", "AEXPR_NOT_BETWEEN", "AEXPR_BETWEEN_SYM", "AEXPR_NOT_BETWEEN_SYM":
		w.ops = append(w.ops, ">=", "<=")
		return
	}
	w.opName(names)
}

func (w *prWalk) opName(names []interface{}) {
	parts := strList(names)
	if len(parts) == 0 {
		return
	}
	if len(parts) > 1 && !strings.EqualFold(parts[0], "pg_catalog") {
		w.fail("operator " + strings.Join(parts, ".") + " is not in pg_catalog")
		return
	}
	w.ops = append(w.ops, parts[len(parts)-1])
}

func (w *prWalk) typeName(tn map[string]interface{}) {
	parts := strList(tn["names"])
	switch {
	case len(parts) == 2 && strings.EqualFold(parts[0], "pg_catalog"):
	case len(parts) == 1:
		if w.snap != nil && w.snap.typ[strings.ToLower(parts[0])] {
			w.fail("cast to type " + parts[0] + ", which is defined outside pg_catalog")
		} else if w.snap == nil {
			w.fail("cast to type " + parts[0] + ": no catalog snapshot")
		}
	default:
		w.fail("cast to type " + strings.Join(parts, ".") + ", which is not in pg_catalog")
	}
}

func (w *prWalk) finish(query string) plainReadVerdict {
	if w.reason != "" {
		return protectedBecause(w.reason)
	}
	// Sensitive tables/columns.
	if why := w.sensitive(); why != "" {
		return protectedBecause(why)
	}
	usesOps := len(w.ops) > 0 || w.implicit
	if w.snap == nil {
		if usesOps {
			return protectedBecause("operators in a read need a catalog snapshot, and there is none")
		}
		return plainReadVerdict{Plain: true}
	}
	for _, o := range w.snap.Operators {
		if o != "" && strings.Contains(query, o) {
			return protectedBecause("user-defined operator " + o + " appears in the statement")
		}
	}
	if w.implicit {
		for _, o := range comparisonOps {
			if w.snap.op[o] {
				return protectedBecause("implicit comparison with a user-defined " + o + " operator present")
			}
		}
	}
	if w.argFuncs > 0 && w.snap.ImplicitCasts > 0 {
		return protectedBecause("database has implicit casts backed by user functions")
	}
	return plainReadVerdict{Plain: true}
}

func (w *prWalk) sensitive() string {
	if len(w.in.Sensitive) == 0 || len(w.tables) == 0 {
		return ""
	}
	for _, mark := range w.in.Sensitive {
		ms, mt := splitTableName(mark.Table)
		if mt == "" {
			continue
		}
		for _, t := range w.tables {
			if t.name != mt || (ms != "" && t.schema != "" && t.schema != ms) {
				continue
			}
			label := mt
			if ms != "" {
				label = ms + "." + mt
			}
			if len(mark.Columns) == 0 {
				return "read of sensitive table " + label
			}
			if w.star {
				return "SELECT * on " + label + ", which has sensitive columns"
			}
			for _, r := range w.singleRef {
				if r == t.name || (t.alias != "" && r == t.alias) {
					return "whole-row read of " + label + ", which has sensitive columns"
				}
			}
			for _, c := range mark.Columns {
				c = strings.ToLower(strings.TrimSpace(c))
				for _, col := range w.cols {
					if col == c {
						return "read of sensitive column " + label + "." + c
					}
				}
			}
		}
	}
	return ""
}

func splitTableName(t string) (schema, name string) {
	t = strings.ToLower(strings.TrimSpace(strings.ReplaceAll(t, `"`, "")))
	if i := strings.LastIndex(t, "."); i >= 0 {
		return t[:i], t[i+1:]
	}
	return "", t
}

// ── JSON helpers ──

func str(v interface{}) string {
	s, _ := v.(string)
	return s
}

func list(v interface{}) []interface{} {
	l, _ := v.([]interface{})
	return l
}

func child(v interface{}, typ string) map[string]interface{} {
	m, _ := v.(map[string]interface{})
	if m == nil {
		return nil
	}
	c, _ := m[typ].(map[string]interface{})
	return c
}

func strList(v interface{}) []string {
	var out []string
	for _, e := range list(v) {
		if s := child(e, "String"); s != nil {
			out = append(out, str(s["sval"]))
		}
	}
	return out
}

// defElemTrue: EXPLAIN (ANALYZE) / (ANALYZE true|on|1) -> true; false/off/0 -> false.
func defElemTrue(de map[string]interface{}) bool {
	arg, ok := de["arg"].(map[string]interface{})
	if !ok || arg == nil {
		return true
	}
	if s := child(arg, "String"); s != nil {
		switch strings.ToLower(str(s["sval"])) {
		case "false", "off", "0", "no":
			return false
		}
		return true
	}
	if b := child(arg, "Boolean"); b != nil {
		v, _ := b["boolval"].(bool)
		return v
	}
	if i := child(arg, "Integer"); i != nil {
		v, _ := i["ival"].(float64)
		return v != 0
	}
	if c := child(arg, "A_Const"); c != nil {
		if b, ok := c["boolval"].(map[string]interface{}); ok {
			v, _ := b["boolval"].(bool)
			return v
		}
		if iv, ok := c["ival"].(map[string]interface{}); ok {
			v, _ := iv["ival"].(float64)
			return v != 0
		}
		if sv, ok := c["sval"].(map[string]interface{}); ok {
			switch strings.ToLower(str(sv["sval"])) {
			case "false", "off", "0", "no":
				return false
			}
		}
	}
	return true
}
