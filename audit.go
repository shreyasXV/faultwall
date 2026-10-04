package main

// audit.go: `faultwall audit`, a local, read-only report of what a Postgres
// role can do (privileges, secret-looking columns, views over them,
// dangerous functions, extensions), plus `--fix`, which prints SQL for a new
// per-agent role and never runs it.
//
// Rules this file keeps (tests enforce them):
//   - Read-only. The session starts with default_transaction_read_only=on,
//     runs SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY, and does all
//     work inside one BEGIN READ ONLY transaction of catalog SELECTs.
//   - No network calls except the one Postgres connection (and the libpq-style
//     sslmode probe, which goes to the same host and port). No telemetry, no
//     update check. audit_nohttp_test.go fails if audit code paths reach
//     net/http.
//   - Set-based catalog queries, a fixed number of round trips no matter how
//     many tables there are.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/lib/pq"
)

// auditReadURL is the free 48h read offer. Keep it in one place.
// Points at the homepage until faultwall.com/read is published (founder
// approval of the copy); switch back with a one-line change.
const auditReadURL = "https://faultwall.com"

// auditCTA is the single closing line of the human report.
const auditCTA = "Want this for your agent's real traffic? Free 48h read: " + auditReadURL

// auditSchemaVersion is the --json schema version. Bump on breaking changes.
const auditSchemaVersion = 1

// auditFixHeader is the approved Rev 4 wording for --fix.
const auditFixHeader = "Generates the database privileges that can be represented natively, and identifies controls that still require Faultwall."

const (
	labelPostgres  = "enforced by Postgres"
	labelFaultwall = "not enforced by audit or Postgres grants"
)

// auditDangerousFunctions are checked for EXECUTE (plus every dblink*).
var auditDangerousFunctions = []string{
	"pg_read_file", "pg_read_binary_file", "pg_ls_dir", "pg_stat_file",
	"lo_import", "lo_export", "pg_terminate_backend", "pg_cancel_backend",
}

// auditPredefinedRoles are the built-in roles that widen reach.
var auditPredefinedRoles = []string{
	"pg_read_server_files", "pg_write_server_files", "pg_execute_server_program",
	"pg_read_all_data", "pg_write_all_data", "pg_signal_backend",
}

// auditExtensions widen what a session can reach (network, files, OS).
var auditExtensions = []string{
	"dblink", "postgres_fdw", "file_fdw", "http", "pg_net",
	"plpython3u", "plpythonu", "plperlu", "pltclu", "adminpack",
	"aws_s3", "aws_lambda",
}

type auditOptions struct {
	DSN       string
	Role      string
	JSON      bool
	Fix       bool
	All       bool
	Agent     string
	NewRole   string
	ProxyRole string
	Writes    []string
}

// ---- report model (also the --json schema) ----

type AuditReport struct {
	SchemaVersion    int              `json:"schema_version"`
	Tool             string           `json:"tool"`
	FaultwallVersion string           `json:"faultwall_version"`
	GeneratedAt      string           `json:"generated_at"`
	Target           AuditTarget      `json:"target"`
	Role             AuditRole        `json:"role"`
	Summary          AuditSummary     `json:"summary"`
	Findings         []AuditFinding   `json:"findings"`
	Database         AuditDatabase    `json:"database"`
	Schemas          []AuditSchema    `json:"schemas"`
	Tables           []AuditTable     `json:"tables"`
	Views            []AuditView      `json:"views"`
	SecretColumns    []AuditColumn    `json:"secret_columns"`
	Functions        []AuditFunction  `json:"functions"`
	ServerFiles      AuditServerFiles `json:"server_file_access"`
	Extensions       []AuditExtension `json:"extensions"`
	Sessions         AuditSessions    `json:"sessions"`
	CTA              string           `json:"cta"`
	FixSQL           string           `json:"fix_sql,omitempty"`

	// not serialized: inputs for --fix
	columns   []auditCol
	sequences []auditSeq
	existing  map[string]bool // roles named by --fix that already exist
}

type AuditTarget struct {
	Host          string `json:"host"`
	Port          string `json:"port"`
	Database      string `json:"database"`
	ServerVersion string `json:"server_version"`
	ConnectedAs   string `json:"connected_as"`
}

type AuditRole struct {
	Name        string          `json:"name"`
	Superuser   bool            `json:"superuser"`
	BypassRLS   bool            `json:"bypass_rls"`
	CreateRole  bool            `json:"create_role"`
	CreateDB    bool            `json:"create_db"`
	Replication bool            `json:"replication"`
	CanLogin    bool            `json:"can_login"`
	MemberOf    []string        `json:"member_of"`
	ElevatedVia []string        `json:"elevated_via"`
	Predefined  map[string]bool `json:"predefined_roles"`
}

type AuditSummary struct {
	Tables                 int `json:"tables"`
	Select                 int `json:"select"`
	Insert                 int `json:"insert"`
	Update                 int `json:"update"`
	Delete                 int `json:"delete"`
	Truncate               int `json:"truncate"`
	References             int `json:"references"`
	Trigger                int `json:"trigger"`
	Owned                  int `json:"owned"`
	Views                  int `json:"views"`
	ViewsReadable          int `json:"views_readable"`
	SecretColumnsReadable  int `json:"secret_columns_readable"`
	SensitiveViewsReadable int `json:"sensitive_views_readable"`
	DangerousFunctionsExec int `json:"dangerous_functions_executable"`
	RLSTables              int `json:"rls_tables"`
	RLSAppliesToRole       int `json:"rls_applies_to_role"`
	SchemasWithCreate      int `json:"schemas_with_create"`
	TablesGrantedToPublic  int `json:"tables_granted_to_public"`
}

type AuditFinding struct {
	ID         string `json:"id"`
	EnforcedBy string `json:"enforced_by"` // "postgres" | "faultwall"
	Label      string `json:"label"`       // "enforced by Postgres" | "not enforced by audit or Postgres grants"
	Text       string `json:"text"`
	// Availability, for findings Postgres can't enforce: what the FaultWall
	// proxy in this release does about it. "proxy" = available now, "partial",
	// or "planned" (not in this release).
	Availability string `json:"availability,omitempty"`
}

type AuditDatabase struct {
	Connect bool `json:"connect"`
	Create  bool `json:"create"`
	Temp    bool `json:"temp"`
}

type AuditSchema struct {
	Name         string `json:"name"`
	Owner        string `json:"owner"`
	Usage        bool   `json:"usage"`
	Create       bool   `json:"create"`
	OwnedByRole  bool   `json:"owned_by_role"`
	PublicCreate bool   `json:"public_create"`
}

type AuditPrivs struct {
	Select     bool `json:"select"`
	Insert     bool `json:"insert"`
	Update     bool `json:"update"`
	Delete     bool `json:"delete"`
	Truncate   bool `json:"truncate"`
	References bool `json:"references"`
	Trigger    bool `json:"trigger"`
}

type AuditTable struct {
	Schema           string     `json:"schema"`
	Name             string     `json:"name"`
	Kind             string     `json:"kind"`
	Owner            string     `json:"owner"`
	OwnedByRole      bool       `json:"owned_by_role"`
	SchemaUsage      bool       `json:"schema_usage"`
	Privileges       AuditPrivs `json:"privileges"`
	SelectAnyColumn  bool       `json:"select_any_column"`
	RLSEnabled       bool       `json:"rls_enabled"`
	RLSForced        bool       `json:"rls_forced"`
	RLSPolicies      int        `json:"rls_policies"`
	RLSApplies       bool       `json:"rls_applies_to_role"`
	PublicPrivileges []string   `json:"public_privileges"`
	SecretColumns    []string   `json:"secret_columns"`
}

type AuditView struct {
	Schema          string   `json:"schema"`
	Name            string   `json:"name"`
	Kind            string   `json:"kind"`
	Owner           string   `json:"owner"`
	Select          bool     `json:"select"`
	SelectAnyColumn bool     `json:"select_any_column"`
	ReadsSecret     []string `json:"reads_secret_columns"`
}

type AuditColumn struct {
	Schema        string `json:"schema"`
	Table         string `json:"table"`
	Column        string `json:"column"`
	Kind          string `json:"kind"`
	Select        bool   `json:"select"`
	Insert        bool   `json:"insert"`
	Update        bool   `json:"update"`
	ViaTableGrant bool   `json:"via_table_grant"`
}

type AuditFunction struct {
	Schema          string `json:"schema"`
	Name            string `json:"name"`
	Args            string `json:"args"`
	Execute         bool   `json:"execute"`
	GrantedToPublic bool   `json:"granted_to_public"`
}

type AuditServerFiles struct {
	CopyProgram bool `json:"copy_program"`
	ReadFiles   bool `json:"read_server_files"`
	WriteFiles  bool `json:"write_server_files"`
}

type AuditExtension struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Schema  string `json:"schema"`
	Usage   *bool  `json:"fdw_usage,omitempty"`
}

type AuditSessions struct {
	Open             int `json:"open"`
	ApplicationNames int `json:"application_names"`
}

// auditCol is one column of a relation, for --fix.
type auditCol struct {
	Schema, Table, Column string
	Kind                  string
	Select, Insert        bool
	Update                bool
}

// auditSeq is a serial sequence owned by a table column, for --fix --writes.
type auditSeq struct {
	TableSchema, Table string
	Schema, Name       string
	Usage              bool
}

// ---- CLI ----

func auditUsage() string {
	return `Usage: faultwall audit [postgres://user:pass@host:5432/db] [flags]

Prints what a Postgres role can do: role attributes, per-table privileges,
ownership (can DROP), RLS, secret-looking columns, views that read them,
dangerous functions, server file access and extensions. Each finding says
"enforced by Postgres" (a native grant can fix it) or "not enforced by audit or
Postgres grants" (Postgres can't express it), with what the FaultWall proxy can
do about it today and what is planned.

Uses DATABASE_URL when no URL is given.

Flags:
  --role NAME         Role to check (default: the connecting user). Includes
                      privileges inherited through role membership.
  --json              Machine-readable output (schema_version ` + fmt.Sprint(auditSchemaVersion) + `)
  --all               List every table, not just the first 20
  --fix               Print SQL for a NEW per-agent role. Prints only, never runs it.
  --agent NAME        Agent name for --fix (role fw_agent_<name>, default fw_agent_agent)
  --new-role NAME     Exact role name for --fix (overrides --agent)
  --writes LIST       --fix: also grant INSERT/UPDATE/DELETE on these tables
                      (comma-separated, table or schema.table)
  --proxy-role NAME   --fix: grant the new role to FaultWall's proxy login

Safety:
  Read-only. It sets default_transaction_read_only=on and SET SESSION
  CHARACTERISTICS AS TRANSACTION READ ONLY, and runs only catalog SELECTs.
  No network calls except the one Postgres connection: no telemetry, no
  update check. Nothing leaves your machine.
  --fix never prints REVOKE, ALTER or DROP, and never changes existing roles.

Examples:
  faultwall audit "$DATABASE_URL"
  faultwall audit "$DATABASE_URL" --role app_user --json
  faultwall audit "$DATABASE_URL" --fix --agent support --writes tickets > fix.sql`
}

func parseAuditArgs(args []string, getenvFn func(string) string) (*auditOptions, error) {
	o := &auditOptions{}
	val := func(i *int, name string) (string, error) {
		a := args[*i]
		if eq := strings.IndexByte(a, '='); eq >= 0 {
			return a[eq+1:], nil
		}
		if *i+1 >= len(args) {
			return "", fmt.Errorf("%s needs a value", name)
		}
		*i++
		return args[*i], nil
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		name := a
		if eq := strings.IndexByte(a, '='); eq >= 0 && strings.HasPrefix(a, "-") {
			name = a[:eq]
		}
		var err error
		switch name {
		case "-h", "--help", "help":
			return nil, errAuditHelp
		case "--json":
			o.JSON = true
		case "--fix":
			o.Fix = true
		case "--all":
			o.All = true
		case "--role":
			o.Role, err = val(&i, name)
		case "--agent":
			o.Agent, err = val(&i, name)
		case "--new-role":
			o.NewRole, err = val(&i, name)
		case "--proxy-role":
			o.ProxyRole, err = val(&i, name)
		case "--writes":
			var s string
			s, err = val(&i, name)
			for _, w := range strings.Split(s, ",") {
				if w = strings.TrimSpace(w); w != "" {
					o.Writes = append(o.Writes, w)
				}
			}
		default:
			if strings.HasPrefix(a, "-") {
				return nil, fmt.Errorf("unknown flag %s (see faultwall audit --help)", a)
			}
			if o.DSN != "" {
				return nil, fmt.Errorf("unexpected argument %q (one connection string only)", a)
			}
			o.DSN = a
		}
		if err != nil {
			return nil, err
		}
	}
	if o.DSN == "" {
		o.DSN = strings.TrimSpace(getenvFn("DATABASE_URL"))
	}
	if o.DSN == "" {
		return nil, errors.New("no database given: pass a postgres:// URL or set DATABASE_URL (see faultwall audit --help)")
	}
	if len(o.Writes) > 0 && !o.Fix {
		return nil, errors.New("--writes only applies with --fix")
	}
	return o, nil
}

var errAuditHelp = errors.New("help")

func runAudit(args []string) error {
	return runAuditTo(os.Stdout, args, os.Getenv)
}

func runAuditTo(w io.Writer, args []string, getenvFn func(string) string) error {
	o, err := parseAuditArgs(args, getenvFn)
	if err == errAuditHelp {
		fmt.Fprintln(w, auditUsage())
		return nil
	}
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	rep, err := collectAudit(ctx, o.DSN, o.Role, auditFixRoleNames(o))
	if err != nil {
		return err
	}
	rep.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	buildAuditFindings(rep)
	if o.Fix {
		sqlText, err := buildAuditFix(rep, o)
		if err != nil {
			return err
		}
		if o.JSON {
			rep.FixSQL = sqlText
		} else {
			_, err = io.WriteString(w, sqlText)
			return err
		}
	}
	if o.JSON {
		return writeAuditJSON(w, rep)
	}
	_, err = io.WriteString(w, renderAuditText(rep, o.All))
	return err
}

func writeAuditJSON(w io.Writer, rep *AuditReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(rep)
}

// ---- connection ----

// auditSessionParams are sent in the startup packet so the session is
// read-only before the first statement runs.
var auditSessionParams = [][2]string{
	{"default_transaction_read_only", "on"},
	{"statement_timeout", "60000"},
}

// auditDSN adds the read-only startup params (and application_name if the
// user didn't set one). withParams=false is the fallback for poolers that
// reject unknown startup parameters (PgBouncer); the session is then made
// read-only by SET SESSION CHARACTERISTICS and BEGIN READ ONLY alone.
func auditDSN(dsn string, withParams bool) (string, error) {
	dsn = strings.TrimSpace(dsn)
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		u, err := url.Parse(dsn)
		if err != nil {
			return "", fmt.Errorf("could not parse the connection URL: %v", err)
		}
		q := u.Query()
		if withParams {
			for _, kv := range auditSessionParams {
				q.Set(kv[0], kv[1])
			}
		}
		if q.Get("application_name") == "" {
			q.Set("application_name", "faultwall-audit")
		}
		u.RawQuery = q.Encode()
		return u.String(), nil
	}
	if strings.Contains(dsn, "://") {
		return "", errors.New("the connection URL must start with postgres:// or postgresql://")
	}
	// keyword/value form
	out := dsn
	if withParams {
		for _, kv := range auditSessionParams {
			out += " " + kv[0] + "=" + kv[1]
		}
	}
	if !strings.Contains(out, "application_name") {
		out += " application_name=faultwall-audit"
	}
	return out, nil
}

func auditTargetFromDSN(dsn string) AuditTarget {
	t := AuditTarget{}
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		if u, err := url.Parse(dsn); err == nil {
			t.Host, t.Port = u.Hostname(), u.Port()
			if h := u.Query().Get("host"); h != "" {
				t.Host = h
			}
		}
	} else {
		for _, m := range kvParamRe.FindAllStringSubmatch(dsn, -1) {
			switch m[1] {
			case "host":
				t.Host = m[2]
			case "port":
				t.Port = m[2]
			}
		}
	}
	if t.Host == "" {
		t.Host = "localhost"
	}
	if t.Port == "" {
		t.Port = "5432"
	}
	return t
}

func auditOpen(ctx context.Context, dsn string, withParams bool) (*sql.DB, *sql.Conn, error) {
	d, err := auditDSN(dsn, withParams)
	if err != nil {
		return nil, nil, err
	}
	d = normalizeLibPQSSLMode(d)
	pool, err := sql.Open("postgres", d)
	if err != nil {
		return nil, nil, err
	}
	pool.SetMaxOpenConns(1)
	conn, err := pool.Conn(ctx)
	if err == nil {
		err = conn.PingContext(ctx)
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		pool.Close()
		return nil, nil, err
	}
	return pool, conn, nil
}

// collectAudit connects once, makes the session read-only and gathers the
// report in one read-only transaction.
func collectAudit(ctx context.Context, dsn, role string, checkRoles []string) (*AuditReport, error) {
	pool, conn, err := auditOpen(ctx, dsn, true)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "startup parameter") {
		pool, conn, err = auditOpen(ctx, dsn, false)
	}
	if err != nil {
		return nil, fmt.Errorf("could not connect: %v", err)
	}
	defer pool.Close()
	defer conn.Close()

	if _, err := conn.ExecContext(ctx, "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY"); err != nil {
		return nil, fmt.Errorf("could not make the session read-only: %v", err)
	}
	tx, err := conn.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return nil, fmt.Errorf("could not start a read-only transaction: %v", err)
	}
	defer tx.Rollback()
	var ro string
	if err := tx.QueryRowContext(ctx, "SHOW transaction_read_only").Scan(&ro); err != nil || ro != "on" {
		return nil, fmt.Errorf("refusing to continue: transaction is not read-only (%q, %v)", ro, err)
	}
	rep := newAuditReport(auditTargetFromDSN(dsn))
	if err := gatherAudit(ctx, tx, rep, role); err != nil {
		return nil, err
	}
	rep.existing = map[string]bool{}
	if len(checkRoles) > 0 {
		rows, err := tx.QueryContext(ctx, `SELECT rolname FROM pg_roles WHERE rolname = ANY($1::text[])`, pq.Array(checkRoles))
		if err != nil {
			return nil, fmt.Errorf("reading roles: %v", err)
		}
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				rows.Close()
				return nil, err
			}
			rep.existing[n] = true
		}
		rows.Close()
	}
	return rep, nil
}

func newAuditReport(t AuditTarget) *AuditReport {
	return &AuditReport{
		SchemaVersion:    auditSchemaVersion,
		Tool:             "faultwall audit",
		FaultwallVersion: Version,
		Target:           t,
		CTA:              auditCTA,
		Schemas:          []AuditSchema{},
		Tables:           []AuditTable{},
		Views:            []AuditView{},
		SecretColumns:    []AuditColumn{},
		Functions:        []AuditFunction{},
		Extensions:       []AuditExtension{},
		Findings:         []AuditFinding{},
	}
}

// auditQuerier is satisfied by *sql.Tx.
type auditQuerier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const auditUserSchemaFilter = `n.nspname NOT IN ('pg_catalog', 'information_schema')
  AND n.nspname NOT LIKE 'pg\_toast%' AND n.nspname NOT LIKE 'pg\_temp\_%'`

var auditKindNames = map[string]string{
	"r": "table", "p": "partitioned table", "f": "foreign table",
	"v": "view", "m": "materialized view",
}

func auditIsTableKind(k string) bool {
	return k == "table" || k == "partitioned table" || k == "foreign table"
}

func gatherAudit(ctx context.Context, q auditQuerier, rep *AuditReport, roleArg string) error {
	// 1. role
	r := &rep.Role
	err := q.QueryRowContext(ctx, `SELECT current_user, r.rolname, r.rolsuper, r.rolbypassrls,
  r.rolcreaterole, r.rolcreatedb, r.rolreplication, r.rolcanlogin,
  current_database(), current_setting('server_version')
FROM pg_roles r WHERE r.rolname = coalesce(nullif($1, ''), current_user)`, roleArg).Scan(
		&rep.Target.ConnectedAs, &r.Name, &r.Superuser, &r.BypassRLS, &r.CreateRole, &r.CreateDB,
		&r.Replication, &r.CanLogin, &rep.Target.Database, &rep.Target.ServerVersion)
	if err == sql.ErrNoRows {
		return fmt.Errorf("role %q does not exist", roleArg)
	}
	if err != nil {
		return fmt.Errorf("reading role: %v", err)
	}
	role := r.Name

	// 2. memberships (recursive, through any chain)
	rows, err := q.QueryContext(ctx, `WITH RECURSIVE m(roleid) AS (
  SELECT am.roleid FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.member WHERE r.rolname = $1
  UNION
  SELECT am.roleid FROM pg_auth_members am JOIN m ON am.member = m.roleid)
SELECT r.rolname, r.rolsuper, r.rolbypassrls, r.rolcreaterole
FROM m JOIN pg_roles r ON r.oid = m.roleid ORDER BY 1`, role)
	if err != nil {
		return fmt.Errorf("reading role membership: %v", err)
	}
	r.MemberOf = []string{}
	r.ElevatedVia = []string{}
	member := map[string]bool{}
	for rows.Next() {
		var name string
		var su, bypass, cr bool
		if err := rows.Scan(&name, &su, &bypass, &cr); err != nil {
			rows.Close()
			return err
		}
		member[name] = true
		r.MemberOf = append(r.MemberOf, name)
		if su || bypass || cr {
			var what []string
			if su {
				what = append(what, "superuser")
			}
			if bypass {
				what = append(what, "bypass RLS")
			}
			if cr {
				what = append(what, "create role")
			}
			r.ElevatedVia = append(r.ElevatedVia, name+" ("+strings.Join(what, ", ")+")")
		}
	}
	rows.Close()
	r.Predefined = map[string]bool{}
	for _, p := range auditPredefinedRoles {
		r.Predefined[p] = r.Superuser || member[p]
	}
	rep.ServerFiles = AuditServerFiles{
		CopyProgram: r.Superuser || member["pg_execute_server_program"],
		ReadFiles:   r.Superuser || member["pg_read_server_files"],
		WriteFiles:  r.Superuser || member["pg_write_server_files"],
	}

	// 3. database
	if err := q.QueryRowContext(ctx, `SELECT has_database_privilege($1::name, current_database(), 'CONNECT'),
  has_database_privilege($1::name, current_database(), 'CREATE'),
  has_database_privilege($1::name, current_database(), 'TEMP')`, role).Scan(
		&rep.Database.Connect, &rep.Database.Create, &rep.Database.Temp); err != nil {
		return fmt.Errorf("reading database privileges: %v", err)
	}

	// 4. schemas
	rows, err = q.QueryContext(ctx, `SELECT n.nspname, pg_get_userbyid(n.nspowner),
  has_schema_privilege($1::name, n.oid, 'USAGE'), has_schema_privilege($1::name, n.oid, 'CREATE'),
  pg_has_role($1::name, n.nspowner, 'USAGE'),
  EXISTS (SELECT 1 FROM aclexplode(coalesce(n.nspacl, acldefault('n', n.nspowner))) a
          WHERE a.grantee = 0 AND a.privilege_type = 'CREATE')
FROM pg_namespace n WHERE `+auditUserSchemaFilter+` ORDER BY 1`, role)
	if err != nil {
		return fmt.Errorf("reading schemas: %v", err)
	}
	usage := map[string]bool{}
	for rows.Next() {
		var s AuditSchema
		if err := rows.Scan(&s.Name, &s.Owner, &s.Usage, &s.Create, &s.OwnedByRole, &s.PublicCreate); err != nil {
			rows.Close()
			return err
		}
		usage[s.Name] = s.Usage
		rep.Schemas = append(rep.Schemas, s)
	}
	rows.Close()

	// 5. relations, privileges, RLS
	rows, err = q.QueryContext(ctx, `SELECT c.oid, n.nspname, c.relname, c.relkind::text, pg_get_userbyid(c.relowner),
  pg_has_role($1::name, c.relowner, 'USAGE'),
  has_table_privilege($1::name, c.oid, 'SELECT'), has_table_privilege($1::name, c.oid, 'INSERT'),
  has_table_privilege($1::name, c.oid, 'UPDATE'), has_table_privilege($1::name, c.oid, 'DELETE'),
  has_table_privilege($1::name, c.oid, 'TRUNCATE'), has_table_privilege($1::name, c.oid, 'REFERENCES'),
  has_table_privilege($1::name, c.oid, 'TRIGGER'),
  has_any_column_privilege($1::name, c.oid, 'SELECT'),
  c.relrowsecurity, c.relforcerowsecurity,
  (SELECT count(*) FROM pg_policy p WHERE p.polrelid = c.oid),
  coalesce((SELECT string_agg(DISTINCT a.privilege_type, ',' ORDER BY a.privilege_type)
            FROM aclexplode(c.relacl) a WHERE a.grantee = 0), '')
FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('r', 'p', 'v', 'm', 'f') AND `+auditUserSchemaFilter+`
ORDER BY 2, 3`, role)
	if err != nil {
		return fmt.Errorf("reading tables: %v", err)
	}
	type relRef struct {
		schema, name, kind string
		table              int // index in Tables, or -1
		view               int // index in Views, or -1
	}
	rels := map[int64]*relRef{}
	for rows.Next() {
		var oid int64
		var schema, name, kind, owner, public string
		var owned, sel, ins, upd, del, trn, ref, trg, anySel, rls, force bool
		var pol int
		if err := rows.Scan(&oid, &schema, &name, &kind, &owner, &owned, &sel, &ins, &upd, &del, &trn, &ref, &trg,
			&anySel, &rls, &force, &pol, &public); err != nil {
			rows.Close()
			return err
		}
		u := usage[schema]
		kn := auditKindNames[kind]
		rr := &relRef{schema: schema, name: name, kind: kn, table: -1, view: -1}
		if auditIsTableKind(kn) {
			t := AuditTable{
				Schema: schema, Name: name, Kind: kn, Owner: owner, OwnedByRole: owned, SchemaUsage: u,
				Privileges: AuditPrivs{
					Select: sel && u, Insert: ins && u, Update: upd && u, Delete: del && u,
					Truncate: trn && u, References: ref && u, Trigger: trg && u,
				},
				SelectAnyColumn: anySel && u,
				RLSEnabled:      rls, RLSForced: force, RLSPolicies: pol,
				PublicPrivileges: []string{}, SecretColumns: []string{},
			}
			t.RLSApplies = rls && !r.Superuser && !r.BypassRLS && (!owned || force)
			if public != "" {
				t.PublicPrivileges = strings.Split(public, ",")
			}
			rr.table = len(rep.Tables)
			rep.Tables = append(rep.Tables, t)
		} else {
			v := AuditView{Schema: schema, Name: name, Kind: kn, Owner: owner,
				Select: sel && u, SelectAnyColumn: anySel && u, ReadsSecret: []string{}}
			rr.view = len(rep.Views)
			rep.Views = append(rep.Views, v)
		}
		rels[oid] = rr
	}
	rows.Close()

	// 6. columns (column-level privileges; secret detection happens in Go so
	//    the rules match the proxy's isSecretColumn exactly)
	rows, err = q.QueryContext(ctx, `SELECT c.oid, a.attname,
  has_column_privilege($1::name, c.oid, a.attnum, 'SELECT'),
  has_column_privilege($1::name, c.oid, a.attnum, 'INSERT'),
  has_column_privilege($1::name, c.oid, a.attnum, 'UPDATE')
FROM pg_attribute a JOIN pg_class c ON c.oid = a.attrelid JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE a.attnum > 0 AND NOT a.attisdropped AND c.relkind IN ('r', 'p', 'v', 'm', 'f') AND `+auditUserSchemaFilter+`
ORDER BY c.oid, a.attnum`, role)
	if err != nil {
		return fmt.Errorf("reading columns: %v", err)
	}
	for rows.Next() {
		var oid int64
		var col string
		var sel, ins, upd bool
		if err := rows.Scan(&oid, &col, &sel, &ins, &upd); err != nil {
			rows.Close()
			return err
		}
		rr := rels[oid]
		if rr == nil {
			continue
		}
		u := usage[rr.schema]
		ac := auditCol{Schema: rr.schema, Table: rr.name, Column: col, Kind: rr.kind,
			Select: sel && u, Insert: ins && u, Update: upd && u}
		rep.columns = append(rep.columns, ac)
		if isSecretColumn(col) && rr.kind != "view" {
			viaTable := false
			if rr.table >= 0 {
				rep.Tables[rr.table].SecretColumns = append(rep.Tables[rr.table].SecretColumns, col)
				viaTable = rep.Tables[rr.table].Privileges.Select
			} else if rr.view >= 0 {
				viaTable = rep.Views[rr.view].Select
			}
			rep.SecretColumns = append(rep.SecretColumns, AuditColumn{
				Schema: rr.schema, Table: rr.name, Column: col, Kind: rr.kind,
				Select: ac.Select, Insert: ac.Insert, Update: ac.Update, ViaTableGrant: viaTable && ac.Select,
			})
		}
	}
	rows.Close()

	// 7. views -> base table.column (pg_rewrite + pg_depend)
	rows, err = q.QueryContext(ctx, `SELECT DISTINCT r.ev_class, bn.nspname, b.relname, a.attname
FROM pg_rewrite r
JOIN pg_depend d ON d.classid = 'pg_rewrite'::regclass AND d.objid = r.oid
  AND d.refclassid = 'pg_class'::regclass AND d.refobjsubid > 0
JOIN pg_class b ON b.oid = d.refobjid
JOIN pg_namespace bn ON bn.oid = b.relnamespace
JOIN pg_attribute a ON a.attrelid = d.refobjid AND a.attnum = d.refobjsubid
JOIN pg_class c ON c.oid = r.ev_class
JOIN pg_namespace n ON n.oid = c.relnamespace
WHERE c.relkind IN ('v', 'm') AND d.refobjid <> r.ev_class AND `+auditUserSchemaFilter+`
ORDER BY 1, 2, 3, 4`)
	if err != nil {
		return fmt.Errorf("reading view dependencies: %v", err)
	}
	for rows.Next() {
		var oid int64
		var bs, bt, col string
		if err := rows.Scan(&oid, &bs, &bt, &col); err != nil {
			rows.Close()
			return err
		}
		rr := rels[oid]
		if rr == nil || rr.view < 0 || !isSecretColumn(col) {
			continue
		}
		rep.Views[rr.view].ReadsSecret = append(rep.Views[rr.view].ReadsSecret, bs+"."+bt+"."+col)
	}
	rows.Close()

	// 8. dangerous functions
	rows, err = q.QueryContext(ctx, `SELECT n.nspname, p.proname, pg_get_function_identity_arguments(p.oid),
  has_function_privilege($1::name, p.oid, 'EXECUTE'),
  EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
          WHERE a.grantee = 0 AND a.privilege_type = 'EXECUTE')
FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE p.proname = ANY($2::text[]) OR p.proname LIKE 'dblink%'
ORDER BY 2, 1, 3`, role, pq.Array(auditDangerousFunctions))
	if err != nil {
		return fmt.Errorf("reading functions: %v", err)
	}
	for rows.Next() {
		var f AuditFunction
		if err := rows.Scan(&f.Schema, &f.Name, &f.Args, &f.Execute, &f.GrantedToPublic); err != nil {
			rows.Close()
			return err
		}
		rep.Functions = append(rep.Functions, f)
	}
	rows.Close()

	// 9. extensions (+ FDW usage)
	rows, err = q.QueryContext(ctx, `SELECT e.extname, e.extversion, n.nspname,
  (SELECT bool_or(has_foreign_data_wrapper_privilege($1::name, w.oid, 'USAGE'))
     FROM pg_foreign_data_wrapper w WHERE w.fdwname = e.extname)
FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
WHERE e.extname = ANY($2::text[]) ORDER BY 1`, role, pq.Array(auditExtensions))
	if err != nil {
		return fmt.Errorf("reading extensions: %v", err)
	}
	for rows.Next() {
		var e AuditExtension
		var fdw sql.NullBool
		if err := rows.Scan(&e.Name, &e.Version, &e.Schema, &fdw); err != nil {
			rows.Close()
			return err
		}
		if fdw.Valid {
			b := fdw.Bool
			e.Usage = &b
		}
		rep.Extensions = append(rep.Extensions, e)
	}
	rows.Close()

	// 10. serial sequences (for --fix --writes)
	rows, err = q.QueryContext(ctx, `SELECT tn.nspname, t.relname, sn.nspname, s.relname,
  has_sequence_privilege($1::name, s.oid, 'USAGE')
FROM pg_depend d
JOIN pg_class s ON s.oid = d.objid AND s.relkind = 'S'
JOIN pg_namespace sn ON sn.oid = s.relnamespace
JOIN pg_class t ON t.oid = d.refobjid
JOIN pg_namespace tn ON tn.oid = t.relnamespace
WHERE d.classid = 'pg_class'::regclass AND d.refclassid = 'pg_class'::regclass AND d.deptype = 'a'
ORDER BY 1, 2, 3, 4`, role)
	if err != nil {
		return fmt.Errorf("reading sequences: %v", err)
	}
	for rows.Next() {
		var s auditSeq
		if err := rows.Scan(&s.TableSchema, &s.Table, &s.Schema, &s.Name, &s.Usage); err != nil {
			rows.Close()
			return err
		}
		rep.sequences = append(rep.sequences, s)
	}
	rows.Close()

	// 11. sessions using this role right now (shared-login signal)
	if err := q.QueryRowContext(ctx, `SELECT count(*), count(DISTINCT application_name)
FROM pg_stat_activity WHERE usename = $1 AND pid <> pg_backend_pid()`, role).Scan(
		&rep.Sessions.Open, &rep.Sessions.ApplicationNames); err != nil {
		return fmt.Errorf("reading sessions: %v", err)
	}

	computeAuditSummary(rep)
	return nil
}

func computeAuditSummary(rep *AuditReport) {
	s := AuditSummary{}
	for _, t := range rep.Tables {
		s.Tables++
		p := t.Privileges
		if p.Select || t.SelectAnyColumn {
			s.Select++
		}
		if p.Insert {
			s.Insert++
		}
		if p.Update {
			s.Update++
		}
		if p.Delete {
			s.Delete++
		}
		if p.Truncate {
			s.Truncate++
		}
		if p.References {
			s.References++
		}
		if p.Trigger {
			s.Trigger++
		}
		if t.OwnedByRole {
			s.Owned++
		}
		if t.RLSEnabled {
			s.RLSTables++
			if t.RLSApplies {
				s.RLSAppliesToRole++
			}
		}
		if len(t.PublicPrivileges) > 0 {
			s.TablesGrantedToPublic++
		}
	}
	for _, v := range rep.Views {
		s.Views++
		if v.Select || v.SelectAnyColumn {
			s.ViewsReadable++
			if len(v.ReadsSecret) > 0 {
				s.SensitiveViewsReadable++
			}
		}
	}
	for _, c := range rep.SecretColumns {
		if c.Select {
			s.SecretColumnsReadable++
		}
	}
	s.DangerousFunctionsExec = len(auditExecutableFunctionNames(rep))
	for _, sc := range rep.Schemas {
		if sc.Create {
			s.SchemasWithCreate++
		}
	}
	rep.Summary = s
}

// auditExecutableFunctionNames returns the distinct dangerous function names
// the role can EXECUTE (any overload), sorted. The dblink family counts as
// one entry, "dblink*", so the report stays short.
func auditExecutableFunctionNames(rep *AuditReport) []string {
	seen := map[string]bool{}
	var out []string
	// pg_cancel_backend / pg_terminate_backend are EXECUTE-able by PUBLIC on
	// every server; without pg_signal_backend (or superuser) they only reach
	// the role's own sessions, so flagging them is noise.
	canSignal := rep.Role.Superuser || rep.Role.Predefined["pg_signal_backend"]
	for _, f := range rep.Functions {
		name := f.Name
		if strings.HasPrefix(name, "dblink") {
			name = "dblink*"
		}
		if (name == "pg_cancel_backend" || name == "pg_terminate_backend") && !canSignal {
			continue
		}
		if f.Execute && !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}
