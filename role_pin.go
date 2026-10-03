package main

// role_pin.go — per-agent database role (db_role from the control plane).
//
// When a key-authenticated agent has a db_role, the proxy runs
// SET SESSION ROLE "<db_role>" upstream right after it logs in, before any
// client query is read. Postgres then enforces that role's grants itself: a
// SELECT-only role makes the database reject writes even if a FaultWall rule
// were wrong. The proxy's own login must be a member of the role
// (GRANT <db_role> TO <proxy user>).
//
// The pin only holds if the agent can't undo it, so for pinned sessions the
// proxy refuses anything that changes or resets the role, in every
// enforcement mode (it is part of authentication, not a policy rule):
//
//	SET [SESSION|LOCAL] ROLE ..., SET ROLE NONE, RESET ROLE
//	SET/RESET SESSION AUTHORIZATION
//	RESET ALL, DISCARD ALL (both reset the role)
//	set_config('role' | 'session_authorization', ...), or set_config with a
//	  non-constant name (can't prove it isn't 'role')
//	any of the above nested anywhere (multi-statement strings, PREPARE,
//	  CREATE/ALTER FUNCTION ... SET role, function bodies, DO blocks)
//
// DO blocks and function bodies are opaque to the parser, so their source is
// matched textually (fail closed: a body that merely mentions "role" is
// refused for pinned agents).

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"

	"github.com/jackc/pgproto3/v2"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// roleFixedMessage is what a pinned agent sees when it tries to change role.
const roleFixedMessage = "[BLOCKED by FaultWall] agent role is fixed"

// dbRoleRe is the same identifier rule the control plane enforces.
var dbRoleRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,62}$`)

// roleWordsRe matches role-changing text inside opaque bodies (DO, function
// source) and in queries Postgres' parser can't parse.
var roleWordsRe = regexp.MustCompile(`(?i)\brole\b|session_authorization|\bset_config\b|\breset\s+all\b|\bdiscard\s+all\b`)

// quoteIdent quotes a Postgres identifier.
func quoteIdent(s string) string { return `"` + strings.ReplaceAll(s, `"`, `""`) + `"` }

// roleChangeAttempt reports whether query could change or reset the
// session's role, with a short reason.
func roleChangeAttempt(query string) (bool, string) {
	q := sanitizeQuery(query)
	if q == "" {
		return false, ""
	}
	j, err := pg_query.ParseToJSON(q)
	if err != nil {
		// Postgres would most likely reject it too, but don't bet the pin on it.
		if roleWordsRe.MatchString(q) {
			return true, "unparseable statement mentions role"
		}
		return false, ""
	}
	var tree interface{}
	if err := json.Unmarshal([]byte(j), &tree); err != nil {
		return true, "unreadable parse tree"
	}
	return walkRoleChange(tree)
}

func walkRoleChange(n interface{}) (bool, string) {
	switch v := n.(type) {
	case []interface{}:
		for _, c := range v {
			if hit, why := walkRoleChange(c); hit {
				return true, why
			}
		}
	case map[string]interface{}:
		if vs, ok := v["VariableSetStmt"].(map[string]interface{}); ok {
			name := strings.ToLower(str(vs["name"]))
			if name == "role" || name == "session_authorization" {
				return true, "changes " + name
			}
			if str(vs["kind"]) == "VAR_RESET_ALL" {
				return true, "RESET ALL resets the role"
			}
		}
		if ds, ok := v["DiscardStmt"].(map[string]interface{}); ok && str(ds["target"]) == "DISCARD_ALL" {
			return true, "DISCARD ALL resets the role"
		}
		if fc, ok := v["FuncCall"].(map[string]interface{}); ok && funcName(fc) == "set_config" {
			args, _ := fc["args"].([]interface{})
			if len(args) == 0 {
				return true, "set_config"
			}
			name, isConst := constString(args[0])
			name = strings.ToLower(strings.TrimSpace(name))
			if !isConst {
				return true, "set_config with a non-constant name"
			}
			if name == "role" || name == "session_authorization" {
				return true, "set_config('" + name + "')"
			}
		}
		for _, k := range []string{"DoStmt", "CreateFunctionStmt"} {
			if body, ok := v[k]; ok {
				b, _ := json.Marshal(body)
				if roleWordsRe.Match(b) {
					return true, "code body mentions role"
				}
			}
		}
		for _, c := range v {
			if hit, why := walkRoleChange(c); hit {
				return true, why
			}
		}
	}
	return false, ""
}

func str(v interface{}) string { s, _ := v.(string); return s }

// funcName is the unqualified, lowercased name of a FuncCall node.
func funcName(fc map[string]interface{}) string {
	parts, _ := fc["funcname"].([]interface{})
	if len(parts) == 0 {
		return ""
	}
	last, _ := parts[len(parts)-1].(map[string]interface{})
	s, _ := last["String"].(map[string]interface{})
	return strings.ToLower(str(s["sval"]))
}

// constString unwraps TypeCast/A_Const to a string literal.
func constString(n interface{}) (string, bool) {
	m, ok := n.(map[string]interface{})
	if !ok {
		return "", false
	}
	if tc, ok := m["TypeCast"].(map[string]interface{}); ok {
		return constString(tc["arg"])
	}
	if ac, ok := m["A_Const"].(map[string]interface{}); ok {
		if sv, ok := ac["sval"].(map[string]interface{}); ok {
			return str(sv["sval"]), true
		}
	}
	return "", false
}

// applySessionRole switches the upstream session to role before any client
// query runs. ParameterStatus/Notice messages are passed to the client (they
// describe the session it gets); CommandComplete and ReadyForQuery are
// consumed. Returns Postgres' error message on failure.
func applySessionRole(client, upstream net.Conn, role string) error {
	if !dbRoleRe.MatchString(role) {
		return fmt.Errorf("%q is not a valid role name", role)
	}
	q := "SET SESSION ROLE " + quoteIdent(role)
	if err := writeWireMessage(upstream, 'Q', append([]byte(q), 0)); err != nil {
		return err
	}
	var pgErr string
	for {
		t, p, err := readWireMessage(upstream)
		if err != nil {
			return fmt.Errorf("reading upstream reply to SET SESSION ROLE: %w", err)
		}
		switch t {
		case 'E':
			pgErr = errorResponseText(p)
		case 'S', 'N':
			if err := writeWireMessage(client, t, p); err != nil {
				return err
			}
		case 'Z':
			if pgErr != "" {
				return errors.New(pgErr)
			}
			return nil
		}
	}
}

// errorResponseText extracts "message (SQLSTATE)" from an ErrorResponse payload.
func errorResponseText(p []byte) string {
	var msg, code string
	for len(p) > 1 && p[0] != 0 {
		f := p[0]
		end := indexOf(p[1:], 0)
		if end < 0 {
			break
		}
		val := string(p[1 : 1+end])
		p = p[2+end:]
		switch f {
		case 'M':
			msg = val
		case 'C':
			code = val
		}
	}
	if code != "" {
		return msg + " (SQLSTATE " + code + ")"
	}
	return msg
}

// fatalMessage is a FATAL ErrorResponse (the connection closes after it).
func fatalMessage(code, msg string) []byte {
	e := &pgproto3.ErrorResponse{Severity: "FATAL", Code: code, Message: "[BLOCKED by FaultWall] " + msg}
	buf, _ := e.Encode(nil)
	return buf
}

// roleFixedResponse is ERROR 42501 + ReadyForQuery: the statement is refused
// but the connection stays usable.
func roleFixedResponse(role, why string, txStatus byte) []byte {
	if txStatus == 0 {
		txStatus = 'I'
	}
	e := &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501",
		Message:  roleFixedMessage,
		Detail:   fmt.Sprintf("This agent's sessions run as database role %q, set on the FaultWall Agents page (%s).", role, why),
		Hint:     "Statements that change or reset the role are refused for this agent. Change the agent's DB role on the Agents page instead.",
	}
	buf, _ := e.Encode(nil)
	buf, _ = (&pgproto3.ReadyForQuery{TxStatus: txStatus}).Encode(buf)
	return buf
}
