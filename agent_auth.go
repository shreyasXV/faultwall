package main

// agent_auth.go — connection-startup authentication for per-agent keys.
//
// Two ways to present a key (see agent_keys.go for where keys come from):
//
//  1. As the Postgres password (the Connect screen's connection string):
//       postgresql://support-agent:fw_ak_...@faultwall:5433/prod
//     The startup `user` is a managed agent name, so the proxy terminates
//     client auth itself with SCRAM-SHA-256 against the agent's synced
//     verifier (scram_server.go): the key never crosses the wire and the
//     proxy never holds it. It then logs in upstream with ITS OWN database
//     credentials (FW_UPSTREAM_USER / FW_UPSTREAM_PASSWORD, falling back to
//     DATABASE_URL, then PGUSER / PGPASSWORD). The agent never holds real DB
//     credentials. Cleartext key auth is only used for keys created before
//     SCRAM support, and only when FW_ALLOW_CLEARTEXT_KEY=*** is set.
//
//  2. As the token in application_name (agent keeps its own DB creds):
//       application_name=agent:support-agent:mission:triage:token:fw_ak_...
//     The key is verified and stripped before application_name is forwarded,
//     so it never shows up in pg_stat_activity. DB auth is passed through.
//
// Either way the session is labeled upstream as agent:<name>:mission:<m>.
// Unknown or revoked keys, and managed agents that present no key, are
// refused at startup with a clear FATAL message. Connections that don't touch
// managed agents keep the legacy application_name identity unchanged.

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"strings"

	"github.com/lib/pq/scram"
)

// startupParam is one key/value pair of a StartupMessage, order preserved.
type startupParam struct{ Key, Val string }

// parseStartupParams returns the protocol version and parameters.
func parseStartupParams(buf []byte) (uint32, []startupParam) {
	if len(buf) < 8 {
		return 0, nil
	}
	proto := binary.BigEndian.Uint32(buf[4:8])
	var out []startupParam
	params := buf[8:]
	for len(params) > 1 {
		i := indexOf(params, 0)
		if i <= 0 {
			break
		}
		k := string(params[:i])
		params = params[i+1:]
		j := indexOf(params, 0)
		if j < 0 {
			break
		}
		out = append(out, startupParam{k, string(params[:j])})
		params = params[j+1:]
	}
	return proto, out
}

func startupGet(ps []startupParam, key string) string {
	for _, p := range ps {
		if p.Key == key {
			return p.Val
		}
	}
	return ""
}

// startupSet replaces (or appends) key.
func startupSet(ps []startupParam, key, val string) []startupParam {
	for i := range ps {
		if ps[i].Key == key {
			ps[i].Val = val
			return ps
		}
	}
	return append(ps, startupParam{key, val})
}

func buildStartupMessage(proto uint32, ps []startupParam) []byte {
	body := make([]byte, 4)
	binary.BigEndian.PutUint32(body, proto)
	for _, p := range ps {
		body = append(body, p.Key...)
		body = append(body, 0)
		body = append(body, p.Val...)
		body = append(body, 0)
	}
	body = append(body, 0)
	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	return append(out, body...)
}

// agentAuthMode is how a connection authenticates.
type agentAuthMode int

const (
	authPassthrough agentAuthMode = iota // legacy: upstream does auth, identity from application_name
	authKeyPassword                      // key as PG password, proxy logs in upstream
	authKeyToken                         // key as application_name token, upstream auth passthrough
)

// agentAuthDecision is the outcome of startupAgentAuth.
type agentAuthDecision struct {
	Mode     agentAuthMode
	Identity *AgentIdentity // final identity (nil = unidentified)
	Startup  []byte         // startup message to forward upstream (may be rewritten)
	Err      string         // non-empty = refuse the connection with this message
	// For authKeyPassword: the agent name the client claimed as `user`.
	ClaimedUser string
	// For authKeyToken: sha256 of the key that identified the session.
	KeyHash string
}

// managedAppName is the label forwarded upstream for key-authenticated agents.
func managedAppName(agent, mission string) string {
	if mission == "" {
		mission = "default"
	}
	return "agent:" + agent + ":mission:" + mission
}

func keyErr(format string, a ...interface{}) string {
	return "FaultWall: " + fmt.Sprintf(format, a...)
}

// startupAgentAuth decides how to authenticate a connection from its
// startup message. It does not do I/O; password mode finishes in
// verifyAgentPassword once the client sends its password.
func startupAgentAuth(startupBuf []byte, keys *AgentKeyStore) agentAuthDecision {
	proto, params := parseStartupParams(startupBuf)
	appName := startupGet(params, "application_name")
	user := startupGet(params, "user")
	identity := ParseAgentIdentity(appName)
	d := agentAuthDecision{Mode: authPassthrough, Identity: identity, Startup: startupBuf}

	// (1) key as password: the startup user is a managed agent name.
	if user != "" && keys.HasAgent(user) {
		if identity != nil && identity.AgentID != user {
			d.Err = keyErr("user %q and application_name agent %q disagree. Use the connection string from the Agents page as-is.", user, identity.AgentID)
			return d
		}
		mission := ""
		if identity != nil {
			mission = identity.MissionID
		}
		d.Mode = authKeyPassword
		d.ClaimedUser = user
		d.Identity = &AgentIdentity{AgentID: user, MissionID: nonEmpty(mission, "default"), Raw: managedAppName(user, mission)}
		return d
	}

	// (2) key as application_name token.
	if identity != nil && strings.HasPrefix(identity.Token, AgentKeyPrefix) {
		e, ok := keys.Lookup(identity.Token)
		switch {
		case !ok:
			d.Err = keyErr("unknown agent key for %q. Copy the connection details from the Agents page (keys are shown once; create a new key if this one was lost).", identity.AgentID)
			return d
		case e.Revoked:
			d.Err = keyErr("the key for agent %q was revoked. Create a new key on the Agents page.", e.Agent)
			return d
		case e.Agent != identity.AgentID:
			d.Err = keyErr("this key belongs to a different agent, not %q.", identity.AgentID)
			return d
		}
		label := managedAppName(e.Agent, identity.MissionID)
		d.Mode = authKeyToken
		d.KeyHash = e.KeySHA256
		d.Identity = &AgentIdentity{AgentID: e.Agent, MissionID: nonEmpty(identity.MissionID, "default"), Raw: label}
		d.Startup = buildStartupMessage(proto, startupSet(params, "application_name", label))
		return d
	}

	// (3) a managed agent claimed by name without its key: refuse (closes the
	// application_name spoofing gap for every dashboard-managed agent).
	if identity != nil && keys.HasAgent(identity.AgentID) {
		d.Err = keyErr("agent %q is managed by FaultWall and needs its key. Connect with the connection string from the Agents page (or add :token:<key> to application_name).", identity.AgentID)
		return d
	}
	return d
}

// verifyAgentPassword checks the password the client sent for a managed agent.
func verifyAgentPassword(agent, password string, keys *AgentKeyStore) string {
	if password == "" {
		return keyErr("agent %q needs its key as the password. Use the connection string from the Agents page.", agent)
	}
	e, ok := keys.Lookup(password)
	switch {
	case !ok:
		return keyErr("unknown agent key for %q. Copy the connection string from the Agents page (keys are shown once; create a new key if this one was lost).", agent)
	case e.Revoked:
		return keyErr("the key for agent %q was revoked. Create a new key on the Agents page.", agent)
	case e.Agent != agent:
		return keyErr("this key belongs to a different agent, not %q.", agent)
	}
	return ""
}

// cleartextKeyAllowed: legacy cleartext key-as-password is opt-in only.
func cleartextKeyAllowed() bool {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("FW_ALLOW_CLEARTEXT_KEY")))
	return v == "1" || v == "true" || v == "yes"
}

// authenticateAgentKey runs key-as-password auth for a managed agent with
// the client: SCRAM-SHA-256 when the agent's key has a verifier, otherwise
// cleartext if (and only if) explicitly allowed. Returns "" on success or the
// FATAL message to send. Nothing is sent upstream before this succeeds.
// keyHash identifies the key that authenticated, so the session can be ended
// when that specific key is revoked.
func authenticateAgentKey(r io.Reader, w io.Writer, agent string, keys *AgentKeyStore) (msg, method, keyHash string) {
	live, any := keys.agentState(agent)
	if any && live == 0 {
		return keyErr("the key for agent %q was revoked. Create a new key on the Agents page.", agent), "none", ""
	}
	if sk := keys.ScramKeys(agent); len(sk) > 0 {
		err := scramServerAuth(r, w, sk[0].Scram)
		switch {
		case err == nil:
			return "", "scram-sha-256", sk[0].KeySHA256
		case errors.Is(err, errScramBadProof):
			return keyErr("wrong key for agent %q. Copy the connection string from the Agents page (keys are shown once; create a new key if this one was lost).", agent), "scram-sha-256", ""
		default:
			return keyErr("agent %q key authentication failed: %v", agent, err), "scram-sha-256", ""
		}
	}
	if !cleartextKeyAllowed() {
		return keyErr("the key for agent %q was created before SCRAM support. Create a new key on the Agents page (or set FW_ALLOW_CLEARTEXT_KEY=*** on the proxy to accept it over cleartext).", agent), "none", ""
	}
	rw, ok := w.(net.Conn)
	if !ok {
		return keyErr("internal: cleartext auth needs a connection"), "cleartext", ""
	}
	pw, err := requestClientPassword(rw)
	if err != nil {
		return keyErr("agent %q: %v", agent, err), "cleartext", ""
	}
	if msg := verifyAgentPassword(agent, pw, keys); msg != "" {
		return msg, "cleartext", ""
	}
	return "", "cleartext", HashAgentKey(pw)
}

// upstreamCreds is what the proxy logs in upstream with for password-mode agents.
type upstreamCreds struct{ User, Password string }

func resolveUpstreamCreds() (upstreamCreds, bool) {
	c := upstreamCreds{User: os.Getenv("FW_UPSTREAM_USER"), Password: os.Getenv("FW_UPSTREAM_PASSWORD")}
	if c.User != "" {
		return c, true
	}
	if raw := os.Getenv("DATABASE_URL"); raw != "" {
		if u, err := url.Parse(raw); err == nil && u.User != nil && u.User.Username() != "" {
			c.User = u.User.Username()
			c.Password, _ = u.User.Password()
			return c, true
		}
	}
	if pu := os.Getenv("PGUSER"); pu != "" {
		return upstreamCreds{User: pu, Password: os.Getenv("PGPASSWORD")}, true
	}
	return c, false
}

// boundUpstreamDatabase is the one database key-authenticated agents may
// open through this proxy: FW_UPSTREAM_DATABASE, else the database in
// DATABASE_URL. "*" (or neither set) allows any database the proxy's login
// can reach. Without a binding an agent could change the database name in
// its DSN and use the proxy's credentials against another database.
func boundUpstreamDatabase() string {
	if d := strings.TrimSpace(os.Getenv("FW_UPSTREAM_DATABASE")); d != "" {
		if d == "*" {
			return ""
		}
		return d
	}
	if raw := os.Getenv("DATABASE_URL"); raw != "" {
		if u, err := url.Parse(raw); err == nil {
			return strings.TrimPrefix(u.Path, "/")
		}
	}
	return ""
}

// bindStartupDatabase applies boundUpstreamDatabase to a key-authenticated
// startup. A missing database defaults to the bound one; a different one is
// refused before the startup is forwarded upstream.
func bindStartupDatabase(params []startupParam) ([]startupParam, error) {
	bound := boundUpstreamDatabase()
	if bound == "" {
		return params, nil
	}
	for _, p := range params {
		if p.Key == "database" && p.Val != "" && p.Val != bound {
			return nil, fmt.Errorf("this proxy only serves database %q; the agent asked for %q. Point the agent's connection string at %q, or run a separate proxy for that database", bound, p.Val, bound)
		}
	}
	return startupSet(params, "database", bound), nil
}

// requestClientPassword sends AuthenticationCleartextPassword and reads the
// client's PasswordMessage.
func requestClientPassword(client net.Conn) (string, error) {
	req := make([]byte, 4)
	binary.BigEndian.PutUint32(req, 3)
	if err := writeWireMessage(client, 'R', req); err != nil {
		return "", err
	}
	t, payload, err := readWireMessage(client)
	if err != nil {
		return "", fmt.Errorf("reading client password: %w", err)
	}
	if t != 'p' {
		return "", fmt.Errorf("expected password message, got %q", t)
	}
	if n := indexOf(payload, 0); n >= 0 {
		payload = payload[:n]
	}
	return string(payload), nil
}

func md5Hex(s string) string {
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

// upstreamLogin authenticates to upstream as the proxy (cleartext, MD5 or
// SCRAM-SHA-256), then relays AuthenticationOk + ParameterStatus +
// BackendKeyData + ReadyForQuery to the client. Returns the backend PID.
// An upstream ErrorResponse is forwarded to the client verbatim.
// forwardReady=false holds back the final ReadyForQuery so the caller can run
// session setup (SET SESSION ROLE) before the client may send queries; the
// caller then sends ReadyForQuery itself.
func upstreamLogin(client, upstream net.Conn, creds upstreamCreds, forwardReady bool) (int, error) {
	var sc *scram.Client
	pid := 0
	authed := false
	for {
		t, payload, err := readWireMessage(upstream)
		if err != nil {
			return pid, fmt.Errorf("reading upstream auth message: %w", err)
		}
		if t == 'E' {
			_ = writeWireMessage(client, t, payload)
			return pid, fmt.Errorf("upstream rejected FaultWall's database login (user %q)", creds.User)
		}
		if t == 'R' && !authed {
			if len(payload) < 4 {
				return pid, fmt.Errorf("short auth message")
			}
			at := binary.BigEndian.Uint32(payload[:4])
			switch at {
			case 0: // AuthenticationOk
				authed = true
				if err := writeWireMessage(client, t, payload); err != nil {
					return pid, err
				}
				continue
			case 3: // cleartext
				if err := writeWireMessage(upstream, 'p', append([]byte(creds.Password), 0)); err != nil {
					return pid, err
				}
			case 5: // MD5
				if len(payload) < 8 {
					return pid, fmt.Errorf("short md5 salt")
				}
				resp := "md5" + md5Hex(md5Hex(creds.Password+creds.User)+string(payload[4:8]))
				if err := writeWireMessage(upstream, 'p', append([]byte(resp), 0)); err != nil {
					return pid, err
				}
			case 10: // SASL
				if !strings.Contains(string(payload[4:]), "SCRAM-SHA-256\x00") {
					return pid, fmt.Errorf("upstream offers no SCRAM-SHA-256")
				}
				sc = scram.NewClient(sha256.New, creds.User, creds.Password)
				sc.Step(nil)
				if sc.Err() != nil {
					return pid, sc.Err()
				}
				first := sc.Out()
				msg := append([]byte("SCRAM-SHA-256"), 0)
				l := make([]byte, 4)
				binary.BigEndian.PutUint32(l, uint32(len(first)))
				msg = append(append(msg, l...), first...)
				if err := writeWireMessage(upstream, 'p', msg); err != nil {
					return pid, err
				}
			case 11: // SASLContinue
				if sc == nil {
					return pid, fmt.Errorf("unexpected SASLContinue")
				}
				sc.Step(payload[4:])
				if sc.Err() != nil {
					return pid, sc.Err()
				}
				if err := writeWireMessage(upstream, 'p', sc.Out()); err != nil {
					return pid, err
				}
			case 12: // SASLFinal
				if sc == nil {
					return pid, fmt.Errorf("unexpected SASLFinal")
				}
				sc.Step(payload[4:])
				if sc.Err() != nil {
					return pid, fmt.Errorf("upstream SCRAM verification failed: %w", sc.Err())
				}
			default:
				return pid, fmt.Errorf("unsupported upstream auth method %d", at)
			}
			continue
		}
		// Post-auth: relay to client until ReadyForQuery.
		if t == 'Z' && !forwardReady {
			return pid, nil
		}
		if err := writeWireMessage(client, t, payload); err != nil {
			return pid, err
		}
		switch t {
		case 'K':
			if len(payload) >= 4 {
				pid = int(binary.BigEndian.Uint32(payload[:4]))
			}
		case 'Z':
			return pid, nil
		}
	}
}
