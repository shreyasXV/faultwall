package main

// agent_auth.go — connection-startup authentication for per-agent keys.
//
// Two ways to present a key (see agent_keys.go for where keys come from):
//
//  1. As the Postgres password (the Connect screen's connection string):
//       postgresql://support-agent:fw_ak_...@faultwall:5433/prod
//     The startup `user` is a managed agent name, so the proxy terminates
//     client auth itself: it asks the client for a cleartext password,
//     verifies sha256(password) against the synced key hashes, then logs in
//     upstream with ITS OWN database credentials (FW_UPSTREAM_USER /
//     FW_UPSTREAM_PASSWORD, falling back to DATABASE_URL, then PGUSER /
//     PGPASSWORD). The agent never holds real DB credentials.
//     Cleartext is required because only the hash is stored (SCRAM would
//     need the raw secret); use --tls-cert/--tls-key off a trusted network.
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
	"fmt"
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
func upstreamLogin(client, upstream net.Conn, creds upstreamCreds) (int, error) {
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
