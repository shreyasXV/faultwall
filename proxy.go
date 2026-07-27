package main

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgproto3/v2"
)

// ANSI color codes
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorCyan   = "\033[36m"
	colorBold   = "\033[1m"
)

// dialUpstream connects to the upstream Postgres, performing SSLRequest
// negotiation when tlsConfig is non-nil (required by RDS/Aurora/Cloud SQL/etc).
func dialUpstream(upstreamAddr string, tlsConfig *tls.Config) (net.Conn, error) {
	conn, err := net.Dial("tcp", upstreamAddr)
	if err != nil {
		return nil, fmt.Errorf("upstream dial failed (%s): %w", upstreamAddr, err)
	}
	if tlsConfig == nil {
		return conn, nil
	}

	// PostgreSQL SSLRequest: 8 bytes total
	// [4 bytes length = 8] [4 bytes code = 80877103 (0x04D2162F)]
	var sslReq [8]byte
	binary.BigEndian.PutUint32(sslReq[0:4], 8)
	binary.BigEndian.PutUint32(sslReq[4:8], 80877103)
	if _, err := conn.Write(sslReq[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send SSLRequest to upstream: %w", err)
	}

	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var resp [1]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read SSLRequest response from upstream: %w", err)
	}
	conn.SetReadDeadline(time.Time{})

	switch resp[0] {
	case 'S':
		tlsConn := tls.Client(conn, tlsConfig)
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream TLS handshake failed: %w", err)
		}
		log.Printf("Upstream TLS negotiated via SSLRequest")
		return tlsConn, nil
	case 'N':
		conn.Close()
		log.Printf("Upstream rejected TLS (SSLRequest → N) — check RDS/server TLS config")
		return nil, fmt.Errorf("upstream does not support TLS but UPSTREAM_TLS was set")
	default:
		conn.Close()
		return nil, fmt.Errorf("unexpected SSLRequest response from upstream: 0x%02X", resp[0])
	}
}

func runProxy(listenAddr, upstreamAddr string, pe *PolicyEngine, tlsCert, tlsKey string, upstreamTLS, upstreamTLSSkipVerify bool) {
	var tlsConfig *tls.Config
	if tlsCert != "" && tlsKey != "" {
		cert, err := tls.LoadX509KeyPair(tlsCert, tlsKey)
		if err != nil {
			log.Fatalf("Proxy: failed to load TLS certificate: %v", err)
		}
		tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		log.Printf("🔒 TLS enabled for client connections (cert: %s, key: %s)", tlsCert, tlsKey)
	} else {
		log.Printf("⚠️  TLS not configured — client connections will be plaintext")
	}

	// Build upstream TLS config if enabled
	var upstreamTLSConfig *tls.Config
	if upstreamTLS {
		host := upstreamAddr
		if h, _, err := net.SplitHostPort(upstreamAddr); err == nil {
			host = h
		}
		upstreamTLSConfig = &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: upstreamTLSSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}
		if upstreamTLSSkipVerify {
			log.Printf("🔒 Upstream TLS enabled (skip verify — NOT for production)")
		} else {
			log.Printf("🔒 Upstream TLS enabled (server: %s)", host)
		}
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("Proxy: failed to listen on %s: %v", listenAddr, err)
	}
	log.Printf("🛡️  FaultWall proxy listening on %s%s%s → upstream %s%s%s",
		colorCyan, listenAddr, colorReset, colorCyan, upstreamAddr, colorReset)
	log.Printf("   Enforcement mode: %s%s%s", colorBold, pe.GetEnforcement(), colorReset)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Proxy: accept error: %v", err)
			continue
		}
		go handleProxyConn(conn, upstreamAddr, pe, tlsConfig, upstreamTLSConfig)
	}
}

func handleProxyConn(client net.Conn, upstreamAddr string, pe *PolicyEngine, tlsConfig *tls.Config, upstreamTLSConfig *tls.Config) {
	defer client.Close()

	// 1. Read startup message (no type byte — starts with 4-byte length)
	startupBuf, err := readStartupMessage(client)
	if err != nil {
		log.Printf("Proxy: failed to read startup: %v", err)
		return
	}

	// Handle pre-startup negotiation (GSS, SSL, Cancel) — may need multiple rounds
	// psql 16+ sends: GSSENCRequest → SSLRequest → StartupMessage
	for {
		if len(startupBuf) < 8 {
			break
		}
		proto := binary.BigEndian.Uint32(startupBuf[4:8])
		if proto == 80877104 { // GSSENCRequest
			client.Write([]byte{'N'})
			startupBuf, err = readStartupMessage(client)
			if err != nil {
				log.Printf("Proxy: failed to read startup after GSS denial: %v", err)
				return
			}
		} else if proto == 80877103 { // SSLRequest
			if tlsConfig != nil {
				client.Write([]byte{'S'})
				client = tls.Server(client, tlsConfig)
			} else {
				client.Write([]byte{'N'})
			}
			startupBuf, err = readStartupMessage(client)
			if err != nil {
				log.Printf("Proxy: failed to read startup after SSL negotiation: %v", err)
				return
			}
		} else if proto == 80877102 { // CancelRequest
			upstream, dialErr := dialUpstream(upstreamAddr, upstreamTLSConfig)
			if dialErr == nil {
				upstream.Write(startupBuf)
				upstream.Close()
			}
			return
		} else {
			break // Real startup message — proceed
		}
	}

	// 2. Extract application_name from startup parameters
	appName := extractAppName(startupBuf)
	identity := ParseAgentIdentity(appName)

	agentLabel := "unknown"
	if identity != nil {
		agentLabel = identity.AgentID
		if identity.MissionID != "" {
			agentLabel += "/" + identity.MissionID
		}
	} else if appName != "" {
		agentLabel = appName
	}

	log.Printf("🔌 New connection: %sagent=%s%s remote=%s", colorCyan, agentLabel, colorReset, client.RemoteAddr())

	// 2b. Validate auth token (before connecting to upstream)
	if identity != nil {
		cfg := pe.GetConfig()
		if cfg != nil {
			ap, ok := cfg.Agents[identity.AgentID]
			agentHasToken := ok && ap.AuthToken != ""
			tokensMatch := agentHasToken && identity.Token == ap.AuthToken
			if agentHasToken {
				if identity.Token == "" || !tokensMatch {
					log.Printf("%s%s[BLOCKED]%s auth token mismatch for agent=%s",
						colorRed, colorBold, colorReset, agentLabel)
					sendStartupError(client, "auth token mismatch for agent: "+identity.AgentID)
					return
				}
			}
			// F3 enforcement: when the require_auth_token guard is on
			// (and the self-check confirmed it works), an agent that
			// presents an identity with no verified token is rejected
			// fail-safe closed. Disabled by default; warn-only otherwise.
			if requireAuthTokenEnforce(identity, agentHasToken, tokensMatch) {
				log.Printf("%s%s[BLOCKED]%s require_auth_token=true: agent=%s has no verified auth_token",
					colorRed, colorBold, colorReset, agentLabel)
				sendStartupError(client, "require_auth_token=true: agent has no verified auth_token: "+identity.AgentID)
				return
			}
		}
	}

	// 3. Connect to upstream Postgres (with optional TLS via SSLRequest)
	upstream, err := dialUpstream(upstreamAddr, upstreamTLSConfig)
	if err != nil {
		log.Printf("Proxy: %v", err)
		return
	}
	defer upstream.Close()

	// 4. Forward startup message to upstream
	if _, err := upstream.Write(startupBuf); err != nil {
		log.Printf("Proxy: failed to forward startup to upstream: %v", err)
		return
	}

	// 5. Relay auth handshake until ReadyForQuery ('Z'). Capture the
	// upstream backend PID (from BackendKeyData) so REAL-F9 can tell
	// proxy-originated sessions from direct-to-DB bypasses.
	upstreamPID, err := relayAuth(client, upstream)
	if err != nil {
		log.Printf("Proxy: auth relay failed for agent=%s: %v", agentLabel, err)
		return
	}
	if upstreamPID > 0 {
		proxyBackendRegistry.Register(upstreamPID)
		defer proxyBackendRegistry.Deregister(upstreamPID)
	}

	// 6. Main proxy loop
	proxyQueryLoop(client, upstream, identity, agentLabel, pe)
}

// readStartupMessage reads a PostgreSQL startup message (no type byte).
func readStartupMessage(r io.Reader) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("reading startup length: %w", err)
	}
	msgLen := int(binary.BigEndian.Uint32(lenBuf))
	if msgLen < 4 || msgLen > 10240 {
		return nil, fmt.Errorf("invalid startup message length: %d", msgLen)
	}

	buf := make([]byte, msgLen)
	copy(buf[:4], lenBuf)
	if _, err := io.ReadFull(r, buf[4:]); err != nil {
		return nil, fmt.Errorf("reading startup payload: %w", err)
	}
	return buf, nil
}

// extractAppName parses the startup message parameters for application_name.
func extractAppName(buf []byte) string {
	if len(buf) < 9 {
		return ""
	}
	// Skip: 4 bytes length + 4 bytes protocol version
	params := buf[8:]
	for len(params) > 1 {
		idx := indexOf(params, 0)
		if idx <= 0 {
			break
		}
		key := string(params[:idx])
		params = params[idx+1:]

		idx = indexOf(params, 0)
		if idx < 0 {
			break
		}
		val := string(params[:idx])
		params = params[idx+1:]

		if key == "application_name" {
			return val
		}
	}
	return ""
}

func indexOf(b []byte, v byte) int {
	for i, c := range b {
		if c == v {
			return i
		}
	}
	return -1
}

// relayAuth relays messages between client and upstream during auth
// handshake. Returns the upstream backend PID parsed from BackendKeyData
// ('K'), or 0 if not seen — used by REAL-F9 bypass detection to track
// which sessions the proxy has originated.
func relayAuth(client, upstream net.Conn) (int, error) {
	upstreamPID := 0
	for {
		// Read message from upstream (server)
		msgType, payload, err := readWireMessage(upstream)
		if err != nil {
			return upstreamPID, fmt.Errorf("reading upstream auth message: %w", err)
		}

		// Forward to client
		if err := writeWireMessage(client, msgType, payload); err != nil {
			return upstreamPID, fmt.Errorf("forwarding auth to client: %w", err)
		}

		switch msgType {
		case 'K': // BackendKeyData — first 4 bytes are the upstream PID.
			if len(payload) >= 4 {
				upstreamPID = int(binary.BigEndian.Uint32(payload[:4]))
			}
		case 'Z': // ReadyForQuery — auth complete
			return upstreamPID, nil
		case 'E': // ErrorResponse from upstream
			return upstreamPID, fmt.Errorf("upstream rejected connection")
		case 'R': // Authentication message
			if len(payload) >= 4 {
				authType := binary.BigEndian.Uint32(payload[:4])
				// 0=Ok, 12=SASLFinal — no client response needed
				// Everything else (3=Cleartext, 5=MD5, 10=SASL, 11=SASLContinue) needs a response
				if authType != 0 && authType != 12 {
					cType, cPayload, cErr := readWireMessage(client)
					if cErr != nil {
						return upstreamPID, fmt.Errorf("reading client auth response: %w", cErr)
					}
					if wErr := writeWireMessage(upstream, cType, cPayload); wErr != nil {
						return upstreamPID, fmt.Errorf("forwarding client auth to upstream: %w", wErr)
					}
				}
			}
		}
		// ParameterStatus ('S'), etc. — already forwarded
	}
}

// readWireMessage reads a standard PostgreSQL wire message: [1 byte type][4 byte length][payload].
func readWireMessage(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	msgType := header[0]
	bodyLen := int(binary.BigEndian.Uint32(header[1:5])) - 4
	if bodyLen < 0 {
		return msgType, nil, nil
	}
	if bodyLen > 1<<24 { // 16MB sanity limit
		return 0, nil, fmt.Errorf("message too large: %d bytes", bodyLen)
	}
	payload := make([]byte, bodyLen)
	if bodyLen > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return 0, nil, err
		}
	}
	return msgType, payload, nil
}

// writeWireMessage writes a standard PostgreSQL wire message.
func writeWireMessage(w io.Writer, msgType byte, payload []byte) error {
	header := make([]byte, 5)
	header[0] = msgType
	binary.BigEndian.PutUint32(header[1:5], uint32(len(payload)+4))
	if _, err := w.Write(header); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// proxyQueryLoop is the main loop: reads client messages, inspects queries, forwards or blocks.
func proxyQueryLoop(client, upstream net.Conn, identity *AgentIdentity, agentLabel string, pe *PolicyEngine) {
	var clientWriteMu sync.Mutex

	// REAL-F2: per-connection search_path. proxyQueryLoop is one goroutine
	// per client connection — the right scope. We watch every Q/Parse for a
	// `SET search_path …` (or RESET) and update this state. The policy
	// check then sees the agent's actual current search_path, not the
	// hard-coded "public" assumption from the shipped F2.
	searchPath := NewSearchPathState()

	// Row limit enforcement state
	maxRows := pe.GetMaxRows(identity)
	maxQueryTimeMs := pe.GetMaxQueryTimeMs(identity)
	rowCount := 0
	rowLimitExceeded := false

	// Max query time enforcement
	var queryTimer *time.Timer
	var queryTimedOut int32 // atomic flag
	var connShutdown sync.Once
	shutdownConn := func(reason string) {
		connShutdown.Do(func() {
			clientWriteMu.Lock()
			sendGenericBlockedResponse(client, reason)
			clientWriteMu.Unlock()
			upstream.Close()
		})
	}

	// Per-query stats tracking
	var queryStartTime time.Time
	queryRowCount := 0
	// inFlightFingerprint carries the fingerprint of the currently-executing
	// query from the request goroutine to the response goroutine so the QWM world
	// model can record the query's measured latency against its fingerprint when
	// ReadyForQuery ('Z') arrives. Same shared-closure pattern as queryStartTime.
	var inFlightFingerprint string
	var inFlightUnderLoad float64

	// Goroutine: relay upstream responses → client with DataRow counting
	go func() {
		for {
			msgType, payload, err := readWireMessage(upstream)
			if err != nil {
				client.Close()
				return
			}

			// Count DataRow ('D') messages for max_rows enforcement and stats
			if msgType == 'D' {
				queryRowCount++
				if maxRows > 0 && pe.GetEnforcement() == "enforce" {
					rowCount++
					if rowCount > maxRows && !rowLimitExceeded {
						rowLimitExceeded = true
						log.Printf("%s[BLOCKED]%s %s max_rows limit exceeded (%d rows, limit: %d)",
							colorRed, colorReset, agentLabel, rowCount, maxRows)
						pe.addViolation(PolicyViolation{
							AgentID:   identity.AgentID,
							MissionID: identity.MissionID,
							Reason:    fmt.Sprintf("max_rows exceeded (limit: %d)", maxRows),
							Action:    "blocked",
							Timestamp: time.Now(),
						})
						shutdownConn(fmt.Sprintf("FaultWall: max_rows limit (%d) exceeded for agent %s", maxRows, agentLabel))
						return
					}
				}
			}

			// Check query timeout
			if atomic.LoadInt32(&queryTimedOut) == 1 {
				shutdownConn(fmt.Sprintf("FaultWall: max_query_time_ms (%d) exceeded for agent %s", maxQueryTimeMs, agentLabel))
				return
			}

			// ReadyForQuery ('Z') = query complete, reset row counter and stop timer
			if msgType == 'Z' {
				// Record per-query stats in agent tracker
				if agentTracker != nil && identity != nil && !queryStartTime.IsZero() {
					durationMs := float64(time.Since(queryStartTime).Microseconds()) / 1000.0
					agentTracker.RecordRows(identity.AgentID, int64(queryRowCount))
					agentTracker.RecordDuration(identity.AgentID, durationMs)
				}
				// RFC-003: feed the measured latency to the QWM world model's
				// per-fingerprint base-service EWMA (only learns under low load).
				if !queryStartTime.IsZero() && inFlightFingerprint != "" {
					durationMs := float64(time.Since(queryStartTime).Microseconds()) / 1000.0
					recordQueryLatency(inFlightFingerprint, durationMs, inFlightUnderLoad)
				}
				inFlightFingerprint = ""
				queryRowCount = 0
				queryStartTime = time.Time{}

				rowCount = 0
				rowLimitExceeded = false
				if queryTimer != nil {
					queryTimer.Stop()
				}
				atomic.StoreInt32(&queryTimedOut, 0)
			}

			// Forward to client
			clientWriteMu.Lock()
			wErr := writeWireMessage(client, msgType, payload)
			clientWriteMu.Unlock()
			if wErr != nil {
				return
			}
		}
	}()

	// Track blocked Parse statements by name so we can block their Execute too
	blockedStmts := make(map[string]bool)

	for {
		msgType, payload, err := readWireMessage(client)
		if err != nil {
			upstream.Close()
			return
		}

		// Simple query protocol: type 'Q'
		if msgType == 'Q' && len(payload) > 1 {
			query := string(payload[:len(payload)-1])
			// REAL-F2: track per-connection search_path BEFORE the policy
			// check. A `SET search_path …` is a no-op for tables/functions
			// blocking but updates the state used to resolve unqualified
			// names in subsequent queries.
			if IsSearchPathStatement(query) {
				searchPath.ApplySearchPathStatement(query)
			}
			ctx := &QueryContext{SearchPath: searchPath.Schemas()}
			decisionStart := time.Now()
			violation, pq := safeCheckQueryWithContext(pe, identity, query, ctx)
			decisionLatencyMs := float64(time.Since(decisionStart).Microseconds()) / 1000.0

			// Track this query in the agent tracker
			if agentTracker != nil && identity != nil {
				agentTracker.RecordQuery(identity.AgentID)
			}

			if violation != nil && pe.GetEnforcement() == "enforce" {
				violation.Action = "blocked"
				pe.addViolation(*violation)
				clientWriteMu.Lock()
				sendBlockedResponse(client, violation, decisionLatencyMs)
				clientWriteMu.Unlock()
				logBlocked(agentLabel, query, violation)
				scoreQueryShadow(agentLabel, query, pq)
				recordObservation(agentLabel, identity, query, pq, true)
				emitTelemetryFor("blocked", "block", violation, pq, decisionLatencyMs)
				continue
			}

			if violation != nil {
				violation.Action = "monitored"
				pe.addViolation(*violation)
				logMonitored(agentLabel, query, violation)
				scoreQueryShadow(agentLabel, query, pq)
				emitTelemetryFor("monitored", "flag", violation, pq, decisionLatencyMs)
			} else {
				logAllowed(agentLabel, query)
				scoreQueryShadow(agentLabel, query, pq)
				// RFC-003: remember this fingerprint + the load it ran under so the
				// response goroutine can record its latency into the base-service EWMA.
				if pq != nil {
					inFlightFingerprint = pq.Fingerprint
					inFlightUnderLoad = currentUtilization()
				}
				emitTelemetryFor("allowed", "allow", nil, pq, decisionLatencyMs)
			}
			recordObservation(agentLabel, identity, query, pq, false)
		}

		// Extended query protocol: type 'P' (Parse)
		// Parse message format: [stmt_name \0] [query \0] [param count (int16)] [param OIDs...]
		if msgType == 'P' && len(payload) > 1 {
			stmtName, query := extractParseMessage(payload)

			if query != "" {
				if IsSearchPathStatement(query) {
					searchPath.ApplySearchPathStatement(query)
				}
				ctx := &QueryContext{SearchPath: searchPath.Schemas()}
				decisionStart := time.Now()
				violation, pq := safeCheckQueryWithContext(pe, identity, query, ctx)
				decisionLatencyMs := float64(time.Since(decisionStart).Microseconds()) / 1000.0

				// Track this query in the agent tracker
				if agentTracker != nil && identity != nil {
					agentTracker.RecordQuery(identity.AgentID)
				}

				if violation != nil && pe.GetEnforcement() == "enforce" {
					violation.Action = "blocked"
					pe.addViolation(*violation)

					// Track this statement name as blocked
					blockedStmts[stmtName] = true

					// Don't forward Parse — drain remaining messages until Sync,
					// then send ErrorResponse + ReadyForQuery
					drainUntilSync(client)
					clientWriteMu.Lock()
					sendExtendedBlockedResponse(client, violation, decisionLatencyMs)
					clientWriteMu.Unlock()
					logBlocked(agentLabel, query, violation)
					scoreQueryShadow(agentLabel, query, pq)
					recordObservation(agentLabel, identity, query, pq, true)
					emitTelemetryFor("blocked", "block", violation, pq, decisionLatencyMs)
					continue
				}

				if violation != nil {
					violation.Action = "monitored"
					pe.addViolation(*violation)
					logMonitored(agentLabel, query, violation)
					scoreQueryShadow(agentLabel, query, pq)
					emitTelemetryFor("monitored", "flag", violation, pq, decisionLatencyMs)
				} else {
					logAllowed(agentLabel, query)
					scoreQueryShadow(agentLabel, query, pq)
					emitTelemetryFor("allowed", "allow", nil, pq, decisionLatencyMs)
				}
				recordObservation(agentLabel, identity, query, pq, false)
			}
		}

		// Extended query protocol: type 'B' (Bind)
		// Check if this Bind references a blocked statement
		if msgType == 'B' && len(payload) > 2 {
			_, stmtName := extractBindNames(payload)
			if blockedStmts[stmtName] {
				// Skip this Bind — drain until Sync and send error
				drainUntilSync(client)
				clientWriteMu.Lock()
				sendGenericBlockedResponse(client, "Statement was blocked by FaultWall policy")
				clientWriteMu.Unlock()
				continue
			}
		}

		// Extended query protocol: type 'E' (Execute)
		// Check if this Execute references a blocked portal (unnamed portal from blocked Parse)
		if msgType == 'E' && len(payload) > 1 {
			portalName := extractNullTerminated(payload, 0)
			if blockedStmts[portalName] {
				drainUntilSync(client)
				clientWriteMu.Lock()
				sendGenericBlockedResponse(client, "Statement was blocked by FaultWall policy")
				clientWriteMu.Unlock()
				continue
			}
		}

		// Forward message to upstream (all non-blocked messages)
		if err := writeWireMessage(upstream, msgType, payload); err != nil {
			log.Printf("Proxy: upstream write error: %v", err)
			return
		}

		// Track query start time for stats
		if msgType == 'Q' || msgType == 'E' {
			queryStartTime = time.Now()
		}

		// Start query timer for max_query_time_ms enforcement
		if (msgType == 'Q' || msgType == 'E') && maxQueryTimeMs > 0 && pe.GetEnforcement() == "enforce" {
			if queryTimer != nil {
				queryTimer.Stop()
			}
			atomic.StoreInt32(&queryTimedOut, 0)
			queryTimer = time.AfterFunc(time.Duration(maxQueryTimeMs)*time.Millisecond, func() {
				atomic.StoreInt32(&queryTimedOut, 1)
				log.Printf("%s[BLOCKED]%s %s max_query_time_ms exceeded (%dms)",
					colorRed, colorReset, agentLabel, maxQueryTimeMs)
				pe.addViolation(PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Reason:    fmt.Sprintf("max_query_time_ms exceeded (limit: %dms)", maxQueryTimeMs),
					Action:    "blocked",
					Timestamp: time.Now(),
				})
				shutdownConn(fmt.Sprintf("FaultWall: max_query_time_ms (%d) exceeded for agent %s", maxQueryTimeMs, agentLabel))
			})
		}

		// Close statement: clean up blocked tracking
		if msgType == 'C' && len(payload) > 2 {
			closeType := payload[0]
			name := extractNullTerminated(payload, 1)
			if closeType == 'S' {
				delete(blockedStmts, name)
			} else if closeType == 'P' {
				delete(blockedStmts, name)
			}
		}

		// Terminate
		if msgType == 'X' {
			return
		}
	}
}

// extractParseMessage extracts statement name and query from a Parse message payload.
// Handles null-byte injection: validates the trailing parameter section structure
// to find the true query terminator, then replaces embedded null bytes with spaces.
func extractParseMessage(payload []byte) (stmtName, query string) {
	// Format: stmt_name \0 query \0 [int16 param_count] [int32 OID ...]
	nameEnd := indexOf(payload, 0)
	if nameEnd < 0 {
		return "", ""
	}
	stmtName = string(payload[:nameEnd])

	rest := payload[nameEnd+1:]

	// Find the correct query terminator by scanning for null bytes and
	// validating that the remaining bytes form a valid parameter section:
	// exactly 2 + paramCount*4 bytes.
	bestIdx := -1
	for i := 0; i < len(rest); i++ {
		if rest[i] != 0 {
			continue
		}
		remaining := rest[i+1:]
		if len(remaining) == 0 {
			bestIdx = i
			continue
		}
		if len(remaining) < 2 {
			continue
		}
		paramCount := int(binary.BigEndian.Uint16(remaining[:2]))
		expectedLen := 2 + paramCount*4
		if len(remaining) == expectedLen {
			bestIdx = i
			break // found the structurally valid terminator
		}
	}

	if bestIdx < 0 {
		// Fallback: use first null byte (original behavior)
		queryEnd := indexOf(rest, 0)
		if queryEnd < 0 {
			return stmtName, ""
		}
		query = string(rest[:queryEnd])
		return stmtName, query
	}

	// Extract query bytes up to the true terminator, replacing any
	// embedded null bytes with spaces to neutralize injection.
	raw := make([]byte, bestIdx)
	copy(raw, rest[:bestIdx])
	for i := range raw {
		if raw[i] == 0 {
			raw[i] = ' '
		}
	}
	query = string(raw)
	return stmtName, query
}

// extractBindNames extracts portal name and statement name from a Bind message payload.
func extractBindNames(payload []byte) (portalName, stmtName string) {
	// Format: portal_name \0 stmt_name \0 [rest...]
	portalEnd := indexOf(payload, 0)
	if portalEnd < 0 {
		return "", ""
	}
	portalName = string(payload[:portalEnd])

	rest := payload[portalEnd+1:]
	stmtEnd := indexOf(rest, 0)
	if stmtEnd < 0 {
		return portalName, ""
	}
	stmtName = string(rest[:stmtEnd])
	return portalName, stmtName
}

// extractNullTerminated extracts a null-terminated string starting at offset.
func extractNullTerminated(payload []byte, offset int) string {
	if offset >= len(payload) {
		return ""
	}
	end := indexOf(payload[offset:], 0)
	if end < 0 {
		return ""
	}
	return string(payload[offset : offset+end])
}

// drainUntilSync reads and discards client messages until a Sync ('S') message is found.
// This is needed when we block a Parse message — the client may have sent Bind/Execute/Sync
// as a batch, and we need to consume them all before sending our error response.
func drainUntilSync(client net.Conn) {
	for {
		msgType, _, err := readWireMessage(client)
		if err != nil {
			return
		}
		if msgType == 'S' { // Sync message
			return
		}
	}
}

// sendExtendedBlockedResponse sends ErrorResponse + ReadyForQuery for blocked extended queries.
// latencyMs is the decision time in milliseconds — appended to the error message as [<n>ms]
// so the client sees FaultWall's sub-ms overhead in-band. Preempts the "doesn't this add
// latency?" objection without requiring a separate dashboard view.
func sendExtendedBlockedResponse(client net.Conn, v *PolicyViolation, latencyMs float64) {
	detail := v.Reason
	if v.Table != "" {
		detail += " (table: " + v.Table + ")"
	}
	if v.Operation != "" {
		detail += " (op: " + v.Operation + ")"
	}
	if latencyMs >= 0 {
		detail += fmt.Sprintf(" [%.2fms]", latencyMs)
	}

	errResp := &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501",
		Message:  "[BLOCKED by FaultWall] " + detail,
	}
	buf, _ := errResp.Encode(nil)
	client.Write(buf)

	readyMsg := &pgproto3.ReadyForQuery{TxStatus: 'I'}
	buf, _ = readyMsg.Encode(nil)
	client.Write(buf)
}

// sendGenericBlockedResponse sends a generic error for blocked Bind/Execute on previously blocked statements.
func sendGenericBlockedResponse(client net.Conn, msg string) {
	errResp := &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501",
		Message:  "[BLOCKED by FaultWall] " + msg,
	}
	buf, _ := errResp.Encode(nil)
	client.Write(buf)

	readyMsg := &pgproto3.ReadyForQuery{TxStatus: 'I'}
	buf, _ = readyMsg.Encode(nil)
	client.Write(buf)
}

// sendStartupError sends an ErrorResponse to the client before the auth handshake.
// Used to reject connections early (e.g., auth token mismatch).
func sendStartupError(client net.Conn, msg string) {
	errResp := &pgproto3.ErrorResponse{
		Severity: "FATAL",
		Code:     "28P01", // invalid_password
		Message:  "[BLOCKED by FaultWall] " + msg,
	}
	buf, _ := errResp.Encode(nil)
	client.Write(buf)
}

// safeCheckQuery parses query once, then evaluates it against the policy with
// panic recovery (fail-open). Returns both the violation and the *ParsedQuery
// so callers can reuse the parsed result without a second CGO round-trip.
func safeCheckQuery(pe *PolicyEngine, identity *AgentIdentity, query string) (violation *PolicyViolation, parsed *ParsedQuery) {
	return safeCheckQueryWithContext(pe, identity, query, nil)
}

// safeCheckQueryWithContext is safeCheckQuery with a per-connection
// QueryContext (currently the search_path snapshot). The proxy hot path
// uses this; other callers can pass nil.
func safeCheckQueryWithContext(pe *PolicyEngine, identity *AgentIdentity, query string, ctx *QueryContext) (violation *PolicyViolation, parsed *ParsedQuery) {
	parsed = ParseQuery(query)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s[FAIL-OPEN]%s panic in policy check: %v — allowing query", colorYellow, colorReset, r)
			violation = nil
		}
	}()
	violation = pe.CheckQueryWithContext(identity, parsed, query, 0, ctx)
	return
}

// sendBlockedResponse sends an ErrorResponse + ReadyForQuery to the client.
// latencyMs is the decision time in milliseconds, appended as [<n>ms] to the
// error message so the client sees FaultWall's sub-ms decision overhead
// in-band on every blocked query. Pass a negative value to suppress.
func sendBlockedResponse(client net.Conn, v *PolicyViolation, latencyMs float64) {
	detail := v.Reason
	if v.Table != "" {
		detail += " (table: " + v.Table + ")"
	}
	if v.Operation != "" {
		detail += " (op: " + v.Operation + ")"
	}
	if latencyMs >= 0 {
		detail += fmt.Sprintf(" [%.2fms]", latencyMs)
	}

	errResp := &pgproto3.ErrorResponse{
		Severity: "ERROR",
		Code:     "42501", // insufficient_privilege
		Message:  "[BLOCKED by FaultWall] " + detail,
	}
	buf, _ := errResp.Encode(nil)
	client.Write(buf)

	readyMsg := &pgproto3.ReadyForQuery{TxStatus: 'I'}
	buf, _ = readyMsg.Encode(nil)
	client.Write(buf)
}

// ── Colorful logging ──

func querySnippet(q string) string {
	q = strings.TrimSpace(q)
	q = strings.ReplaceAll(q, "\n", " ")
	q = strings.Join(strings.Fields(q), " ") // collapse whitespace
	if len(q) > 80 {
		return q[:80] + "…"
	}
	return q
}

func logAllowed(agent, query string) {
	log.Printf("%s%s[ALLOWED]%s agent=%-20s query=%s",
		colorGreen, colorBold, colorReset, agent, querySnippet(query))
}

func logBlocked(agent, query string, v *PolicyViolation) {
	detail := v.Reason
	if v.Table != "" {
		detail += " table=" + v.Table
	}
	log.Printf("%s%s[BLOCKED]%s agent=%-20s reason=%-25s query=%s",
		colorRed, colorBold, colorReset, agent, detail, querySnippet(query))
}

func logMonitored(agent, query string, v *PolicyViolation) {
	detail := v.Reason
	if v.Table != "" {
		detail += " table=" + v.Table
	}
	log.Printf("%s%s[MONITOR]%s agent=%-20s reason=%-25s query=%s",
		colorYellow, colorBold, colorReset, agent, detail, querySnippet(query))
}

// scoreQueryShadow runs the QWM scorer in shadow mode (observe-only, never blocks).
// pq is the already-parsed query from safeCheckQuery — no second CGO call.
//
// RFC-003: infra is now the LIVE DB-state snapshot from the StateSampler (not the
// old QWMInfraState{} stub), so the world-model scorer is state-conditioned.
func scoreQueryShadow(agentLabel, query string, pq *ParsedQuery) {
	if qwmScorer == nil || pq == nil {
		return
	}
	infra := currentInfraState()
	score := qwmScorer.Score(pq, infra)
	if score > qwmFlagThreshold {
		top := qwmScorer.TopFeatures(pq, infra, 3)
		logQWMFlag(agentLabel, query, score, top)

		// RFC-003: enrich the flag with world-model predictions + the live DB
		// conditions that drove it, so the user can see what's actually wrong.
		rec := QWMFlagRecord{
			Agent:       agentLabel,
			Query:       querySnippet(query),
			Score:       score,
			TopFeatures: top,
			Operation:   pq.Operation,
			Tables:      pq.Tables,
			Utilization: infra.Utilization,
			Timestamp:   time.Now(),
		}
		var baseMs, congestion float64
		usedModel := false
		if wm, ok := qwmScorer.(*worldModelScorer); ok {
			if predicted, pBreach, used := wm.Predict(pq, infra); used {
				rec.PredictedMs = predicted
				rec.PBreach = pBreach
				usedModel = true
				if b, known := wm.base.Base(pq.Fingerprint); known {
					baseMs = b
				}
				congestion = congestionFactor(infra.Utilization, wm.artifact.Servers)
			}
		}
		rec.Conditions = &FlagConditions{
			ActiveBackends:  infra.ActiveBackends,
			BlockedBackends: infra.BlockedBackends,
			LongestActiveMs: infra.LongestActiveMs,
			CacheHitRatio:   infra.CacheHitRatio,
			TPS:             infra.TPS,
			Utilization:     infra.Utilization,
			BaseServiceMs:   baseMs,
			CongestionX:     congestion,
		}
		rec.Reason = explainQWMFlag(pq, infra, rec, usedModel)
		recordQWMFlag(rec)
	}
}

// currentInfraState returns the live DB-state snapshot for the world model, or a
func currentInfraState() QWMInfraState {
	if qwmStateSampler != nil {
		return qwmStateSampler.Snapshot()
	}
	return QWMInfraState{}
}

// currentUtilization is a hot-path-cheap read of the cached utilization.
func currentUtilization() float64 { return currentInfraState().Utilization }

// recordQueryLatency feeds a measured query latency into the world model's
// per-fingerprint base-service EWMA. No-op unless the world-model scorer is active.
func recordQueryLatency(fingerprint string, latencyMs, utilization float64) {
	if wm, ok := qwmScorer.(*worldModelScorer); ok {
		wm.Observe(fingerprint, latencyMs, utilization)
	}
}

// explainQWMFlag builds a plain-English reason for a flag so the user sees WHAT
// is wrong with their database, not just "a query was risky". It distinguishes
// the world-model (load-driven) path from the shape-based fallback path and
// calls out the specific live conditions (high load, lock contention, low cache
// hit, slow base query).
func explainQWMFlag(pq *ParsedQuery, infra QWMInfraState, rec QWMFlagRecord, usedModel bool) string {
	var parts []string

	if usedModel && rec.PredictedMs > 0 {
		// Load-driven world-model explanation: base × congestion → predicted vs SLO.
		parts = append(parts, fmt.Sprintf(
			"Under current load this query is predicted to take ~%.1fs (P(SLO breach)=%.0f%%).",
			rec.PredictedMs/1000.0, rec.PBreach*100))
		if rec.Conditions != nil && rec.Conditions.BaseServiceMs > 0 && rec.Conditions.CongestionX > 1 {
			parts = append(parts, fmt.Sprintf(
				"Its normal (unloaded) time is ~%.0fms, inflated ~%.1f× by current DB load.",
				rec.Conditions.BaseServiceMs, rec.Conditions.CongestionX))
		}
	} else {
		// Shape-based fallback: the query's shape is risky regardless of load.
		parts = append(parts, fmt.Sprintf(
			"Query shape scored risky (%s on %s).",
			nonEmpty(pq.Operation, "operation"), tablesOrUnknown(pq.Tables)))
	}

	// Live DB conditions that contributed — these are the user's actual issues.
	if infra.Utilization >= 0.8 {
		parts = append(parts, fmt.Sprintf("Database is busy: %d active backend(s), utilization %.0f%%.",
			infra.ActiveBackends, infra.Utilization*100))
	}
	if infra.BlockedBackends > 0 {
		parts = append(parts, fmt.Sprintf("⚠ %d backend(s) blocked waiting on locks — lock contention.", infra.BlockedBackends))
	}
	if infra.LongestActiveMs >= 5000 {
		parts = append(parts, fmt.Sprintf("Longest running query has been active %.1fs.", infra.LongestActiveMs/1000.0))
	}
	if infra.CacheHitRatio > 0 && infra.CacheHitRatio < 0.9 {
		parts = append(parts, fmt.Sprintf("Low cache hit ratio (%.0f%%) — heavy disk reads.", infra.CacheHitRatio*100))
	}
	if len(parts) == 1 && infra.ActiveBackends > 0 {
		parts = append(parts, fmt.Sprintf("(%d active backend(s) at flag time.)", infra.ActiveBackends))
	}
	return strings.Join(parts, " ")
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func tablesOrUnknown(t []string) string {
	if len(t) == 0 {
		return "(no table)"
	}
	return strings.Join(t, ", ")
}

// recordObservation writes a query event to the global ObservationStore.
// pq is the already-parsed query from safeCheckQuery — no second CGO call.
// Unidentified connections (identity == nil) are tagged _unidentified.
func recordObservation(agentLabel string, identity *AgentIdentity, query string, pq *ParsedQuery, blocked bool) {
	if observationStore == nil || pq == nil {
		return
	}
	agentID := "_unidentified"
	if identity != nil && identity.AgentID != "" {
		agentID = identity.AgentID
	} else if identity == nil && agentLabel != "unknown" {
		agentID = agentLabel
	}
	observationStore.Record(agentID, pq, query, blocked)
}
