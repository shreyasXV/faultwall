package main

// agent_sessions.go — live sessions of key-authenticated agents, so a
// revoked (or deleted) agent key also ends that agent's open connections,
// not just new ones. After every policy sync the proxy checks each live
// key-authenticated session: if its agent has no live key left, the session
// gets a FATAL "agent key revoked" and both sides are closed.

import (
	"log"
	"sync"

	"github.com/jackc/pgproto3/v2"
)

type agentSession struct {
	agent string
	kill  func(msg string)
}

type agentSessionRegistry struct {
	mu   sync.Mutex
	next uint64
	byID map[uint64]agentSession
}

var agentSessions = &agentSessionRegistry{byID: map[uint64]agentSession{}}

// Register adds a live session; call the returned func when it ends.
func (r *agentSessionRegistry) Register(agent string, kill func(msg string)) func() {
	r.mu.Lock()
	r.next++
	id := r.next
	r.byID[id] = agentSession{agent: agent, kill: kill}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		delete(r.byID, id)
		r.mu.Unlock()
	}
}

// Count returns the number of live sessions for agent ("" = all).
func (r *agentSessionRegistry) Count(agent string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, s := range r.byID {
		if agent == "" || s.agent == agent {
			n++
		}
	}
	return n
}

// KillRevoked ends every session whose agent has no live key in keys.
// Returns how many sessions were ended.
func (r *agentSessionRegistry) KillRevoked(keys *AgentKeyStore) int {
	r.mu.Lock()
	var victims []agentSession
	for id, s := range r.byID {
		if live, _ := keys.agentState(s.agent); live == 0 {
			victims = append(victims, s)
			delete(r.byID, id)
		}
	}
	r.mu.Unlock()
	for _, s := range victims {
		log.Printf("%s%s[REVOKED]%s ending open session of agent=%s (key revoked)", colorRed, colorBold, colorReset, s.agent)
		s.kill(keyErr("the key for agent %q was revoked. This session was ended. Create a new key on the Agents page.", s.agent))
	}
	return len(victims)
}

// fatalRevokedMessage is the ErrorResponse sent to a session being ended.
func fatalRevokedMessage(msg string) []byte {
	e := &pgproto3.ErrorResponse{Severity: "FATAL", Code: "28000", Message: "[BLOCKED by FaultWall] " + msg}
	buf, _ := e.Encode(nil)
	return buf
}
