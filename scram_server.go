package main

// scram_server.go — server side of SCRAM-SHA-256 (RFC 5802 / RFC 7677) for
// agent keys, the same exchange Postgres runs for password_encryption =
// scram-sha-256. The control plane stores only a verifier per agent key
// (salt, iterations, StoredKey, ServerKey) and syncs it here, so the proxy
// can check that the client knows the key without the key ever crossing the
// wire and without the proxy ever holding it.
//
// Channel binding (SCRAM-SHA-256-PLUS) is not offered.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ScramVerifier is the at-rest SCRAM-SHA-256 form of an agent key (base64 std).
type ScramVerifier struct {
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	StoredKey  string `json:"stored_key"`
	ServerKey  string `json:"server_key"`
}

func (v *ScramVerifier) valid() bool {
	return v != nil && v.Salt != "" && v.Iterations > 0 && v.StoredKey != "" && v.ServerKey != ""
}

// errScramBadProof means the client's proof did not match: wrong key.
var errScramBadProof = errors.New("scram: wrong key")

const (
	authSASL         = 10
	authSASLContinue = 11
	authSASLFinal    = 12
)

func writeAuth(w io.Writer, code uint32, data []byte) error {
	b := make([]byte, 4, 4+len(data))
	binary.BigEndian.PutUint32(b, code)
	return writeWireMessage(w, 'R', append(b, data...))
}

func scramHMAC(key, msg []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	return m.Sum(nil)
}

// scramAttrs parses "a=1,b=2" (values may contain '=').
func scramAttrs(s string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(s, ",") {
		if len(part) >= 2 && part[1] == '=' {
			out[part[:1]] = part[2:]
		}
	}
	return out
}

// scramServerAuth runs the SCRAM-SHA-256 exchange with the client against v.
// r reads client messages (must be the same buffered reader the proxy uses
// for the connection); w writes to the client. On success the caller sends
// (or relays) AuthenticationOk. Returns errScramBadProof for a wrong key.
func scramServerAuth(r io.Reader, w io.Writer, v *ScramVerifier) error {
	if !v.valid() {
		return fmt.Errorf("scram: agent has no SCRAM verifier")
	}
	salt, err1 := base64.StdEncoding.DecodeString(v.Salt)
	storedKey, err2 := base64.StdEncoding.DecodeString(v.StoredKey)
	serverKey, err3 := base64.StdEncoding.DecodeString(v.ServerKey)
	if err1 != nil || err2 != nil || err3 != nil || len(salt) == 0 || len(storedKey) != sha256.Size || len(serverKey) != sha256.Size {
		return fmt.Errorf("scram: malformed verifier")
	}

	// 1. AuthenticationSASL: mechanism list.
	if err := writeAuth(w, authSASL, []byte("SCRAM-SHA-256\x00\x00")); err != nil {
		return err
	}

	// 2. SASLInitialResponse: mechanism\0 int32 len, client-first-message.
	t, payload, err := readWireMessage(r)
	if err != nil {
		return fmt.Errorf("scram: reading client-first: %w", err)
	}
	if t != 'p' {
		return fmt.Errorf("scram: expected SASLInitialResponse, got %q", t)
	}
	nul := indexOf(payload, 0)
	if nul < 0 || len(payload) < nul+5 {
		return fmt.Errorf("scram: malformed SASLInitialResponse")
	}
	if mech := string(payload[:nul]); mech != "SCRAM-SHA-256" {
		return fmt.Errorf("scram: unsupported mechanism %q", mech)
	}
	n := int(int32(binary.BigEndian.Uint32(payload[nul+1 : nul+5])))
	clientFirst := payload[nul+5:]
	if n < 0 || n > len(clientFirst) {
		return fmt.Errorf("scram: bad client-first length")
	}
	cf := string(clientFirst[:n])

	// gs2 header: "n,," (no binding) or "y,," (client could bind; we offer none).
	// "p=..." asks for binding we never advertised: refuse.
	var gs2 string
	switch {
	case strings.HasPrefix(cf, "n,,"), strings.HasPrefix(cf, "y,,"):
		gs2 = cf[:3]
	default:
		return fmt.Errorf("scram: unsupported channel binding in %q", strings.SplitN(cf, ",", 2)[0])
	}
	clientFirstBare := cf[3:]
	clientNonce := scramAttrs(clientFirstBare)["r"]
	if clientNonce == "" {
		return fmt.Errorf("scram: client nonce missing")
	}

	// 3. AuthenticationSASLContinue: server-first-message.
	rnd := make([]byte, 18)
	if _, err := rand.Read(rnd); err != nil {
		return err
	}
	nonce := clientNonce + base64.StdEncoding.EncodeToString(rnd)
	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", nonce, v.Salt, v.Iterations)
	if err := writeAuth(w, authSASLContinue, []byte(serverFirst)); err != nil {
		return err
	}

	// 4. SASLResponse: client-final-message.
	t, payload, err = readWireMessage(r)
	if err != nil {
		return fmt.Errorf("scram: reading client-final: %w", err)
	}
	if t != 'p' {
		return fmt.Errorf("scram: expected SASLResponse, got %q", t)
	}
	cfin := string(payload)
	pIdx := strings.LastIndex(cfin, ",p=")
	if pIdx < 0 {
		return fmt.Errorf("scram: client proof missing")
	}
	withoutProof := cfin[:pIdx]
	attrs := scramAttrs(withoutProof)
	if attrs["c"] != base64.StdEncoding.EncodeToString([]byte(gs2)) {
		return fmt.Errorf("scram: channel binding mismatch")
	}
	if subtle.ConstantTimeCompare([]byte(attrs["r"]), []byte(nonce)) != 1 {
		return fmt.Errorf("scram: nonce mismatch")
	}
	proof, err := base64.StdEncoding.DecodeString(cfin[pIdx+3:])
	if err != nil || len(proof) != sha256.Size {
		return errScramBadProof
	}

	authMessage := []byte(clientFirstBare + "," + serverFirst + "," + withoutProof)
	clientSig := scramHMAC(storedKey, authMessage)
	clientKey := make([]byte, sha256.Size)
	for i := range clientKey {
		clientKey[i] = proof[i] ^ clientSig[i]
	}
	got := sha256.Sum256(clientKey)
	if subtle.ConstantTimeCompare(got[:], storedKey) != 1 {
		return errScramBadProof
	}

	// 5. AuthenticationSASLFinal: server signature (client verifies us).
	serverSig := scramHMAC(serverKey, authMessage)
	return writeAuth(w, authSASLFinal, []byte("v="+base64.StdEncoding.EncodeToString(serverSig)))
}
