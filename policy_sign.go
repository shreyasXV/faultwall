package main

// policy_sign.go — signed policy documents (POLICY-WIRE-CONTRACT.md,
// "Proxy acceptance" + Rev B1/B3).
//
// GET /v1/policy carries signed_policy {payload, sig, key_id}: payload is
// base64url of the raw canonical JSON of a PolicyDoc and sig is Ed25519 over
// exactly those bytes. signed_freshness has the same envelope around
// {tenant_id, installation_id, policy_version, nonce, issued_at}.
//
// The proxy verifies with a pinned key: FW_POLICY_PUBKEY (required in
// enforce mode), or in watch mode a key pinned on first verified fetch
// (trust on first use, 0600 file next to the policy cache).

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// defaultOfflineWindowSeconds is the contract default (72h).
const defaultOfflineWindowSeconds = 259200

// signedBlob is the {payload, sig, key_id} envelope.
type signedBlob struct {
	Payload string `json:"payload"`
	Sig     string `json:"sig"`
	KeyID   string `json:"key_id"`
}

// PolicyGrant is a narrow, possibly time-limited allowance.
type PolicyGrant struct {
	ID         string   `json:"id"`
	Agent      string   `json:"agent"`
	Operations []string `json:"operations"`
	Tables     []string `json:"tables"`
	Columns    []string `json:"columns,omitempty"`
	ExpiresAt  string   `json:"expires_at,omitempty"` // RFC3339; "" = permanent
}

// SensitiveMark marks a table (no columns = whole table) or some columns.
type SensitiveMark struct {
	Table   string   `json:"table"`
	Columns []string `json:"columns,omitempty"`
}

// PolicyDoc is the signed document.
type PolicyDoc struct {
	Schema               int             `json:"schema"`
	TenantID             string          `json:"tenant_id"`
	DatabaseID           string          `json:"database_id"`
	Environment          string          `json:"environment"`
	Version              int64           `json:"version"`
	IssuedAt             string          `json:"issued_at"`
	OfflineWindowSeconds int64           `json:"offline_window_seconds"`
	DenyAllOnExpiry      bool            `json:"deny_all_on_expiry"`
	AgentsYAML           string          `json:"agents_yaml"`
	AgentKeysSHA256      string          `json:"agent_keys_sha256"`
	Grants               []PolicyGrant   `json:"grants"`
	Sensitive            []SensitiveMark `json:"sensitive"`
	FrozenAgents         []string        `json:"frozen_agents"`
}

func (d *PolicyDoc) window() time.Duration {
	s := d.OfflineWindowSeconds
	if s <= 0 {
		s = defaultOfflineWindowSeconds
	}
	return time.Duration(s) * time.Second
}

// FreshnessToken is the signed_freshness payload.
type FreshnessToken struct {
	TenantID       string `json:"tenant_id"`
	InstallationID string `json:"installation_id"`
	PolicyVersion  int64  `json:"policy_version"`
	Nonce          string `json:"nonce"`
	IssuedAt       string `json:"issued_at"`
}

// policyKeyID is the first 16 hex chars of sha256(raw 32-byte public key).
func policyKeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])[:16]
}

// parsePolicyPubKey accepts the public key as base64url / base64 (raw 32
// bytes), 64 hex chars, or a PEM/DER SubjectPublicKeyInfo. An optional
// "ed25519:" prefix is ignored.
func parsePolicyPubKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "ed25519:")
	if s == "" {
		return nil, errors.New("empty public key")
	}
	if strings.HasPrefix(s, "-----BEGIN") {
		blk, _ := pem.Decode([]byte(s))
		if blk == nil {
			return nil, errors.New("bad PEM public key")
		}
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, err
		}
		pk, ok := k.(ed25519.PublicKey)
		if !ok {
			return nil, errors.New("PEM key is not Ed25519")
		}
		return pk, nil
	}
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return ed25519.PublicKey(b), nil
		}
	}
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		b, err := enc.DecodeString(s)
		if err != nil {
			continue
		}
		if len(b) == ed25519.PublicKeySize {
			return ed25519.PublicKey(b), nil
		}
		if k, err := x509.ParsePKIXPublicKey(b); err == nil {
			if pk, ok := k.(ed25519.PublicKey); ok {
				return pk, nil
			}
		}
	}
	return nil, errors.New("public key must be 32 raw Ed25519 bytes (base64url/base64/hex) or a PEM Ed25519 key")
}

func b64Decode(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, enc := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not base64url")
}

// verifyBlob checks the envelope against pub and returns the raw payload.
func verifyBlob(b *signedBlob, pub ed25519.PublicKey) ([]byte, error) {
	if b == nil {
		return nil, errors.New("missing signature")
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("no pinned policy key")
	}
	if b.KeyID != "" && b.KeyID != policyKeyID(pub) {
		return nil, fmt.Errorf("signed with key %s, pinned key is %s", b.KeyID, policyKeyID(pub))
	}
	payload, err := b64Decode(b.Payload)
	if err != nil || len(payload) == 0 {
		return nil, errors.New("bad payload encoding")
	}
	sig, err := b64Decode(b.Sig)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, errors.New("bad signature encoding")
	}
	if !ed25519.Verify(pub, payload, sig) {
		return nil, errors.New("signature does not verify")
	}
	return payload, nil
}

// signBlob is the control plane's side; used by tests and the E2E shim.
func signBlob(priv ed25519.PrivateKey, payload []byte) *signedBlob {
	return &signedBlob{
		Payload: base64.RawURLEncoding.EncodeToString(payload),
		Sig:     base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, payload)),
		KeyID:   policyKeyID(priv.Public().(ed25519.PublicKey)),
	}
}

func newPollNonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// ── key pin ──

func policyPinPath(cachePath string) string {
	if p := os.Getenv("FW_POLICY_PIN_FILE"); p != "" {
		return p
	}
	if cachePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(cachePath), "policy-pubkey.pin")
}

func readPinnedKey(path string) (ed25519.PublicKey, error) {
	if path == "" {
		return nil, os.ErrNotExist
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parsePolicyPubKey(string(b))
}

func writePinnedKey(path string, pub ed25519.PublicKey) error {
	if path == "" {
		return errors.New("no pin path")
	}
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(base64.RawURLEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	return os.Rename(tmp, path)
}

// writeFileAtomic writes b to path via tmp + rename, mode 0600.
func writeFileAtomic(path string, b []byte) error {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
