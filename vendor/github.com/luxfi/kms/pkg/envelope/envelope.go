// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package envelope is the canonical wire shape for ZAP secret-opcode
// requests. The client builds and signs an Envelope, the server
// verifies it before authorization runs. Both sides import this
// package so the wire format has exactly one source of truth.
//
// Wire shape (JSON):
//
//	{
//	  "v": 1,                                  // version
//	  "id": {                                  // service identity
//	    "scheme": 0x42,                        // NodeIDSchemeMLDSA65
//	    "node":   "NodeID-cb58...",            // 20-byte NodeID
//	    "digest": "base64(48 bytes)",          // SHAKE256-384 FullDigest
//	    "path":   "hanzo/kms-operator",        // service path
//	    "pubkey": "base64(ML-DSA-65 pubkey)"   // for offline verify
//	  },
//	  "ts":    1717267200,                     // unix seconds
//	  "nonce": "base64(16 bytes)",             // anti-replay
//	  "op":    64,                             // wire opcode
//	  "req":   <raw JSON of the request>,      // unwrapped at dispatch
//	  "sig":   "base64(ML-DSA-65 sig)"         // over the digest below
//	}
//
// Signed digest (see luxfi/keys.envelopeDigest):
//
//	SHAKE256("lux-svc-envelope-v1" || FullDigest || canonical(env))
//
// where canonical(env) is the deterministic-JSON encoding of
// {v, ts, nonce, op, req}. Tying the FullDigest into the prehash
// prevents an attacker from swapping out the identity block while
// keeping a valid signature on the payload.

package envelope

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/luxfi/ids"
	"golang.org/x/crypto/sha3"
)

// ErrReplay is returned by VerifierWithLedger.Verify when the envelope's
// (NodeID, Nonce) tuple has already been observed within the ledger TTL.
// The kmsd maps this to statusForbid on the wire so callers cannot
// distinguish a stale-nonce reject from a clock-skew reject.
//
// The wire surface (envelope: replay-detected) is intentionally vague.
// Production audit logs record the verbose reason; the wire body does
// not echo it.
var ErrReplay = errors.New("envelope: replay-detected")

// (package envelope is intentionally decoupled from luxfi/keys — see
// VerifierFunc / Signer — so the kms zapclient can take a Signer
// without re-introducing the keys ↔ zapclient cycle.)

// Signer is the surface envelope.Build needs to produce a signature.
// luxfi/keys.ServiceIdentity satisfies it. Callers that hold a
// *keys.ServiceIdentity can pass it directly. Tests inject fakes.
//
// envelope-side note: this interface is intentionally NOT keys-tied
// so zapclient can take a Signer without importing keys (which would
// re-introduce the keys ↔ zapclient cycle).
type Signer interface {
	// Sign returns the ML-DSA-65 signature over the SHAKE256 digest
	// the verifier reconstructs. The implementation MUST bind the
	// caller's FullDigest into the prehash (luxfi/keys does this in
	// ServiceIdentity.Sign).
	Sign(envelope []byte) ([]byte, error)
}

// IdentityHeader is the static identity block a signer publishes on
// every envelope. Carried as a struct so callers can hand any
// identity-bearer into BuildFromHeader without coupling to keys.
type IdentityHeader struct {
	NodeID      ids.NodeID
	FullDigest  ids.FullDigest
	ServicePath string
	PublicKey   []byte
}

// Version is the only supported envelope version. Bumping invalidates
// every prior in-flight signature; do not bump without a coordinated
// rollout.
const Version = 1

// MaxClockSkew is the wall-clock window the verifier accepts. Outside
// this window the envelope is rejected with reason "envelope-stale".
const MaxClockSkew = 5 * time.Minute

// Envelope is the canonical signed wrapper.
type Envelope struct {
	Version int             `json:"v"`
	ID      Identity        `json:"id"`
	Ts      int64           `json:"ts"`
	Nonce   string          `json:"nonce"`
	Op      uint16          `json:"op"`
	Req     json.RawMessage `json:"req"`
	Sig     []byte          `json:"sig"`
}

// Identity is the identity block carried inside an Envelope.
type Identity struct {
	Scheme uint8  `json:"scheme"`
	Node   string `json:"node"`
	Digest []byte `json:"digest"`
	Path   string `json:"path"`
	PubKey []byte `json:"pubkey"`
}

// VerifiedIdentity is the result of a successful envelope verification.
// The caller (server or audit-log writer) gets the typed NodeID + the
// full 48-byte commitment + the path the caller declared.
type VerifiedIdentity struct {
	NodeID      ids.NodeID
	FullDigest  ids.FullDigest
	ServicePath string
}

// String returns "path@NodeID" for diagnostics. Not a wire form.
func (v VerifiedIdentity) String() string {
	if v.ServicePath != "" {
		return fmt.Sprintf("%s@%s", v.ServicePath, v.NodeID.String())
	}
	return v.NodeID.String()
}

// Parse parses an Envelope from raw JSON bytes. Returns a structured
// error on shape problems so the wire layer can map them to
// statusForbid with a reason field.
func Parse(raw []byte) (*Envelope, error) {
	if len(raw) == 0 {
		return nil, errors.New("envelope: empty payload")
	}
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return nil, fmt.Errorf("envelope: malformed JSON: %w", err)
	}
	if env.Version != Version {
		return nil, fmt.Errorf("envelope: unsupported version %d", env.Version)
	}
	if env.ID.Scheme != uint8(ids.NodeIDSchemeMLDSA65) {
		return nil, fmt.Errorf("envelope: unsupported identity scheme 0x%02X", env.ID.Scheme)
	}
	if strings.TrimSpace(env.ID.Path) == "" {
		return nil, errors.New("envelope: identity path is required")
	}
	if len(env.ID.PubKey) == 0 {
		return nil, errors.New("envelope: identity pubkey is required")
	}
	if len(env.ID.Digest) != ids.FullDigestLen {
		return nil, fmt.Errorf("envelope: identity digest length=%d, want %d",
			len(env.ID.Digest), ids.FullDigestLen)
	}
	if len(env.Sig) == 0 {
		return nil, errors.New("envelope: signature is required")
	}
	if strings.TrimSpace(env.Nonce) == "" {
		return nil, errors.New("envelope: nonce is required")
	}
	return &env, nil
}

// VerifierFunc is the surface envelope.Verify needs to validate an
// ML-DSA-65 signature. luxfi/keys provides the canonical impl
// (keys.VerifyServiceEnvelope); envelope keeps the dependency
// inverted so it doesn't import keys.
//
// The Verifier MUST bind fullDigest into the signed prehash (the
// envelope canonical bytes alone are NOT enough — see
// luxfi/keys.VerifyServiceEnvelope).
type VerifierFunc func(pubKey []byte, fullDigest ids.FullDigest, signedBytes, sig []byte) error

// EnvelopeDomain is the customisation prefix mixed into every
// envelope signature. Pinned at v1; bumping invalidates every prior
// in-flight signature.
const EnvelopeDomain = "lux-svc-envelope-v1"

// Verify verifies an envelope's freshness and internal consistency,
// then asks the supplied VerifierFunc to check the ML-DSA-65
// signature. Returns the verified identity on success.
//
//   - Freshness: |now − env.Ts| ≤ MaxClockSkew.
//   - Identity binding: env.ID.Node MUST be the prefix of env.ID.Digest.
//   - Signature: delegated to the verifier (which knows the
//     keys.envelopeDigest construction).
//
// The wall-clock skew check is the only time-dependent step; tests
// pin `now`.
func Verify(env *Envelope, now time.Time, verifier VerifierFunc) (VerifiedIdentity, error) {
	if env == nil {
		return VerifiedIdentity{}, errors.New("envelope: nil")
	}
	if verifier == nil {
		return VerifiedIdentity{}, errors.New("envelope: verifier is nil")
	}

	if d := now.Unix() - env.Ts; d > int64(MaxClockSkew.Seconds()) || d < -int64(MaxClockSkew.Seconds()) {
		return VerifiedIdentity{}, fmt.Errorf("envelope: stale (skew=%ds)", d)
	}

	var full ids.FullDigest
	copy(full[:], env.ID.Digest)

	signed, err := canonicalBytes(env)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("envelope: canonical: %w", err)
	}
	if err := verifier(env.ID.PubKey, full, signed, env.Sig); err != nil {
		return VerifiedIdentity{}, fmt.Errorf("envelope: %w", err)
	}

	var nodeID ids.NodeID
	copy(nodeID[:], full[:ids.NodeIDLen])
	parsedNode, err := ids.NodeIDFromString(env.ID.Node)
	if err != nil {
		return VerifiedIdentity{}, fmt.Errorf("envelope: parse Node: %w", err)
	}
	if parsedNode != nodeID {
		return VerifiedIdentity{}, errors.New("envelope: Node does not match digest prefix")
	}

	return VerifiedIdentity{
		NodeID:      nodeID,
		FullDigest:  full,
		ServicePath: env.ID.Path,
	}, nil
}

// VerifierWithLedger is the canonical production verifier: wall-clock
// freshness + ML-DSA-65 signature + replay defence (nonce ledger).
//
// The free Verify() function is the back-compat no-ledger entry; the
// kmsd Server wraps a VerifierWithLedger and uses it for every wire
// request. Tests that don't care about replay defence stay on Verify().
//
// Construction:
//
//	v, err := envelope.NewVerifierWithLedger(envelope.VerifierWithLedgerConfig{
//	    Verifier: keys.VerifyServiceEnvelope,
//	    Ledger:   envelope.NewMemoryNonceLedger(envelope.MemoryNonceLedgerConfig{}),
//	})
//
// On every request:
//
//	identity, err := v.Verify(ctx, env, time.Now())
//	// err == envelope.ErrReplay → captured replay; statusForbid on wire
type VerifierWithLedger struct {
	verify VerifierFunc
	ledger NonceLedger
}

// VerifierWithLedgerConfig wires a VerifierWithLedger.
type VerifierWithLedgerConfig struct {
	// Verifier is the ML-DSA-65 signature verifier. Production passes
	// keys.VerifyServiceEnvelope. Required.
	Verifier VerifierFunc

	// Ledger records (NodeID, Nonce) tuples and rejects duplicates.
	// Required for production wire path; the kmsd construct boots fail-
	// closed if absent.
	Ledger NonceLedger
}

// NewVerifierWithLedger wires a VerifierWithLedger. Returns an error if
// either field is nil — a verifier without a ledger silently re-opens
// the replay window, and a ledger without a verifier accepts unsigned
// frames. Both modes are wire-reachable security holes; we refuse to
// construct one.
func NewVerifierWithLedger(cfg VerifierWithLedgerConfig) (*VerifierWithLedger, error) {
	if cfg.Verifier == nil {
		return nil, errors.New("envelope: signature verifier is required")
	}
	if cfg.Ledger == nil {
		return nil, errors.New("envelope: nonce ledger is required")
	}
	return &VerifierWithLedger{
		verify: cfg.Verifier,
		ledger: cfg.Ledger,
	}, nil
}

// Verify runs the full production verification pipeline:
//
//  1. Wall-clock freshness check (|now - env.Ts| ≤ MaxClockSkew).
//  2. ML-DSA-65 signature verification.
//  3. NodeID prefix check (env.ID.Node ⊑ env.ID.Digest).
//  4. Nonce ledger insert. Duplicate → ErrReplay.
//
// The ledger insert runs AFTER signature verification. An unsigned or
// forged envelope is rejected at step 2 and therefore cannot pump the
// ledger; only validly-signed envelopes consume nonce-space.
func (v *VerifierWithLedger) Verify(ctx context.Context, env *Envelope, now time.Time) (VerifiedIdentity, error) {
	ident, err := Verify(env, now, v.verify)
	if err != nil {
		return VerifiedIdentity{}, err
	}
	seen, err := v.ledger.SeenOrInsert(ctx, ident.NodeID, env.Nonce, now)
	if err != nil {
		// Transport-layer ledger failure (e.g. disk-backed impl unable
		// to fsync). Fail closed — we cannot prove this isn't a replay.
		return VerifiedIdentity{}, fmt.Errorf("envelope: ledger: %w", err)
	}
	if seen {
		return VerifiedIdentity{}, ErrReplay
	}
	return ident, nil
}

// Digest returns the canonical SHAKE256 prehash a signer signs (and a
// verifier reconstructs). Exported so callers can hand-roll a Signer
// without re-deriving the digest. SP 800-185 left_encode framing on
// every field so a verifier cannot be tricked by a payload whose
// first bytes spell another field's prefix.
func Digest(fullDigest ids.FullDigest, signedBytes []byte) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write(leftEncode(uint64(len(EnvelopeDomain)) * 8))
	_, _ = h.Write([]byte(EnvelopeDomain))
	_, _ = h.Write(leftEncode(uint64(ids.FullDigestLen) * 8))
	_, _ = h.Write(fullDigest[:])
	_, _ = h.Write(leftEncode(uint64(len(signedBytes)) * 8))
	_, _ = h.Write(signedBytes)
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// leftEncode is the SP 800-185 §2.3.1 left_encode operation.
func leftEncode(x uint64) []byte {
	if x == 0 {
		return []byte{0x01, 0x00}
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], x)
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	out := make([]byte, 0, 9-i)
	out = append(out, byte(8-i))
	out = append(out, buf[i:]...)
	return out
}

// canonicalBytes returns the deterministic bytes the signer produced
// when computing the envelope signature. We exclude the Sig field and
// re-encode the rest via encoding/json with stable field ordering.
func canonicalBytes(env *Envelope) ([]byte, error) {
	c := struct {
		Version int             `json:"v"`
		ID      Identity        `json:"id"`
		Ts      int64           `json:"ts"`
		Nonce   string          `json:"nonce"`
		Op      uint16          `json:"op"`
		Req     json.RawMessage `json:"req"`
	}{
		Version: env.Version,
		ID:      env.ID,
		Ts:      env.Ts,
		Nonce:   env.Nonce,
		Op:      env.Op,
		Req:     env.Req,
	}
	return json.Marshal(c)
}

// Build is the canonical constructor: the caller supplies the
// public identity header and a Signer separately. Used by clients
// that hold the identity in any shape.
//
//   - hdr:    the public identity block stamped into env.ID.
//   - signer: signs the SHAKE256 prehash returned by Digest().
//   - op:     wire opcode (must match the server's op dispatch).
//   - req:    inner request JSON (already marshalled).
//   - nonce:  caller-fresh nonce (typically 16 random bytes, base64-
//     encoded). The verifier ledgers (NodeID, Nonce) for the duration
//     of MaxClockSkew + 1m and rejects duplicates — callers MUST use a
//     fresh nonce per envelope. Reusing a nonce within the window
//     produces ErrReplay at the verifier.
//   - now:    wall-clock at signing time.
func Build(hdr IdentityHeader, signer Signer, op uint16, req json.RawMessage, nonce string, now time.Time) (*Envelope, error) {
	if signer == nil {
		return nil, errors.New("envelope: signer is nil")
	}
	if strings.TrimSpace(nonce) == "" {
		return nil, errors.New("envelope: nonce is required")
	}
	if len(hdr.PublicKey) == 0 {
		return nil, errors.New("envelope: identity header is empty")
	}
	env := &Envelope{
		Version: Version,
		ID: Identity{
			Scheme: uint8(ids.NodeIDSchemeMLDSA65),
			Node:   hdr.NodeID.String(),
			Digest: hdr.FullDigest[:],
			Path:   hdr.ServicePath,
			PubKey: hdr.PublicKey,
		},
		Ts:    now.Unix(),
		Nonce: nonce,
		Op:    op,
		Req:   req,
	}
	signed, err := canonicalBytes(env)
	if err != nil {
		return nil, fmt.Errorf("envelope: canonical: %w", err)
	}
	sig, err := signer.Sign(signed)
	if err != nil {
		return nil, fmt.Errorf("envelope: sign: %w", err)
	}
	env.Sig = sig
	return env, nil
}
