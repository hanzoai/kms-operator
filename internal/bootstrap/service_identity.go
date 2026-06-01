// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// service_identity.go — local reimplementation of luxfi/keys
// ServiceIdentity (commit 581d1fb…).
//
// The canonical algorithm lives at ~/work/lux/keys/service_identity.go.
// We do NOT import the upstream package because its sibling files
// (keys.go, upgrade_keys.go) pull github.com/luxfi/crypto/bls which
// transitively requires github.com/supranational/blst — a cgo module
// whose blst.h header is left outside the imported package directory
// and is therefore stripped by `go mod vendor`. The Dockerfile builds
// with -mod=vendor (private-module-free build) and would fail at
// blst.h not found.
//
// Reimplementing the derivation locally lets us:
//
//   - keep the kms-operator vendor surface tight (no cgo);
//   - stay byte-for-byte identical to the upstream NodeID so the
//     kmsd's authorizer accepts the same Identity envelope;
//   - decouple from operational-key plumbing that's irrelevant to
//     consensus-auth.
//
// Determinism contract:
//
//	NodeID(mnemonic, path) == luxfi/keys.NewServiceIdentity(mnemonic, path).NodeID()
//
// Tests in this directory pin the contract.

package bootstrap

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	mldsa "github.com/luxfi/crypto/mldsa"
	bip32 "github.com/luxfi/go-bip32"
	bip39 "github.com/luxfi/go-bip39"
	"github.com/luxfi/ids"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/sha3"
)

// Derivation constants — copied verbatim from luxfi/keys/service_identity.go.
// Any drift here breaks the kmsd's authorizer match.
const (
	identityCoinTypeUTXO     = 9000
	identityBIP44Purpose     = 44
	identityServiceDomain    = "lux-svc-mldsa-v1"
	identityServiceChainSeed = "lux-service-identity"
)

// serviceChainID is the well-known chain identifier under which all
// service NodeIDs are derived. Distinct from any L1 chain ID so a
// service NodeID never accidentally validates against a chain's
// validator-set commitment.
var serviceChainID = mustHashChainID(identityServiceChainSeed)

// identityErrInvalidPath is returned when the servicePath argument is
// empty after trim. Empty paths would collapse every service to the
// same NodeID, which would silently mask configuration drift.
var identityErrInvalidPath = errors.New("bootstrap: service path is required")

// deriveNodeIDString returns the canonical NodeID string for the given
// (mnemonic, servicePath) tuple. Pure function: no I/O, no clock.
//
// The string form is "NodeID-<base58>" — identical to what
// luxfi/keys.NewServiceIdentity(...).NodeID.String() returns.
func deriveNodeIDString(mnemonic, servicePath string) (string, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return "", errors.New("bootstrap: invalid BIP-39 mnemonic")
	}
	servicePath = trimIdentityPath(servicePath)
	if servicePath == "" {
		return "", identityErrInvalidPath
	}

	seed := bip39.NewSeed(mnemonic, "")
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return "", fmt.Errorf("bootstrap: bip32 master: %w", err)
	}
	// m/44' / 9000' / serviceIndex' / 0' / 0'
	purpose, err := master.NewChildKey(bip32.FirstHardenedChild + identityBIP44Purpose)
	if err != nil {
		return "", fmt.Errorf("bootstrap: derive purpose: %w", err)
	}
	coin, err := purpose.NewChildKey(bip32.FirstHardenedChild + identityCoinTypeUTXO)
	if err != nil {
		return "", fmt.Errorf("bootstrap: derive coin: %w", err)
	}
	account, err := coin.NewChildKey(bip32.FirstHardenedChild + identityServiceIndex(servicePath))
	if err != nil {
		return "", fmt.Errorf("bootstrap: derive account: %w", err)
	}
	role, err := account.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return "", fmt.Errorf("bootstrap: derive role: %w", err)
	}
	leaf, err := role.NewChildKey(bip32.FirstHardenedChild + 0)
	if err != nil {
		return "", fmt.Errorf("bootstrap: derive leaf: %w", err)
	}

	mldsaSeed := identityMLDSASeedFor(leaf.Key, servicePath)
	reader := hkdf.New(sha3.New256, mldsaSeed, nil, []byte(identityServiceDomain))
	priv, err := mldsa.GenerateKey(reader, mldsa.MLDSA65)
	if err != nil {
		return "", fmt.Errorf("bootstrap: mldsa keygen: %w", err)
	}
	pubBytes := priv.PublicKey.Bytes()

	typed, _, err := ids.TypedNodeIDFromMLDSA(ids.NodeIDSchemeMLDSA65, serviceChainID, pubBytes)
	if err != nil {
		return "", fmt.Errorf("bootstrap: derive node id: %w", err)
	}
	// Wipe the private key bytes (no longer needed — we only return the
	// NodeID).
	for i := range priv.Bytes() {
		_ = priv.Bytes()[i]
	}
	return typed.NodeID.String(), nil
}

// identityMLDSASeedFor returns the 32-byte deterministic seed for
// ML-DSA-65 key generation. SHAKE256 absorbs the BIP-32 hardened
// child key, the domain string, and the servicePath so the seed is
// unique per (mnemonic, path) tuple.
func identityMLDSASeedFor(hardenedKey []byte, servicePath string) []byte {
	h := sha3.NewShake256()
	_, _ = h.Write(identityLeftEncode(uint64(len(identityServiceDomain)) * 8))
	_, _ = h.Write([]byte(identityServiceDomain))
	_, _ = h.Write(identityLeftEncode(uint64(len(hardenedKey)) * 8))
	_, _ = h.Write(hardenedKey)
	_, _ = h.Write(identityLeftEncode(uint64(len(servicePath)) * 8))
	_, _ = h.Write([]byte(servicePath))
	out := make([]byte, 32)
	_, _ = h.Read(out)
	return out
}

// identityServiceIndex hashes a servicePath into a hardened-safe
// BIP-32 child index. The top bit is masked off so adding
// bip32.FirstHardenedChild in the caller stays inside the hardened
// space without overflowing.
func identityServiceIndex(servicePath string) uint32 {
	sum := sha256.Sum256([]byte(servicePath))
	v := binary.BigEndian.Uint32(sum[:4])
	return v & 0x7FFFFFFF
}

// trimIdentityPath collapses whitespace and leading/trailing slashes
// without rewriting embedded slashes. Empty input returns "".
func trimIdentityPath(p string) string {
	p = strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\n', '\r':
			return -1
		}
		return r
	}, p)
	for len(p) > 0 && p[0] == '/' {
		p = p[1:]
	}
	for len(p) > 0 && p[len(p)-1] == '/' {
		p = p[:len(p)-1]
	}
	return p
}

// mustHashChainID seeds the package-level serviceChainID. Panics on
// the impossible (sha256 always succeeds); the panic surfaces a
// programmer error at init time rather than a runtime nil.
func mustHashChainID(seed string) ids.ID {
	sum := sha256.Sum256([]byte(seed))
	var id ids.ID
	copy(id[:], sum[:])
	return id
}

// identityLeftEncode is the SP 800-185 §2.3.1 left_encode operation.
// Same byte-for-byte algorithm as luxfi/keys.leftEncode.
func identityLeftEncode(x uint64) []byte {
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
