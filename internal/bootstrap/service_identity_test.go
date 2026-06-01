// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// service_identity_test.go — byte-for-byte determinism contract with
// luxfi/keys.NewServiceIdentity.
//
// The test vectors below were captured from the canonical impl at
// ~/work/lux/keys/service_identity.go (commit 5c8083a, v1.0.10) using
// the BIP-39 reference mnemonic "abandon abandon abandon abandon abandon
// abandon abandon abandon abandon abandon abandon about".
//
// If this test fails, the kms-operator and the kmsd will derive
// different NodeIDs from the same mnemonic, which silently revokes
// every service's KMS access at deploy time. Treat any breakage here
// as an emergency: regenerate the vectors from upstream, audit the
// derivation diff (typically a constant renamed in luxfi/keys), and
// only then bump the vectors here.

package bootstrap

import "testing"

const canonicalReferenceMnemonic = "abandon abandon abandon abandon abandon abandon " +
	"abandon abandon abandon abandon abandon about"

// canonicalVectors pins the NodeID string each (mnemonic, path) tuple
// MUST derive to. Captured via:
//
//	cd ~/work/lux/keys && go run /tmp/derive_canonical.go
func canonicalVectors() map[string]string {
	return map[string]string{
		"hanzo/kms-operator": "NodeID-6MHbbHVyQULbQiY45LKq4FSe4eDAJXYFt",
		"hanzo/commerce":     "NodeID-JKgePFRhXAu5jcBuUpWZboahUqdgMD35V",
		"hanzo/paas":         "NodeID-FwEcuXgS5fS1VTdSGaAmE9i8kM7UUL7oT",
		"lux/kms-operator":   "NodeID-6HnEhTtDAah1D8Vx7yF5wobCRVEg7junj",
		"hanzo/hanzo-base":   "NodeID-GpEAPpXCkDkJTuZSrTyVm9mjcRV9JAgcx",
	}
}

// TestDeriveNodeIDString_MatchesCanonical pins each canonical vector.
// Failure means the local derivation has diverged from luxfi/keys and
// would silently break consensus-native auth.
func TestDeriveNodeIDString_MatchesCanonical(t *testing.T) {
	for path, want := range canonicalVectors() {
		got, err := deriveNodeIDString(canonicalReferenceMnemonic, path)
		if err != nil {
			t.Errorf("derive(%q): %v", path, err)
			continue
		}
		if got != want {
			t.Errorf("path %q: got %q, want %q (canonical drift)", path, got, want)
		}
	}
}

// TestDeriveNodeIDString_DistinctPaths sanity-checks that different
// paths produce different NodeIDs. A collision here would mean the
// derivation collapsed two services into one identity.
func TestDeriveNodeIDString_DistinctPaths(t *testing.T) {
	seen := make(map[string]string)
	for _, path := range []string{
		"hanzo/kms-operator", "hanzo/commerce", "hanzo/paas",
		"lux/kms-operator", "hanzo/hanzo-base", "zoo/registry",
	} {
		id, err := deriveNodeIDString(canonicalReferenceMnemonic, path)
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("NodeID collision: %q and %q both → %s", prev, path, id)
		}
		seen[id] = path
	}
}

// TestDeriveNodeIDString_PathTrimming verifies that surrounding slashes
// and whitespace do not change the derivation, matching luxfi/keys'
// trimServicePath semantics.
func TestDeriveNodeIDString_PathTrimming(t *testing.T) {
	base, err := deriveNodeIDString(canonicalReferenceMnemonic, "hanzo/kms-operator")
	if err != nil {
		t.Fatal(err)
	}
	for _, dirty := range []string{
		"/hanzo/kms-operator/",
		" hanzo/kms-operator ",
		"hanzo/kms-operator\n",
		"/hanzo/kms-operator",
	} {
		got, err := deriveNodeIDString(canonicalReferenceMnemonic, dirty)
		if err != nil {
			t.Errorf("derive(%q): %v", dirty, err)
			continue
		}
		if got != base {
			t.Errorf("path trimming diverged: %q → %s, base → %s", dirty, got, base)
		}
	}
}

// TestDeriveNodeIDString_BadInput surfaces malformed mnemonic + empty
// path as errors rather than silent collapse.
func TestDeriveNodeIDString_BadInput(t *testing.T) {
	if _, err := deriveNodeIDString("", "hanzo/foo"); err == nil {
		t.Error("empty mnemonic should error")
	}
	if _, err := deriveNodeIDString(canonicalReferenceMnemonic, ""); err == nil {
		t.Error("empty path should error")
	}
	if _, err := deriveNodeIDString(canonicalReferenceMnemonic, "   "); err == nil {
		t.Error("whitespace-only path should error")
	}
	if _, err := deriveNodeIDString("not a valid bip39 phrase", "hanzo/foo"); err == nil {
		t.Error("invalid mnemonic should error")
	}
}
