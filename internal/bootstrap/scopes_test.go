// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// scopes_test.go — the least-privilege overlay: the pure scope-derivation
// rule and the Snapshot's faithful (nil-vs-empty preserving) marshalling of
// the scopes block. Internal test (package bootstrap) so it can exercise the
// unexported deriveServiceScope / normalizeScopeMap.

package bootstrap

import (
	"encoding/json"
	"testing"
)

func TestDeriveServiceScope(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"hanzo/commerce", "hanzo/commerce"},
		{"/hanzo/commerce/", "hanzo/commerce"},
		{"  hanzo/commerce  ", "hanzo/commerce"},
		{"hanzo/kms-operator", "hanzo/kms-operator"},
		{"lux/bridge/signer", "lux/bridge/signer"},
	}
	for _, c := range cases {
		if got := deriveServiceScope(c.in); got != c.want {
			t.Errorf("deriveServiceScope(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestSnapshot_MarshalCanonical_ScopesFaithful pins the wire contract the
// kmsd consumes: a nil authority scope map must serialize to `null` (flat),
// a present-but-empty map to `{}` (scoped, deny all), and a populated map
// with its grants — none silently dropped. This is the property that keeps a
// scoped authority from failing OPEN across the Secret round trip.
func TestSnapshot_MarshalCanonical_ScopesFaithful(t *testing.T) {
	snap := Snapshot{
		Validators: []string{"NodeID-b", "NodeID-a"},
		Operators:  []string{"NodeID-op"},
		Scopes: &AuthorityScopes{
			// Validators nil → flat read authority.
			Operators: map[string]string{
				"NodeID-op":  "",               // operator unconfined
				"NodeID-svc": "hanzo/commerce", // service confined to subtree
			},
		},
	}
	raw, err := snap.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}

	var back Snapshot
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal canonical: %v (raw=%s)", err, raw)
	}
	if back.Scopes == nil {
		t.Fatalf("scopes dropped entirely on round trip: %s", raw)
	}
	if back.Scopes.Validators != nil {
		t.Errorf("nil validator scopes must round-trip as null→nil, got %v", back.Scopes.Validators)
	}
	if got := back.Scopes.Operators["NodeID-svc"]; got != "hanzo/commerce" {
		t.Errorf("service scope grant lost: got %q want hanzo/commerce", got)
	}
	if got, ok := back.Scopes.Operators["NodeID-op"]; !ok || got != "" {
		t.Errorf("operator unconfined grant lost: got %q present=%v (want \"\", true)", got, ok)
	}

	// Present-but-empty map must survive as {} (scoped, zero grants), not
	// collapse to null (which the kmsd reads as flat — fail open).
	emptySnap := Snapshot{
		Validators: []string{"NodeID-a"},
		Operators:  []string{"NodeID-a"},
		Scopes:     &AuthorityScopes{Validators: map[string]string{}},
	}
	rawEmpty, err := emptySnap.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical empty: %v", err)
	}
	var backEmpty Snapshot
	if err := json.Unmarshal(rawEmpty, &backEmpty); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if backEmpty.Scopes == nil || backEmpty.Scopes.Validators == nil {
		t.Fatalf("present-but-empty validator scope collapsed to nil (fail-open): %s", rawEmpty)
	}
	if len(backEmpty.Scopes.Validators) != 0 {
		t.Errorf("empty scope map gained entries: %v", backEmpty.Scopes.Validators)
	}
}

// TestSnapshot_MarshalCanonical_NilScopesOmitted — a scope-less snapshot
// must not emit a `scopes` key at all (back-compat: identical bytes to the
// pre-scopes operator so existing deployments see no spurious rewrite).
func TestSnapshot_MarshalCanonical_NilScopesOmitted(t *testing.T) {
	snap := Snapshot{Validators: []string{"NodeID-a"}, Operators: []string{"NodeID-a"}}
	raw, err := snap.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical: %v", err)
	}
	if got := string(raw); got != `{"validators":["NodeID-a"],"operators":["NodeID-a"]}` {
		t.Fatalf("scope-less snapshot bytes changed (back-compat break): %s", got)
	}
}

// TestSnapshot_Equal_AccountsForScopes — Equal must consider the scope
// overlay so an idempotent reconcile does not rewrite the Secret, yet a
// changed grant does trigger a rewrite.
func TestSnapshot_Equal_AccountsForScopes(t *testing.T) {
	base := Snapshot{
		Validators: []string{"NodeID-a"},
		Operators:  []string{"NodeID-op", "NodeID-svc"},
		Scopes: &AuthorityScopes{Operators: map[string]string{
			"NodeID-op": "", "NodeID-svc": "hanzo/commerce",
		}},
	}
	// Same content, different map insertion order + slice order.
	same := Snapshot{
		Validators: []string{"NodeID-a"},
		Operators:  []string{"NodeID-svc", "NodeID-op"},
		Scopes: &AuthorityScopes{Operators: map[string]string{
			"NodeID-svc": "hanzo/commerce", "NodeID-op": "",
		}},
	}
	if !base.Equal(same) {
		a, _ := base.MarshalCanonical()
		b, _ := same.MarshalCanonical()
		t.Fatalf("Equal must be order-insensitive: %s vs %s", a, b)
	}

	// A widened grant is a real change.
	widened := Snapshot{
		Validators: []string{"NodeID-a"},
		Operators:  []string{"NodeID-op", "NodeID-svc"},
		Scopes: &AuthorityScopes{Operators: map[string]string{
			"NodeID-op": "", "NodeID-svc": "hanzo", // widened commerce → hanzo
		}},
	}
	if base.Equal(widened) {
		t.Fatalf("Equal must detect a changed scope grant")
	}

	// Scopes present vs absent is a change.
	flat := Snapshot{Validators: []string{"NodeID-a"}, Operators: []string{"NodeID-op", "NodeID-svc"}}
	if base.Equal(flat) {
		t.Fatalf("Equal must distinguish scoped from flat")
	}
}
