// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// kms_authority_scopes_test.go — end-to-end coverage that a reconcile pass
// stamps the least-privilege overlay onto kms-consensus-authority: the WRITE
// (operator) authority is confined per-service (each service NodeID → its
// own subtree), the operator itself stays unconfined, and the READ
// (validator) authority is left flat. Reuses the fake-client + luxd-stub rig
// from kms_authority_test.go.

package bootstrap_test

import (
	"context"
	"sort"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/hanzoai/kms-operator/internal/bootstrap"
)

func TestBootstrap_EmitsPerServiceWriteScopes(t *testing.T) {
	ctx := context.Background()
	// A service-mnemonic Secret with a known path so the emitted scope is
	// deterministic.
	svcMnem := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "hanzo",
			Name:      "hanzo-base-mnemonic",
			Labels: map[string]string{
				"app.kubernetes.io/component": "service-mnemonic",
			},
			Annotations: map[string]string{
				"kms-operator.lux.network/service-path": "hanzo/hanzo-base",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			bootstrap.MnemonicKey: []byte(knownMnemonic),
		},
	}
	c := newFakeClient(t, svcMnem)
	luxd := newLuxdStub(t, []string{"NodeID-2EZHk7zR8K1nFkGm7uNZmMddD1L5N1khh"})

	cfg := configFor(luxd.URL)
	rec := bootstrap.NewReconciler(c, testLogger(), cfg, bootstrap.NewLuxdClient(luxd.URL))

	rcReconcile(ctx, t, rec)

	snap := readSnapshot(ctx, t, c, cfg.AuthorityRef)

	// The READ authority is flat: luxd L1 validators have no per-node
	// subtree to confine to.
	if snap.Scopes == nil {
		t.Fatalf("snapshot carries no scopes overlay: %+v", snap)
	}
	if snap.Scopes.Validators != nil {
		t.Errorf("read (validator) authority must be flat (nil scopes), got %v", snap.Scopes.Validators)
	}

	// The WRITE authority is fully granted (fail-closed completeness): every
	// operator member has an explicit scope grant.
	if len(snap.Scopes.Operators) != len(snap.Operators) {
		t.Fatalf("operator scope grants (%d) != operator members (%d) — an un-granted member would fail closed: scopes=%v members=%v",
			len(snap.Scopes.Operators), len(snap.Operators), snap.Scopes.Operators, snap.Operators)
	}
	for _, op := range snap.Operators {
		if _, ok := snap.Scopes.Operators[op]; !ok {
			t.Fatalf("operator member %s has no scope grant (would fail closed)", op)
		}
	}

	// The grant VALUES are exactly: one unconfined ("" = the operator) and
	// one service subtree ("hanzo/hanzo-base").
	vals := make([]string, 0, len(snap.Scopes.Operators))
	for _, v := range snap.Scopes.Operators {
		vals = append(vals, v)
	}
	sort.Strings(vals)
	want := []string{"", "hanzo/hanzo-base"}
	if len(vals) != len(want) {
		t.Fatalf("scope values = %v, want %v", vals, want)
	}
	for i := range want {
		if vals[i] != want[i] {
			t.Fatalf("scope values = %v, want %v", vals, want)
		}
	}
}

// TestBootstrap_ScopeEmission_Idempotent — the scope overlay must not cause
// spurious Secret rewrites: a second identical reconcile leaves the
// resourceVersion unchanged (Equal accounts for scopes).
func TestBootstrap_ScopeEmission_Idempotent(t *testing.T) {
	ctx := context.Background()
	svcMnem := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "hanzo",
			Name:      "hanzo-base-mnemonic",
			Labels:    map[string]string{"app.kubernetes.io/component": "service-mnemonic"},
			Annotations: map[string]string{
				"kms-operator.lux.network/service-path": "hanzo/hanzo-base",
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{bootstrap.MnemonicKey: []byte(knownMnemonic)},
	}
	c := newFakeClient(t, svcMnem)
	luxd := newLuxdStub(t, []string{"NodeID-2EZHk7zR8K1nFkGm7uNZmMddD1L5N1khh"})
	cfg := configFor(luxd.URL)
	rec := bootstrap.NewReconciler(c, testLogger(), cfg, bootstrap.NewLuxdClient(luxd.URL))

	rcReconcile(ctx, t, rec)
	first := authoritySecret(ctx, t, c, cfg.AuthorityRef).ResourceVersion
	rcReconcile(ctx, t, rec)
	second := authoritySecret(ctx, t, c, cfg.AuthorityRef).ResourceVersion
	if first != second {
		t.Fatalf("scoped authority rewritten on idempotent reconcile: rv %s → %s", first, second)
	}
}
