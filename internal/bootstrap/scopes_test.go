// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// scopes_test.go — the least-privilege overlay: grant derivation from the
// CR (never from the servicePath), set semantics, and the Snapshot's
// faithful (nil-vs-empty preserving) marshalling of the scopes block.
// Internal test (package bootstrap) so it can exercise the unexported
// canonicalization.

package bootstrap

import (
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	secretsv1 "github.com/hanzoai/kms-operator/api/v1"
)

// prodRow is one real (CR name, servicePath, org, env, secretsPath) tuple
// read off the live hanzo-k8s fleet. Verbatim, not invented.
type prodRow struct{ cr, servicePath, org, env, secretsPath string }

// prodFixture is a representative slice of the 129 live KMSSecret CRs,
// including both many-to-many identities in the fleet: bootnode-kms-sync
// (two paths) and iam-master-key-kms-sync (same path, two ENVS).
var prodFixture = []prodRow{
	{"adnexus-secrets-sync", "hanzo/adnexus-secrets-sync", "hanzo", "prod", "/adnexus"},
	{"bootnode-kms-sync", "hanzo/bootnode-kms-sync", "hanzo", "prod", "/bootnode"},
	{"bootnode-kms-sync", "hanzo/bootnode-kms-sync", "hanzo", "prod", "/bootnode-secrets"},
	{"collab-kms-sync", "hanzo/collab-kms-sync", "hanzo", "prod", "/collab-secret"},
	{"enso-secrets", "hanzo/enso-secrets", "hanzo", "prod", "/llm-secrets"},
	{"ghcr-bootnode-pull-kms-sync", "hanzo/ghcr-bootnode-pull-kms-sync", "hanzo", "prod", "/ghcr-bootnode-pull"},
	{"hanzo-cd-oidc-kms-sync", "hanzo/hanzo-cd-oidc-kms-sync", "hanzo", "prod", "/argocd"},
	{"iam-master-key-kms-sync", "hanzo/iam-master-key-kms-sync", "hanzo", "devnet", "/iam"},
	{"iam-master-key-kms-sync", "hanzo/iam-master-key-kms-sync", "hanzo", "prod", "/iam"},
	{"cloud-widget-kms-sync", "hanzo/cloud-widget-kms-sync", "hanzo", "prod", "/"},
}

// TestServicePathDerivedScope_LocksOutProduction is the regression that
// justifies this whole file. It runs the OLD rule — "confine an identity
// to the subtree named by its servicePath" — over real fleet data and
// shows it denies almost everything.
//
// This is not hypothetical. The rule the operator carried before this
// gate was exactly `scope = trimIdentityPath(servicePath)`. Enforcing it
// would have taken production KMS offline.
func TestServicePathDerivedScope_LocksOutProduction(t *testing.T) {
	denied := 0
	for _, row := range prodFixture {
		// The old rule's answer.
		oldScope := strings.Trim(row.servicePath, "/")
		// The address the service actually reads.
		real := strings.Trim(row.org+"/"+strings.Trim(row.secretsPath, "/"), "/")
		if real == oldScope || strings.HasPrefix(real, oldScope+"/") {
			continue
		}
		denied++
	}
	if denied != len(prodFixture) {
		t.Fatalf("fixture drifted: expected the servicePath rule to deny every row, denied %d/%d", denied, len(prodFixture))
	}
	t.Logf("servicePath-derived scope denies %d/%d real production grants — total lockout", denied, len(prodFixture))
}

// TestGrantsFromKMSSecret_UsesRealSecretsPath — the grant a CR confers is
// its secretsScope, and demonstrably NOT its servicePath.
func TestGrantsFromKMSSecret_UsesRealSecretsPath(t *testing.T) {
	for _, row := range prodFixture {
		cr := crFor(row)
		got := GrantsFromKMSSecret(cr)
		if len(got) != 1 {
			t.Fatalf("%s: got %d grants, want exactly 1: %v", row.cr, len(got), got)
		}
		want := Grant{Org: row.org, Env: row.env, Path: strings.Trim(row.secretsPath, "/")}
		if got[0] != want {
			t.Errorf("%s: grant = %+v, want %+v", row.cr, got[0], want)
		}
		// And it is NOT the servicePath — the bug this gate removes.
		if got[0].Path == strings.TrimPrefix(row.servicePath, "hanzo/") && row.cr != "" {
			if got[0].Path != strings.Trim(row.secretsPath, "/") {
				t.Errorf("%s: grant fell back to the servicePath", row.cr)
			}
		}
	}
}

// TestGrantsFromKMSSecret_RootPathIsALegitimateGrant — a live CR
// (cloud-widget-kms-sync) is scoped to the org root "/". Canonicalizing
// that to "" must NOT drop the grant: dropping it would silently deny the
// service, and treating "" as "everything" would silently widen it. It
// stays an explicit grant on the org root.
func TestGrantsFromKMSSecret_RootPathIsALegitimateGrant(t *testing.T) {
	cr := crFor(prodRow{"cloud-widget-kms-sync", "hanzo/cloud-widget-kms-sync", "hanzo", "prod", "/"})
	got := GrantsFromKMSSecret(cr)
	if len(got) != 1 {
		t.Fatalf("root-path CR produced %d grants, want 1: %v", len(got), got)
	}
	if got[0] != (Grant{Org: "hanzo", Env: "prod", Path: ""}) {
		t.Fatalf("root grant = %+v, want {hanzo prod \"\"}", got[0])
	}
}

// TestGrantsFromKMSSecret_UnsetAuthBlocksProduceNoGrants — the CR type
// carries eight auth blocks as VALUES, so the seven a CR does not use are
// present-but-zero. They must not each contribute a phantom grant.
func TestGrantsFromKMSSecret_UnsetAuthBlocksProduceNoGrants(t *testing.T) {
	cr := &secretsv1.KMSSecret{ObjectMeta: metav1.ObjectMeta{Name: "empty", Namespace: "hanzo"}}
	if got := GrantsFromKMSSecret(cr); len(got) != 0 {
		t.Fatalf("a CR with no auth block produced %d grants: %v", len(got), got)
	}
}

// TestGrants_Canonical_DedupeSortStable — the emitted set must be a SET
// (deduplicated) with a stable order, or an idempotent reconcile rewrites
// the Secret on every tick.
func TestGrants_Canonical_DedupeSortStable(t *testing.T) {
	g := Grants{Grants: []Grant{
		{Org: "hanzo", Env: "prod", Path: "/bootnode-secrets/"},
		{Org: "hanzo", Env: "prod", Path: "bootnode"},
		{Org: "hanzo", Env: "prod", Path: "/bootnode"}, // dup of the above after canonicalization
		{Org: "hanzo", Env: "devnet", Path: " /iam "},
	}}
	c := g.canonical()
	want := []Grant{
		{Org: "hanzo", Env: "devnet", Path: "iam"},
		{Org: "hanzo", Env: "prod", Path: "bootnode"},
		{Org: "hanzo", Env: "prod", Path: "bootnode-secrets"},
	}
	if len(c.Grants) != len(want) {
		t.Fatalf("canonical = %v, want %v", c.Grants, want)
	}
	for i := range want {
		if c.Grants[i] != want[i] {
			t.Fatalf("canonical = %v, want %v", c.Grants, want)
		}
	}
	// Re-canonicalizing is a fixed point.
	if c2 := c.canonical(); len(c2.Grants) != len(c.Grants) {
		t.Fatalf("canonical is not idempotent: %v → %v", c.Grants, c2.Grants)
	}
}

// TestGrants_EmptySetIsDenyAll_NotUnconfined — the fail-closed shape.
// "Unconfined" is an explicit flag; an empty grant list must never be
// readable as "everything".
func TestGrants_EmptySetIsDenyAll_NotUnconfined(t *testing.T) {
	empty := Grants{}.canonical()
	if empty.Unconfined {
		t.Fatal("an empty grant set must not be Unconfined")
	}
	if empty.Grants == nil {
		t.Fatal("canonical grant list must be non-nil so it renders [] not null")
	}
	raw, err := json.Marshal(empty)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"grants":[]}` {
		t.Fatalf("empty grant set marshalled as %s, want {\"grants\":[]}", raw)
	}
	var back Grants
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Unconfined || len(back.Grants) != 0 {
		t.Fatalf("deny-all did not survive the round trip: %+v", back)
	}
}

// TestSnapshot_MarshalCanonical_ScopesFaithful pins the wire contract the
// kmsd consumes: a nil Identities map serializes to `null` (no overlay), a
// present-but-empty map to `{}` (overlay present, nothing granted), and a
// populated map keeps every grant. This is the property that keeps the
// overlay from failing OPEN across the Secret round trip.
func TestSnapshot_MarshalCanonical_ScopesFaithful(t *testing.T) {
	snap := Snapshot{
		Validators: []string{"NodeID-b", "NodeID-a"},
		Operators:  []string{"NodeID-op"},
		Scopes: &AuthorityScopes{Identities: map[string]Grants{
			"NodeID-op": {Unconfined: true},
			"NodeID-svc": {Grants: []Grant{
				{Org: "hanzo", Env: "prod", Path: "/bootnode"},
				{Org: "hanzo", Env: "prod", Path: "/bootnode-secrets"},
			}},
		}},
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
	if got := back.Scopes.Identities["NodeID-svc"].Grants; len(got) != 2 {
		t.Fatalf("service grant set lost entries: %v (raw=%s)", got, raw)
	}
	if !back.Scopes.Identities["NodeID-op"].Unconfined {
		t.Errorf("operator Unconfined flag lost: %s", raw)
	}

	// Present-but-empty map must survive as {} (overlay present, nothing
	// granted), not collapse to null (which reads as no overlay).
	emptySnap := Snapshot{
		Validators: []string{"NodeID-a"},
		Operators:  []string{"NodeID-a"},
		Scopes:     &AuthorityScopes{Identities: map[string]Grants{}},
	}
	rawEmpty, err := emptySnap.MarshalCanonical()
	if err != nil {
		t.Fatalf("MarshalCanonical empty: %v", err)
	}
	var backEmpty Snapshot
	if err := json.Unmarshal(rawEmpty, &backEmpty); err != nil {
		t.Fatalf("unmarshal empty: %v", err)
	}
	if backEmpty.Scopes == nil || backEmpty.Scopes.Identities == nil {
		t.Fatalf("present-but-empty identities collapsed to nil (fail-open): %s", rawEmpty)
	}
	if len(backEmpty.Scopes.Identities) != 0 {
		t.Errorf("empty identities map gained entries: %v", backEmpty.Scopes.Identities)
	}
}

// TestSnapshot_MarshalCanonical_NilScopesOmitted — a scope-less snapshot
// must not emit a `scopes` key at all: byte-identical to the pre-overlay
// operator so an existing deployment sees no spurious rewrite.
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

// TestSnapshot_Equal_AccountsForScopes — Equal must consider the overlay
// so an idempotent reconcile does not rewrite the Secret, yet a changed
// grant does trigger a rewrite.
func TestSnapshot_Equal_AccountsForScopes(t *testing.T) {
	mk := func(paths ...string) Snapshot {
		gs := make([]Grant, 0, len(paths))
		for _, p := range paths {
			gs = append(gs, Grant{Org: "hanzo", Env: "prod", Path: p})
		}
		return Snapshot{
			Validators: []string{"NodeID-a"},
			Operators:  []string{"NodeID-op", "NodeID-svc"},
			Scopes: &AuthorityScopes{Identities: map[string]Grants{
				"NodeID-op":  {Unconfined: true},
				"NodeID-svc": {Grants: gs},
			}},
		}
	}
	base := mk("bootnode", "bootnode-secrets")
	// Same content, different insertion order.
	same := mk("bootnode-secrets", "bootnode")
	if !base.Equal(same) {
		a, _ := base.MarshalCanonical()
		b, _ := same.MarshalCanonical()
		t.Fatalf("Equal must be order-insensitive: %s vs %s", a, b)
	}
	// A widened grant is a real change.
	if base.Equal(mk("bootnode", "bootnode-secrets", "iam")) {
		t.Fatal("Equal must detect an added grant")
	}
	// A narrowed grant is a real change.
	if base.Equal(mk("bootnode")) {
		t.Fatal("Equal must detect a removed grant")
	}
	// Scopes present vs absent is a change.
	flat := Snapshot{Validators: []string{"NodeID-a"}, Operators: []string{"NodeID-op", "NodeID-svc"}}
	if base.Equal(flat) {
		t.Fatal("Equal must distinguish an overlay from none")
	}
}

// TestIdentityRefForKMSSecret_Defaults pins the ONE resolver both the
// per-CR hook and the authority pass depend on. Drift here emits grants
// keyed to a NodeID no service presents.
func TestIdentityRefForKMSSecret_Defaults(t *testing.T) {
	cr := &secretsv1.KMSSecret{ObjectMeta: metav1.ObjectMeta{Name: "enso-secrets", Namespace: "hanzo-apps"}}
	ref, path := IdentityRefForKMSSecret(cr, "hanzo")
	if ref.Name != "enso-secrets-mnemonic" || ref.Namespace != "hanzo" {
		t.Fatalf("default ref = %+v, want hanzo/enso-secrets-mnemonic", ref)
	}
	if path != "hanzo/enso-secrets" {
		t.Fatalf("default servicePath = %q, want hanzo/enso-secrets", path)
	}

	// Explicit values win, and the CR namespace is the last fallback.
	cr.Spec.ServicePath = "lux/bridge-signer"
	cr.Spec.MnemonicSecretRef.SecretName = "bridge-mnemonic"
	ref, path = IdentityRefForKMSSecret(cr, "")
	if ref.Name != "bridge-mnemonic" || ref.Namespace != "hanzo-apps" {
		t.Fatalf("explicit ref = %+v, want hanzo-apps/bridge-mnemonic", ref)
	}
	if path != "lux/bridge-signer" {
		t.Fatalf("explicit servicePath = %q", path)
	}
}

// crFor builds a KMSSecret CR matching one production fixture row.
func crFor(row prodRow) *secretsv1.KMSSecret {
	cr := &secretsv1.KMSSecret{
		ObjectMeta: metav1.ObjectMeta{Name: row.cr, Namespace: "hanzo"},
	}
	cr.Spec.Authentication.UniversalAuth.SecretsScope = secretsv1.MachineIdentityScopeInWorkspace{
		ProjectSlug: row.org,
		EnvSlug:     row.env,
		SecretsPath: row.secretsPath,
		Keys:        []string{"PLACEHOLDER"},
	}
	return cr
}
