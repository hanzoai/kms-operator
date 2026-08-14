// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// kms_authority_scopes_test.go — end-to-end coverage that a reconcile pass
// stamps the least-privilege overlay onto kms-consensus-authority with the
// REAL secret addresses, as a SET.
//
// The load-bearing property: identity→path is MANY-TO-MANY. One identity
// legitimately holds several unrelated grants (hanzo-platform reads 40+
// distinct paths; hanzo-analytics reads shared datastore paths; bootnode
// reads /bootnode AND /bootnode-secrets; iam-master-key reads /iam in
// devnet AND prod). A scalar scope — or any prefix invented from the
// servicePath — silently drops all but one and takes production offline
// the moment it is enforced.
//
// Reuses the fake-client + luxd-stub rig from kms_authority_test.go.

package bootstrap_test

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1 "github.com/hanzoai/kms-operator/api/v1"
	"github.com/hanzoai/kms-operator/internal/bootstrap"
)

// hanzoPlatformPaths is the real read surface of the hanzo-platform
// identity on the live fleet — a slice of the 44 distinct secretsPaths it
// holds. This is the case the audit named as the outage trigger.
var hanzoPlatformPaths = []string{
	"/admin-guard-secrets", "/adnexus", "/argocd/repo-ssh", "/auth",
	"/bootnode", "/bootnode-secrets", "/bot", "/bot-browser",
	"/buildx-ghcr-auth", "/chat-guest-key", "/platform", "/storage",
}

// mnemonicSecret builds a service-mnemonic Secret carrying the canonical
// service path annotation.
func mnemonicSecret(name, servicePath string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Namespace: "hanzo",
			Name:      name,
			Labels:    map[string]string{"app.kubernetes.io/component": "service-mnemonic"},
			Annotations: map[string]string{
				"kms-operator.lux.network/service-path": servicePath,
			},
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{bootstrap.MnemonicKey: []byte(knownMnemonic)},
	}
}

// kmsSecretCR builds a KMSSecret CR scoped to one (org, env, path) and
// pinned to an explicit identity (mnemonic Secret + service path) so
// several CRs can resolve to the SAME NodeID — the many-to-many shape.
func kmsSecretCR(name, mnemonicSecret, servicePath, org, env, path string) *secretsv1.KMSSecret {
	cr := &secretsv1.KMSSecret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: "hanzo"},
	}
	cr.Spec.MnemonicSecretRef.SecretName = mnemonicSecret
	cr.Spec.ServicePath = servicePath
	cr.Spec.Authentication.UniversalAuth.SecretsScope = secretsv1.MachineIdentityScopeInWorkspace{
		ProjectSlug: org,
		EnvSlug:     env,
		SecretsPath: path,
		Keys:        []string{"PLACEHOLDER"},
	}
	return cr
}

// scopeOf returns the grant set the snapshot carries for a NodeID.
func scopeOf(t *testing.T, snap bootstrap.Snapshot, nodeID string) bootstrap.Grants {
	t.Helper()
	if snap.Scopes == nil || snap.Scopes.Identities == nil {
		t.Fatalf("snapshot carries no identity scope overlay: %+v", snap)
	}
	g, ok := snap.Scopes.Identities[nodeID]
	if !ok {
		t.Fatalf("no grant entry for %s — an absent entry is indistinguishable from 'not computed'", nodeID)
	}
	return g
}

// serviceNodeID returns the single confined (non-operator) identity.
func serviceNodeID(t *testing.T, snap bootstrap.Snapshot) string {
	t.Helper()
	var svc []string
	for _, id := range snap.Operators {
		if g, ok := snap.Scopes.Identities[id]; ok && g.Unconfined {
			continue
		}
		svc = append(svc, id)
	}
	if len(svc) != 1 {
		t.Fatalf("expected exactly one confined service identity, got %v", svc)
	}
	return svc[0]
}

// TestBootstrap_ScopeSetCarriesEveryRealPath is the headline property: a
// many-to-many identity's grant set holds EVERY path it actually reads,
// not one of them and not a prefix.
func TestBootstrap_ScopeSetCarriesEveryRealPath(t *testing.T) {
	ctx := context.Background()

	objs := []client.Object{mnemonicSecret("hanzo-platform-mnemonic", "hanzo/hanzo-platform")}
	for i, p := range hanzoPlatformPaths {
		objs = append(objs, kmsSecretCR(
			"hanzo-platform-"+strconv.Itoa(i),
			"hanzo-platform-mnemonic", "hanzo/hanzo-platform",
			"hanzo", "prod", p,
		))
	}

	c := newFakeClient(t, objs...)
	luxd := newLuxdStub(t, []string{"NodeID-2EZHk7zR8K1nFkGm7uNZmMddD1L5N1khh"})
	cfg := configFor(luxd.URL)
	rec := bootstrap.NewReconciler(c, testLogger(), cfg, bootstrap.NewLuxdClient(luxd.URL))

	rcReconcile(ctx, t, rec)
	snap := readSnapshot(ctx, t, c, cfg.AuthorityRef)

	got := scopeOf(t, snap, serviceNodeID(t, snap))
	if got.Unconfined {
		t.Fatal("a service identity must never be Unconfined")
	}

	gotPaths := make([]string, 0, len(got.Grants))
	for _, g := range got.Grants {
		if g.Org != "hanzo" || g.Env != "prod" {
			t.Errorf("grant lost its org/env dimension: %+v", g)
		}
		gotPaths = append(gotPaths, g.Path)
	}
	sort.Strings(gotPaths)

	want := make([]string, 0, len(hanzoPlatformPaths))
	for _, p := range hanzoPlatformPaths {
		want = append(want, strings.Trim(p, "/"))
	}
	sort.Strings(want)

	if len(gotPaths) != len(want) {
		t.Fatalf("scope set holds %d paths, want %d (a scalar scope holds 1 and locks out the other %d)\n got: %v\nwant: %v",
			len(gotPaths), len(want), len(want)-1, gotPaths, want)
	}
	for i := range want {
		if gotPaths[i] != want[i] {
			t.Fatalf("scope set = %v, want %v", gotPaths, want)
		}
	}
	t.Logf("many-to-many identity carries all %d real paths", len(gotPaths))
}

// TestBootstrap_ScopeSet_UnionsAcrossEnvs — the live iam-master-key
// identity reads the SAME path in two environments. Env is a real
// dimension of the store key (kms/secrets/{path}/{env}/{name}); collapsing
// it would either deny devnet or silently grant it.
func TestBootstrap_ScopeSet_UnionsAcrossEnvs(t *testing.T) {
	ctx := context.Background()
	c := newFakeClient(t,
		mnemonicSecret("iam-master-key-kms-sync-mnemonic", "hanzo/iam-master-key-kms-sync"),
		kmsSecretCR("iam-master-key-a", "iam-master-key-kms-sync-mnemonic", "hanzo/iam-master-key-kms-sync", "hanzo", "prod", "/iam"),
		kmsSecretCR("iam-master-key-b", "iam-master-key-kms-sync-mnemonic", "hanzo/iam-master-key-kms-sync", "hanzo", "devnet", "/iam"),
	)
	luxd := newLuxdStub(t, []string{"NodeID-2EZHk7zR8K1nFkGm7uNZmMddD1L5N1khh"})
	cfg := configFor(luxd.URL)
	rec := bootstrap.NewReconciler(c, testLogger(), cfg, bootstrap.NewLuxdClient(luxd.URL))

	rcReconcile(ctx, t, rec)
	snap := readSnapshot(ctx, t, c, cfg.AuthorityRef)
	got := scopeOf(t, snap, serviceNodeID(t, snap))

	if len(got.Grants) != 2 {
		t.Fatalf("expected 2 grants (one per env), got %d: %v", len(got.Grants), got.Grants)
	}
	envs := map[string]bool{}
	for _, g := range got.Grants {
		if g.Path != "iam" {
			t.Errorf("grant path = %q, want iam", g.Path)
		}
		envs[g.Env] = true
	}
	if !envs["prod"] || !envs["devnet"] {
		t.Fatalf("env dimension collapsed: %v", got.Grants)
	}
}

// TestBootstrap_ScopeIsRealPath_NotServicePath — the regression pin. The
// service is derived under "hanzo/enso-secrets" but reads "/llm-secrets".
// The emitted grant must be the address it reads; a servicePath-derived
// scope would deny it outright.
func TestBootstrap_ScopeIsRealPath_NotServicePath(t *testing.T) {
	ctx := context.Background()
	c := newFakeClient(t,
		mnemonicSecret("enso-secrets-mnemonic", "hanzo/enso-secrets"),
		kmsSecretCR("enso-secrets", "enso-secrets-mnemonic", "hanzo/enso-secrets", "hanzo", "prod", "/llm-secrets"),
	)
	luxd := newLuxdStub(t, []string{"NodeID-2EZHk7zR8K1nFkGm7uNZmMddD1L5N1khh"})
	cfg := configFor(luxd.URL)
	rec := bootstrap.NewReconciler(c, testLogger(), cfg, bootstrap.NewLuxdClient(luxd.URL))

	rcReconcile(ctx, t, rec)
	snap := readSnapshot(ctx, t, c, cfg.AuthorityRef)
	got := scopeOf(t, snap, serviceNodeID(t, snap))

	if len(got.Grants) != 1 {
		t.Fatalf("expected 1 grant, got %v", got.Grants)
	}
	if got.Grants[0].Path != "llm-secrets" {
		t.Fatalf("grant path = %q, want llm-secrets (the REAL secretsPath); "+
			"%q would be the servicePath-derived answer that locks the service out", got.Grants[0].Path, "enso-secrets")
	}
}

// TestBootstrap_OperatorUnconfined_UngrantedServiceFailsClosed — the
// operator is EXPLICITLY unconfined; a service with no CR gets an explicit
// empty set (deny all), never an absent entry and never
// unconfined-by-omission.
func TestBootstrap_OperatorUnconfined_UngrantedServiceFailsClosed(t *testing.T) {
	ctx := context.Background()
	// A mnemonic Secret with NO backing CR — the orphan case.
	c := newFakeClient(t, mnemonicSecret("orphan-mnemonic", "hanzo/orphan"))
	luxd := newLuxdStub(t, []string{"NodeID-2EZHk7zR8K1nFkGm7uNZmMddD1L5N1khh"})
	cfg := configFor(luxd.URL)
	rec := bootstrap.NewReconciler(c, testLogger(), cfg, bootstrap.NewLuxdClient(luxd.URL))

	rcReconcile(ctx, t, rec)
	snap := readSnapshot(ctx, t, c, cfg.AuthorityRef)

	// Every operator member carries an explicit entry — a missing entry is
	// ambiguous and must never occur.
	if len(snap.Scopes.Identities) != len(snap.Operators) {
		t.Fatalf("scope entries (%d) != operator members (%d): %v vs %v",
			len(snap.Scopes.Identities), len(snap.Operators), snap.Scopes.Identities, snap.Operators)
	}
	unconfined := 0
	for id, g := range snap.Scopes.Identities {
		if g.Unconfined {
			unconfined++
			continue
		}
		if len(g.Grants) != 0 {
			t.Errorf("orphan identity %s got grants it has no CR for: %v", id, g.Grants)
		}
	}
	if unconfined != 1 {
		t.Fatalf("expected exactly one unconfined identity (the kms-operator), got %d", unconfined)
	}
}

// TestBootstrap_ScopeEmission_Idempotent — the overlay must not cause
// spurious Secret rewrites: a second identical reconcile leaves the
// resourceVersion unchanged (Equal accounts for the grant sets).
func TestBootstrap_ScopeEmission_Idempotent(t *testing.T) {
	ctx := context.Background()
	c := newFakeClient(t,
		mnemonicSecret("bootnode-kms-sync-mnemonic", "hanzo/bootnode-kms-sync"),
		kmsSecretCR("bootnode-kms-sync-a", "bootnode-kms-sync-mnemonic", "hanzo/bootnode-kms-sync", "hanzo", "prod", "/bootnode"),
		kmsSecretCR("bootnode-kms-sync-b", "bootnode-kms-sync-mnemonic", "hanzo/bootnode-kms-sync", "hanzo", "prod", "/bootnode-secrets"),
	)
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
