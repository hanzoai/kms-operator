// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// scopes.go — the least-privilege overlay: what each service identity is
// actually allowed to address.
//
// # Why a SET, and why the CR is the only source
//
// A service identity's NodeID is derived from (mnemonic, servicePath).
// The servicePath NAMES the identity. It says nothing about the DATA the
// service reads. Those two are unrelated in production: measured against
// the live fleet, 127 of 129 KMSSecret CRs have a `secretsPath` that
// shares no prefix with their servicePath —
//
//	servicePath  hanzo/enso-secrets      →  secretsPath  hanzo/llm-secrets
//	servicePath  hanzo/collab-kms-sync   →  secretsPath  hanzo/collab-secret
//	servicePath  hanzo/adnexus-secrets-sync → secretsPath hanzo/adnexus
//
// so ANY scope derived from the servicePath (a single string, a prefix,
// a "<org>/<service>" convention) denies ~98% of real traffic the moment
// it is enforced. That is the total-lockout failure mode this overlay
// exists to avoid, not cause.
//
// The mapping is also many-to-many in both directions: one identity may
// legitimately hold several unrelated grants —
//
//	hanzo/bootnode-kms-sync        → /bootnode  AND  /bootnode-secrets
//	hanzo/iam-master-key-kms-sync  → /iam@devnet AND /iam@prod
//
// and at the IAM-credential granularity a single identity spans dozens
// (hanzo-platform: 44 distinct paths; universal-auth-credentials: 8
// distinct ORGS). A scalar scope cannot express any of that. The value
// is a SET of exact grants, unioned across every CR that resolves to the
// same identity.
//
// The KMSSecret CR's `secretsScope` is the ONE source of truth: it is
// the address the operator itself uses when it fetches on the service's
// behalf, so it is by construction the address the service needs.
//
// # Inert by construction
//
// This file only COMPUTES and EMITS grants into the authority snapshot.
// Nothing enforces them. The kmsd's consensus snapshot decoder ignores
// unknown keys, so emitting `scopes` changes no runtime decision. Gate
// G4 flips enforcement; until then this is data.

package bootstrap

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"sigs.k8s.io/controller-runtime/pkg/client"

	secretsv1alpha1 "github.com/hanzoai/kms-operator/api/v1alpha1"
)

// Grant is ONE exact secret address a service identity may reach.
//
// All three dimensions are carried because all three are real:
//
//   - Org  — the KMS org (CR `projectSlug`). The REST plane addresses
//     /v1/kms/orgs/{org}/secrets/..., so org IS the tenant-isolation
//     boundary there. One live identity (universal-auth-credentials)
//     spans 8 orgs; dropping org would silently grant all of them.
//   - Env  — the environment slug (prod / devnet / default). A real
//     dimension of the ZAP store key (kms/secrets/{path}/{env}/{name}).
//     One live identity holds /iam in devnet AND prod as separate grants.
//   - Path — the secrets path, canonicalized without surrounding "/".
//
// Emission is lossless on purpose. A grant that drops a dimension is an
// over-grant, and an over-grant discovered at enforcement time is an
// outage or a breach, not a warning.
type Grant struct {
	Org  string `json:"org"`
	Env  string `json:"env"`
	Path string `json:"path"`
}

// canonical returns the normalized grant: whitespace trimmed everywhere,
// surrounding slashes stripped from Path. Empty Path means the org root,
// which is a legitimate live grant (hanzo-cloud holds "/"), NOT a bug.
func (g Grant) canonical() Grant {
	return Grant{
		Org:  strings.TrimSpace(g.Org),
		Env:  strings.TrimSpace(g.Env),
		Path: strings.Trim(strings.TrimSpace(g.Path), "/"),
	}
}

// less orders grants deterministically so the snapshot bytes are stable
// across reconciles (map iteration order must never cause a rewrite).
func (g Grant) less(o Grant) bool {
	if g.Org != o.Org {
		return g.Org < o.Org
	}
	if g.Env != o.Env {
		return g.Env < o.Env
	}
	return g.Path < o.Path
}

// String is a diagnostic form: "org/path@env". Not a wire form.
func (g Grant) String() string {
	return fmt.Sprintf("%s/%s@%s", g.Org, g.Path, g.Env)
}

// Grants is the scope SET for one identity.
//
// Fail-closed by construction: "unconfined" is an EXPLICIT boolean, never
// inferred from an empty Grants slice. An identity with zero grants is
// confined to nothing (deny all) — the safe reading. Inferring "empty
// means everything" is the classic fail-open bug and this shape makes it
// unrepresentable.
//
// Only the kms-operator itself is Unconfined: it is the authority that
// writes on every service's behalf, so confining it would confine
// everything.
type Grants struct {
	// Unconfined exempts this identity from scope confinement entirely.
	Unconfined bool `json:"unconfined,omitempty"`

	// Grants is the exact set this identity may address. Always non-nil
	// in canonical form (renders `[]`, never `null`) so "scoped, zero
	// grants" survives the JSON round trip as itself.
	Grants []Grant `json:"grants"`
}

// canonical returns the deduplicated, sorted form.
func (g Grants) canonical() Grants {
	seen := make(map[Grant]struct{}, len(g.Grants))
	out := make([]Grant, 0, len(g.Grants))
	for _, raw := range g.Grants {
		c := raw.canonical()
		if _, dup := seen[c]; dup {
			continue
		}
		seen[c] = struct{}{}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].less(out[j]) })
	return Grants{Unconfined: g.Unconfined, Grants: out}
}

// IdentityKey is the tuple a NodeID is derived from. Two CRs that resolve
// to the same key are the SAME identity and their grants union.
type IdentityKey struct {
	MnemonicRef MnemonicRef
	ServicePath string
}

// IdentityRefForKMSSecret is the ONE canonical resolver from a KMSSecret
// CR to the (mnemonic Secret, service path) tuple its NodeID derives
// from. Both the per-CR reconcile hook and the authority reconcile pass
// call this — if they ever disagreed, the operator would emit grants
// keyed to a NodeID no service actually presents, and every scoped
// request would fail closed.
//
// Defaults (unchanged from the per-CR path):
//
//   - ref.Name      = spec.mnemonicSecretRef.secretName, else "<crname>-mnemonic"
//   - ref.Namespace = spec.mnemonicSecretRef.secretNamespace, else
//     defaultMnemonicNS, else cr.Namespace
//   - servicePath   = spec.servicePath, else "hanzo/<crname>"
func IdentityRefForKMSSecret(cr *secretsv1alpha1.KMSSecret, defaultMnemonicNS string) (MnemonicRef, string) {
	ref := MnemonicRef{
		Namespace: strings.TrimSpace(cr.Spec.MnemonicSecretRef.SecretNamespace),
		Name:      strings.TrimSpace(cr.Spec.MnemonicSecretRef.SecretName),
	}
	if ref.Name == "" {
		ref.Name = cr.Name + "-mnemonic"
	}
	if ref.Namespace == "" {
		if defaultMnemonicNS != "" {
			ref.Namespace = defaultMnemonicNS
		} else {
			ref.Namespace = cr.Namespace
		}
	}
	path := strings.TrimSpace(cr.Spec.ServicePath)
	if path == "" {
		path = "hanzo/" + cr.Name
	}
	return ref, path
}

// GrantsFromKMSSecret returns every grant a single CR confers. A CR may
// carry more than one authentication block; each contributes its own
// secretsScope, so the per-CR result is already a set.
func GrantsFromKMSSecret(cr *secretsv1alpha1.KMSSecret) []Grant {
	a := cr.Spec.Authentication
	out := make([]Grant, 0, 4)

	// Machine-identity auth methods — the shape carrying projectSlug.
	for _, s := range []secretsv1alpha1.MachineIdentityScopeInWorkspace{
		a.UniversalAuth.SecretsScope,
		a.KubernetesAuth.SecretsScope,
		a.AwsIamAuth.SecretsScope,
		a.AzureAuth.SecretsScope,
		a.GcpIdTokenAuth.SecretsScope,
		a.GcpIamAuth.SecretsScope,
	} {
		if g, ok := grantOf(s.ProjectSlug, s.EnvSlug, s.SecretsPath); ok {
			out = append(out, g)
		}
	}

	// Service-token auth carries no projectSlug — the org is implied by
	// the token itself. Emitted with an empty Org, which is honest: the
	// operator does not know it. A scope matcher MUST treat an empty Org
	// as "unspecified", never as "any".
	if g, ok := grantOf("", a.ServiceToken.SecretsScope.EnvSlug, a.ServiceToken.SecretsScope.SecretsPath); ok {
		out = append(out, g)
	}

	// Legacy service-account auth uses projectId + environmentName.
	if g, ok := grantOf(a.ServiceAccount.ProjectId, a.ServiceAccount.EnvironmentName, ""); ok {
		out = append(out, g)
	}

	return out
}

// grantOf builds a canonical grant, reporting false for a wholly empty
// scope block (an unset auth method). Path alone may legitimately be
// empty (the org root), so emptiness of Path is not disqualifying.
func grantOf(org, env, path string) (Grant, bool) {
	g := Grant{Org: org, Env: env, Path: path}.canonical()
	if g.Org == "" && g.Env == "" && g.Path == "" {
		return Grant{}, false
	}
	return g, true
}

// collectGrants walks every KMSSecret CR in the operator's watch scope
// and returns the union of grants per identity.
//
// The union is the whole point: two CRs that resolve to the same
// (mnemonic, servicePath) are one identity presenting one NodeID, and
// that NodeID must carry BOTH grants or the second CR's fetch is denied.
func (r *Reconciler) collectGrants(ctx context.Context) (map[IdentityKey]Grants, error) {
	var list secretsv1alpha1.KMSSecretList
	if err := r.client.List(ctx, &list); err != nil {
		return nil, fmt.Errorf("list kmssecrets: %w", err)
	}
	out := make(map[IdentityKey]Grants, len(list.Items))
	for i := range list.Items {
		cr := &list.Items[i]
		ref, path := IdentityRefForKMSSecret(cr, r.cfg.DefaultMnemonicNamespace)
		key := IdentityKey{MnemonicRef: ref, ServicePath: trimIdentityPath(path)}
		g := out[key]
		g.Grants = append(g.Grants, GrantsFromKMSSecret(cr)...)
		out[key] = g
	}
	for k, v := range out {
		out[k] = v.canonical()
	}
	return out, nil
}

// grantsForSecret returns the grant set for a mnemonic Secret's derived
// identity. A Secret with no matching CR gets an empty (deny-all) set
// rather than an absent entry: an absent entry is indistinguishable from
// "not yet computed", and only an explicit empty set is unambiguously
// fail-closed.
func grantsForSecret(byIdentity map[IdentityKey]Grants, ref MnemonicRef, servicePath string) Grants {
	key := IdentityKey{MnemonicRef: ref, ServicePath: trimIdentityPath(servicePath)}
	if g, ok := byIdentity[key]; ok {
		return g
	}
	return Grants{Grants: []Grant{}}
}

// compile-time assertion that client.Client is what collectGrants needs.
var _ interface {
	List(context.Context, client.ObjectList, ...client.ListOption) error
} = client.Client(nil)
