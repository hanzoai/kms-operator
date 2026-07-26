// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package bootstrap maintains the kms-consensus-authority Secret that
// kmsd (luxfi/kms cmd/kmsd) consumes via KMS_CONSENSUS_FILE. The Secret
// holds a JSON snapshot of two NodeID sets:
//
//	{
//	  "validators": ["NodeID-…", "NodeID-…", …],
//	  "operators":  ["NodeID-kms-operator-…", "NodeID-…", …]
//	}
//
// Validators are the L1 consensus authority (sourced from luxd at
// LUXD_RPC_URL); operators are the mnemonic-derived NodeIDs of the
// kms-operator itself plus every service whose KMSSecret CR references
// a mnemonic Secret. The kmsd's in-process authorizer (zapserver.
// InProcessAuthorizer) does the actual policy composition; this package
// only stamps fresh authority data onto the Secret.
//
// Design rules:
//
//   - The mnemonic itself is NEVER logged, NEVER written to CR status,
//     NEVER persisted outside a Kubernetes Secret. Only the derived
//     NodeID surfaces in logs and the authority Secret.
//   - Generate-on-miss: if a service has no mnemonic Secret on first
//     reconcile, the operator generates one and persists it. There is
//     no "waiting for human bootstrap" defer pattern.
//   - Fail-closed: if luxd is unreachable for the TTL refresh, the
//     existing Secret is left untouched. Membership stays stable; the
//     error surfaces in operator logs at ERROR level.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	corev1 "k8s.io/api/core/v1"
	k8serrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthorityKey is the canonical Secret key for the snapshot JSON. The
// kmsd's KMS_CONSENSUS_FILE points at this filename relative to the
// volume mount root (deployment.yaml mounts the Secret at /etc/kms).
const AuthorityKey = "consensus-authority.json"

// Snapshot is the wire shape produced by the operator and consumed by
// kmsd's loadConsensusSnapshot (luxfi/kms cmd/kms/consensus.go). The
// field names match the kmsd consumer byte-for-byte.
//
// Scopes is the OPTIONAL least-privilege overlay. It is DATA ONLY at this
// gate: the kmsd decodes it but no code path enforces on it (enforcement
// is gate G4). Absent (nil) => no overlay at all, byte-identical to the
// pre-overlay operator.
//
// The overlay is AUTHORITY-side data keyed by the derived NodeID. The
// operator knows each service's grants because it holds the CRs, so the
// grants cannot be spoofed by a caller's envelope.
type Snapshot struct {
	Validators []string         `json:"validators"`
	Operators  []string         `json:"operators"`
	Scopes     *AuthorityScopes `json:"scopes,omitempty"`
}

// AuthorityScopes carries the NodeID→grant-set overlay.
//
// Deliberately keyed by IDENTITY, not by authority. Membership
// (validators / operators) answers "who are you"; grants answer "what may
// you address". Those are orthogonal questions and braiding them forces
// the read/write authority-placement decision — a separate gate — into
// the wire shape. One map, one meaning.
//
// The map carries NO omitempty: a present-but-empty map ("scoped, zero
// grants") must survive the JSON round trip as `{}` rather than collapsing
// to null (which a consumer reads as "no overlay" — fail OPEN). nil =>
// `null` (no overlay); `{}` => `{}` (overlay present, nothing granted).
type AuthorityScopes struct {
	// Identities maps member NodeID → the grant set that identity is
	// confined to. A NodeID absent from a non-nil map is confined to
	// nothing.
	Identities map[string]Grants `json:"identities"`
}

// MarshalCanonical returns the canonical JSON form of the snapshot:
// keys sorted, no trailing newline. Used both for write-on-change
// equality and as the bytes persisted into the Secret. Map keys are sorted
// deterministically by encoding/json, so the scope maps need no explicit
// ordering — only prefix normalization.
func (s Snapshot) MarshalCanonical() ([]byte, error) {
	c := Snapshot{
		Validators: dedupeSorted(s.Validators),
		Operators:  dedupeSorted(s.Operators),
		Scopes:     canonicalScopes(s.Scopes),
	}
	return json.Marshal(c)
}

// canonicalScopes normalizes every grant set while preserving the
// nil-vs-empty distinction that carries the overlay-absent signal.
// Returns nil for a nil input.
func canonicalScopes(sc *AuthorityScopes) *AuthorityScopes {
	if sc == nil {
		return nil
	}
	return &AuthorityScopes{Identities: normalizeIdentityScopes(sc.Identities)}
}

// normalizeIdentityScopes canonicalizes each identity's grant set and
// drops blank NodeID keys. nil stays nil (no overlay); a non-nil map stays
// non-nil even when empty (overlay present, nothing granted).
func normalizeIdentityScopes(m map[string]Grants) map[string]Grants {
	if m == nil {
		return nil
	}
	out := make(map[string]Grants, len(m))
	for k, v := range m {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		out[k] = v.canonical()
	}
	return out
}

// Equal reports whether two snapshots project the same authority set
// after dedupe + sort. Used to skip no-op Secret updates.
func (s Snapshot) Equal(other Snapshot) bool {
	a, _ := s.MarshalCanonical()
	b, _ := other.MarshalCanonical()
	return string(a) == string(b)
}

// dedupeSorted returns the input slice deduplicated and lexicographically
// sorted. Nil/empty input returns an empty slice (never nil) so the JSON
// encoding renders [] instead of null — kmsd treats null and missing the
// same, but [] is the canonical wire form.
func dedupeSorted(ids []string) []string {
	if len(ids) == 0 {
		return []string{}
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// AuthorityRef points at the Kubernetes Secret holding the snapshot.
// Defaults to namespace=hanzo / name=kms-consensus-authority (matching
// the kmsd Deployment in universe/infra/k8s/kms/deployment.yaml).
type AuthorityRef struct {
	Namespace string
	Name      string
}

// LoadAuthority reads the current snapshot from the named Secret.
// Returns an empty snapshot + nil error when the Secret does not exist
// yet (first-boot path); any other error is reported verbatim so the
// caller can fail closed.
func LoadAuthority(ctx context.Context, c client.Client, ref AuthorityRef) (Snapshot, error) {
	var sec corev1.Secret
	err := c.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &sec)
	if err != nil {
		if k8serrors.IsNotFound(err) {
			return Snapshot{Validators: []string{}, Operators: []string{}}, nil
		}
		return Snapshot{}, fmt.Errorf("load authority secret %s/%s: %w", ref.Namespace, ref.Name, err)
	}
	raw, ok := sec.Data[AuthorityKey]
	if !ok || len(raw) == 0 {
		return Snapshot{Validators: []string{}, Operators: []string{}}, nil
	}
	var snap Snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		// A malformed Secret is not silently swallowed — the caller
		// surfaces it as an operator error and the next reconcile
		// rewrites the Secret with a valid canonical form.
		return Snapshot{}, fmt.Errorf("decode authority snapshot %s/%s[%s]: %w", ref.Namespace, ref.Name, AuthorityKey, err)
	}
	if snap.Validators == nil {
		snap.Validators = []string{}
	}
	if snap.Operators == nil {
		snap.Operators = []string{}
	}
	return snap, nil
}

// SaveAuthority writes the canonical form of snap into the Secret,
// creating it if absent and updating only on data change (the resourceVersion
// optimistic-concurrency path is implicit in client.Update).
//
// Returns (changed, err): changed=true when the Secret was created or
// its bytes differed from the prior canonical form; false on no-op.
func SaveAuthority(ctx context.Context, c client.Client, ref AuthorityRef, snap Snapshot) (bool, error) {
	canonical, err := snap.MarshalCanonical()
	if err != nil {
		return false, fmt.Errorf("marshal snapshot: %w", err)
	}

	var existing corev1.Secret
	getErr := c.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &existing)
	if getErr != nil && !k8serrors.IsNotFound(getErr) {
		return false, fmt.Errorf("get authority secret: %w", getErr)
	}
	if k8serrors.IsNotFound(getErr) {
		sec := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Namespace: ref.Namespace,
				Name:      ref.Name,
				Labels: map[string]string{
					"app.kubernetes.io/name":       "kms-consensus-authority",
					"app.kubernetes.io/managed-by": "kms-operator",
					"app.kubernetes.io/component":  "consensus-authority",
				},
				Annotations: map[string]string{
					"kms-operator.lux.network/snapshot-source": "consensus-bootstrap",
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{AuthorityKey: canonical},
		}
		if err := c.Create(ctx, sec); err != nil {
			return false, fmt.Errorf("create authority secret: %w", err)
		}
		return true, nil
	}

	// Update only when the canonical bytes differ.
	if existingBytes, ok := existing.Data[AuthorityKey]; ok && string(existingBytes) == string(canonical) {
		return false, nil
	}
	if existing.Data == nil {
		existing.Data = map[string][]byte{}
	}
	existing.Data[AuthorityKey] = canonical
	if existing.Annotations == nil {
		existing.Annotations = map[string]string{}
	}
	existing.Annotations["kms-operator.lux.network/snapshot-source"] = "consensus-bootstrap"
	if err := c.Update(ctx, &existing); err != nil {
		return false, fmt.Errorf("update authority secret: %w", err)
	}
	return true, nil
}
