// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// kms_authority.go — the kms-consensus-authority reconciliation loop.
//
// This file owns:
//
//   - Operator self-identity bootstrap (kms-operator-mnemonic → NodeID).
//   - Per-service identity ensure (one mnemonic Secret per KMSSecret /
//     KMSPushSecret CR that references one, or the default name pattern
//     "<crname>-mnemonic" in the CR namespace when not referenced).
//   - Periodic TTL reconcile that re-reads luxd's validator set and
//     stamps it onto kms-consensus-authority.
//
// The Reconciler implements sigs.k8s.io/controller-runtime/pkg/manager
// Runnable so main.go can register it via mgr.Add(). It runs in its own
// goroutine outside the standard Reconcile-per-CR machinery; the
// per-service hook (EnsureServiceIdentity) is called inline from the
// KMSSecret / KMSPushSecret Reconcile() paths so a CR addition takes
// effect within one reconciliation tick rather than after the next TTL
// expiry.

package bootstrap

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	"sigs.k8s.io/controller-runtime/pkg/client"

	corev1 "k8s.io/api/core/v1"
)

// Config bundles the env-driven settings the Reconciler depends on.
// All values resolve at boot from environment variables; the runtime
// path holds no mutable config state.
type Config struct {
	// AuthorityRef points at the kms-consensus-authority Secret. The
	// Secret MUST be in the same namespace as the kmsd Deployment that
	// mounts it (default "hanzo"); see universe/infra/k8s/kms/deployment.yaml.
	AuthorityRef AuthorityRef

	// OperatorMnemonicRef points at the operator's own mnemonic
	// Secret. Lives co-located with AuthorityRef so a namespace wipe
	// rotates the operator identity in lockstep.
	OperatorMnemonicRef MnemonicRef

	// OperatorMnemonicEnv is the optional KMS_OPERATOR_MNEMONIC env
	// value used only when OperatorMnemonicRef points at a missing
	// Secret (first boot). Empty string disables the env fallback —
	// the operator generates fresh entropy in that case.
	OperatorMnemonicEnv string

	// OperatorServicePath is the canonical service identity path the
	// operator derives its NodeID under. Defaults to
	// "hanzo/kms-operator"; override via KMS_OPERATOR_SERVICE_PATH.
	OperatorServicePath string

	// LuxdRPCURL is the upstream luxd Platform Chain RPC base. Empty
	// → DefaultLuxdRPCURL. The validator set fetched here becomes the
	// `validators` field of the authority snapshot.
	LuxdRPCURL string

	// TTL is the cadence on which the Reconciler re-fetches the
	// validator set from luxd and re-stamps the Secret. 0 → 30s.
	TTL time.Duration

	// DefaultMnemonicNamespace is where per-service mnemonic Secrets
	// land when a KMSSecret CR does not declare its own
	// spec.mnemonicSecretRef. Defaults to AuthorityRef.Namespace so
	// every mnemonic lives in the same namespace as kmsd.
	DefaultMnemonicNamespace string
}

const (
	envAuthorityNamespace       = "KMS_AUTHORITY_NAMESPACE"
	envAuthoritySecret          = "KMS_AUTHORITY_SECRET"
	envOperatorMnemonicSecret   = "KMS_OPERATOR_MNEMONIC_SECRET"
	envOperatorMnemonicEnv      = "KMS_OPERATOR_MNEMONIC"
	envOperatorServicePath      = "KMS_OPERATOR_SERVICE_PATH"
	envLuxdRPCURL               = "LUXD_RPC_URL"
	envConsensusTTL             = "KMS_CONSENSUS_TTL"
	envDefaultMnemonicNamespace = "KMS_MNEMONIC_NAMESPACE"
	defaultAuthorityNamespace   = "hanzo"
	defaultAuthoritySecret      = "kms-consensus-authority"
	defaultOperatorMnemonicName = "kms-operator-mnemonic"
	defaultOperatorServicePath  = "hanzo/kms-operator"
	defaultTTL                  = 30 * time.Second
	mnemonicComponentLabelKey   = "app.kubernetes.io/component"
	mnemonicComponentLabelValue = "service-mnemonic"
)

// LoadConfigFromEnv resolves the Reconciler config from environment
// variables. Pure function — no I/O. Errors are returned for malformed
// values; defaults fill in for absent variables.
func LoadConfigFromEnv() (Config, error) {
	authNS := strings.TrimSpace(os.Getenv(envAuthorityNamespace))
	if authNS == "" {
		authNS = defaultAuthorityNamespace
	}
	authName := strings.TrimSpace(os.Getenv(envAuthoritySecret))
	if authName == "" {
		authName = defaultAuthoritySecret
	}
	opSecret := strings.TrimSpace(os.Getenv(envOperatorMnemonicSecret))
	if opSecret == "" {
		opSecret = defaultOperatorMnemonicName
	}
	opPath := strings.TrimSpace(os.Getenv(envOperatorServicePath))
	if opPath == "" {
		opPath = defaultOperatorServicePath
	}
	mnemNS := strings.TrimSpace(os.Getenv(envDefaultMnemonicNamespace))
	if mnemNS == "" {
		mnemNS = authNS
	}
	ttl := defaultTTL
	if v := strings.TrimSpace(os.Getenv(envConsensusTTL)); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return Config{}, fmt.Errorf("%s=%q: %w", envConsensusTTL, v, err)
		}
		if d <= 0 {
			return Config{}, fmt.Errorf("%s=%q: must be > 0", envConsensusTTL, v)
		}
		ttl = d
	}
	return Config{
		AuthorityRef: AuthorityRef{
			Namespace: authNS,
			Name:      authName,
		},
		OperatorMnemonicRef: MnemonicRef{
			Namespace: authNS,
			Name:      opSecret,
		},
		OperatorMnemonicEnv:      strings.TrimSpace(os.Getenv(envOperatorMnemonicEnv)),
		OperatorServicePath:      opPath,
		LuxdRPCURL:               strings.TrimSpace(os.Getenv(envLuxdRPCURL)),
		TTL:                      ttl,
		DefaultMnemonicNamespace: mnemNS,
	}, nil
}

// Reconciler is the kms-consensus-authority reconciliation loop. Safe
// for concurrent use after NewReconciler.
type Reconciler struct {
	client client.Client
	logger logr.Logger
	cfg    Config
	luxd   *LuxdClient

	mu sync.Mutex
	// operatorNodeID caches the derived NodeID for the operator's own
	// service identity. Computed lazily on first reconcile.
	operatorNodeID string
}

// NewReconciler wires a Reconciler. The provided luxd client is used
// verbatim; pass nil to construct one from cfg.LuxdRPCURL.
func NewReconciler(c client.Client, logger logr.Logger, cfg Config, luxd *LuxdClient) *Reconciler {
	if luxd == nil {
		luxd = NewLuxdClient(cfg.LuxdRPCURL)
	}
	return &Reconciler{
		client: c,
		logger: logger.WithName("kms-authority"),
		cfg:    cfg,
		luxd:   luxd,
	}
}

// Start implements sigs.k8s.io/controller-runtime/pkg/manager Runnable.
// Runs the bootstrap pass once, then reconciles on TTL until ctx done.
func (r *Reconciler) Start(ctx context.Context) error {
	r.logger.Info("starting kms-consensus-authority reconciler",
		"authority", fmt.Sprintf("%s/%s", r.cfg.AuthorityRef.Namespace, r.cfg.AuthorityRef.Name),
		"operatorMnemonic", fmt.Sprintf("%s/%s", r.cfg.OperatorMnemonicRef.Namespace, r.cfg.OperatorMnemonicRef.Name),
		"servicePath", r.cfg.OperatorServicePath,
		"ttl", r.cfg.TTL,
		"luxdRPC", r.luxd.BaseURL,
	)

	// Bootstrap pass — wires the operator's own identity even if luxd
	// is unreachable. Failure here does not crash the manager; the
	// next tick retries.
	if err := r.reconcileOnce(ctx); err != nil {
		r.logger.Error(err, "initial kms-authority reconcile failed (will retry)")
	}

	ticker := time.NewTicker(r.cfg.TTL)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			r.logger.Info("kms-consensus-authority reconciler stopping")
			return nil
		case <-ticker.C:
			if err := r.reconcileOnce(ctx); err != nil {
				r.logger.Error(err, "periodic kms-authority reconcile failed")
			}
		}
	}
}

// NeedLeaderElection ensures only the leader operator writes the
// authority Secret. Without this, every replica would race to update
// it on every tick.
func (r *Reconciler) NeedLeaderElection() bool { return true }

// reconcileOnce performs a single full pass: derive operator NodeID,
// scan mnemonic Secrets, fetch luxd validator set, compute snapshot,
// write only if changed.
func (r *Reconciler) reconcileOnce(ctx context.Context) error {
	operatorID, err := r.ensureOperatorIdentity(ctx)
	if err != nil {
		return fmt.Errorf("ensure operator identity: %w", err)
	}

	operatorIDs, operatorScopes, err := r.collectOperatorAuthority(ctx, operatorID)
	if err != nil {
		return fmt.Errorf("collect operator authority: %w", err)
	}

	validators, fetchErr := r.luxd.GetCurrentValidators(ctx)
	if fetchErr != nil {
		// Fail-closed: keep existing Secret intact, surface error
		// loudly. Operator membership may have changed but validator
		// freshness is the safety guarantee we refuse to weaken.
		r.logger.Error(fetchErr, "luxd unreachable; leaving kms-consensus-authority untouched",
			"luxdRPC", r.luxd.BaseURL)
		return fetchErr
	}

	// Least-privilege overlay. The WRITE (operator) authority is confined
	// per-service: each service NodeID may write only its own secret subtree
	// (<org>/<service>/*); the kms-operator itself stays unconfined (broad
	// write — it is the authority). The READ (validator) authority is left
	// FLAT (Validators nil): its members are the upstream luxd L1 consensus
	// set, which has no per-node secret subtree to confine to. Scoping the
	// READ authority to per-service subtrees — the change that would confine
	// a compromised SERVICE key's reads — depends on services becoming
	// scoped members of the read authority, an authority-placement decision
	// tracked separately (see LLM.md / task #53 handoff).
	snap := Snapshot{
		Validators: validators,
		Operators:  operatorIDs,
		Scopes: &AuthorityScopes{
			Operators: operatorScopes,
		},
	}
	changed, err := SaveAuthority(ctx, r.client, r.cfg.AuthorityRef, snap)
	if err != nil {
		return fmt.Errorf("save authority secret: %w", err)
	}
	if changed {
		r.logger.Info("kms-consensus-authority secret updated",
			"validators", len(validators),
			"operators", len(operatorIDs),
			"operatorScopes", len(operatorScopes),
		)
	}
	return nil
}

// ensureOperatorIdentity returns the operator's NodeID, deriving it
// (and persisting the underlying mnemonic Secret if absent) on first
// call. Cached for the lifetime of the Reconciler — the mnemonic does
// not rotate without an operator restart.
func (r *Reconciler) ensureOperatorIdentity(ctx context.Context) (string, error) {
	r.mu.Lock()
	cached := r.operatorNodeID
	r.mu.Unlock()
	if cached != "" {
		return cached, nil
	}

	mnemonic, src, err := LoadOrCreateMnemonic(ctx, r.client, r.cfg.OperatorMnemonicRef, r.cfg.OperatorMnemonicEnv)
	if err != nil {
		return "", err
	}
	nodeID, err := deriveNodeIDString(mnemonic, r.cfg.OperatorServicePath)
	if err != nil {
		return "", fmt.Errorf("derive operator identity (path=%q): %w", r.cfg.OperatorServicePath, err)
	}

	r.logger.V(1).Info("operator service identity ready",
		"mnemonicSource", src,
		"mnemonicSecret", fmt.Sprintf("%s/%s", r.cfg.OperatorMnemonicRef.Namespace, r.cfg.OperatorMnemonicRef.Name),
		"servicePath", r.cfg.OperatorServicePath,
		"nodeID", nodeID,
	)

	r.mu.Lock()
	r.operatorNodeID = nodeID
	r.mu.Unlock()
	return nodeID, nil
}

// collectOperatorAuthority walks every service-mnemonic Secret in the
// default mnemonic namespace and derives each one's NodeID. The result
// always includes the operator's own NodeID first.
//
// Service identities are derived under the canonical service path
// "hanzo/<secretname-without--mnemonic-suffix>" when no annotation
// provides an explicit path. Each Secret may carry an optional
// annotation `kms-operator.lux.network/service-path` with the
// canonical path the consumer was registered under.
func (r *Reconciler) collectOperatorAuthority(ctx context.Context, operatorNodeID string) ([]string, map[string]string, error) {
	componentSelector, _ := labels.NewRequirement(
		mnemonicComponentLabelKey,
		selection.Equals,
		[]string{mnemonicComponentLabelValue},
	)
	listOpts := []client.ListOption{
		client.InNamespace(r.cfg.DefaultMnemonicNamespace),
		client.MatchingLabelsSelector{Selector: labels.NewSelector().Add(*componentSelector)},
	}

	var list corev1.SecretList
	if err := r.client.List(ctx, &list, listOpts...); err != nil {
		return nil, nil, fmt.Errorf("list service-mnemonic secrets: %w", err)
	}

	out := []string{operatorNodeID}
	// The operator itself is unconfined (broad write). Every service NodeID
	// is confined to its own secret subtree. A non-nil scope map with every
	// member granted keeps the WRITE authority fail-closed for any future
	// member the operator forgets to grant.
	scopes := map[string]string{operatorNodeID: ""}
	for i := range list.Items {
		sec := &list.Items[i]
		// Skip the operator's own mnemonic — already in `out`.
		if sec.Namespace == r.cfg.OperatorMnemonicRef.Namespace && sec.Name == r.cfg.OperatorMnemonicRef.Name {
			continue
		}
		raw, ok := sec.Data[MnemonicKey]
		if !ok || len(raw) == 0 {
			r.logger.Info("skipping malformed mnemonic secret (no mnemonic data key)",
				"secret", fmt.Sprintf("%s/%s", sec.Namespace, sec.Name))
			continue
		}
		mnemonic := strings.TrimSpace(string(raw))
		path := servicePathFromSecret(sec)
		nodeID, err := deriveNodeIDString(mnemonic, path)
		if err != nil {
			r.logger.Error(err, "skipping mnemonic secret with invalid derivation",
				"secret", fmt.Sprintf("%s/%s", sec.Namespace, sec.Name),
				"servicePath", path)
			continue
		}
		out = append(out, nodeID)
		scopes[nodeID] = deriveServiceScope(path)
	}
	return out, scopes, nil
}

// deriveServiceScope returns the least-privilege secret-path prefix a
// service identity is confined to: its OWN subtree — the canonical service
// path itself. A service derived under "hanzo/commerce" may write only
// "hanzo/commerce" and its descendants, never a sibling
// ("hanzo/commerce-evil"), a parent ("hanzo"), or another org. This is the
// same value the NodeID was derived from, so the scope is authority-side
// (unspoofable by the caller). trimIdentityPath gives the canonical
// "/"-joined form the kmsd compares against.
func deriveServiceScope(servicePath string) string {
	return trimIdentityPath(servicePath)
}

// EnsureServiceIdentity is the per-CR hook the controllers call. It
// guarantees a mnemonic Secret exists for the given service path,
// generating one on first invocation. Returns the derived NodeID so
// the controller can surface it in CR status (NodeID only — the
// mnemonic stays in the Secret).
func (r *Reconciler) EnsureServiceIdentity(
	ctx context.Context,
	ref MnemonicRef,
	servicePath string,
) (string, error) {
	if ref.Namespace == "" {
		ref.Namespace = r.cfg.DefaultMnemonicNamespace
	}
	if ref.Name == "" {
		return "", fmt.Errorf("mnemonic ref name is required")
	}
	if strings.TrimSpace(servicePath) == "" {
		return "", fmt.Errorf("servicePath is required for %s/%s", ref.Namespace, ref.Name)
	}
	mnemonic, src, err := LoadOrCreateMnemonic(ctx, r.client, ref, "")
	if err != nil {
		return "", err
	}
	nodeID, err := deriveNodeIDString(mnemonic, servicePath)
	if err != nil {
		return "", fmt.Errorf("derive service identity (path=%q): %w", servicePath, err)
	}
	r.logger.V(1).Info("service identity ensured",
		"mnemonicSource", src,
		"mnemonicSecret", fmt.Sprintf("%s/%s", ref.Namespace, ref.Name),
		"servicePath", servicePath,
		"nodeID", nodeID,
	)

	// Stamp the canonical service path onto the Secret so a later
	// listing in collectOperatorAuthority derives the same NodeID
	// without needing the CR back-reference.
	if err := r.annotateServicePath(ctx, ref, servicePath); err != nil {
		// Annotation failure is a soft error — the NodeID is still
		// correct for the immediate caller; the next reconcile pass
		// will retry.
		r.logger.Error(err, "annotate service path", "secret", fmt.Sprintf("%s/%s", ref.Namespace, ref.Name))
	}
	return nodeID, nil
}

// annotateServicePath stamps the canonical service identity path onto
// the mnemonic Secret so the periodic reconcile derives the matching
// NodeID without consulting any CR.
func (r *Reconciler) annotateServicePath(ctx context.Context, ref MnemonicRef, path string) error {
	var sec corev1.Secret
	if err := r.client.Get(ctx, client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}, &sec); err != nil {
		return err
	}
	if sec.Annotations == nil {
		sec.Annotations = map[string]string{}
	}
	if existing := sec.Annotations[annotationServicePath]; existing == path {
		return nil
	}
	sec.Annotations[annotationServicePath] = path
	// Maintain the component label so collectOperatorAuthority's
	// listing picks it up.
	if sec.Labels == nil {
		sec.Labels = map[string]string{}
	}
	if sec.Labels[mnemonicComponentLabelKey] != mnemonicComponentLabelValue {
		sec.Labels[mnemonicComponentLabelKey] = mnemonicComponentLabelValue
	}
	return r.client.Update(ctx, &sec)
}

// annotationServicePath is the Secret annotation that carries the
// canonical service identity path. Persisted so a later listing in
// collectOperatorAuthority can derive the matching NodeID without
// needing the CR.
const annotationServicePath = "kms-operator.lux.network/service-path"

// servicePathFromSecret returns the canonical service path stamped on
// the Secret, falling back to a derived value when the annotation is
// absent.
//
// Fallback rule: strip the "-mnemonic" suffix from the Secret name
// (matching the default naming pattern) and prepend "hanzo/". So
// "hanzo-base-mnemonic" → "hanzo/hanzo-base". The fallback only fires
// for legacy Secrets created outside the EnsureServiceIdentity path.
func servicePathFromSecret(sec *corev1.Secret) string {
	if sec.Annotations != nil {
		if p := strings.TrimSpace(sec.Annotations[annotationServicePath]); p != "" {
			return p
		}
	}
	name := strings.TrimSuffix(sec.Name, "-mnemonic")
	if name == sec.Name {
		// No -mnemonic suffix — use the bare name.
		return "hanzo/" + name
	}
	return "hanzo/" + name
}
