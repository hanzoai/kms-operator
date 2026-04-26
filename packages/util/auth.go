// Package util/auth.go owns the controller-side authentication logic.
//
// The canonical luxfi/kms surface (~/work/hanzo/kms cmd/kmsd) accepts a
// single auth shape: clientId/clientSecret -> POST /v1/kms/auth/login ->
// bearer token. Every other auth method that the legacy SDK exposed
// (service tokens, service accounts, K8s/AWS/Azure/GCP machine
// identities) has no equivalent on the canonical server, so this
// package now models exactly one strategy: UniversalAuth.
//
// Forward break only — there are no fallbacks, no toggles, no
// "legacy-support" knobs. Every reconciler MUST present a
// universalAuth.credentialsRef pointing at a Kubernetes Secret that
// holds clientId / clientSecret.
package util

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/kms-operator/api/v1alpha1"
	"github.com/hanzoai/kms-operator/packages/kmsapi"
	corev1 "k8s.io/api/core/v1"
	authenticationv1 "k8s.io/api/authentication/v1"

	"github.com/aws/smithy-go/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// AuthStrategyType identifies the authentication strategy resolved at
// reconcile time. Only UNIVERSAL_MACHINE_IDENTITY is supported.
type AuthStrategyType string

// AuthStrategy enumerates the supported authentication strategies. The
// surface has been frozen to one entry on purpose; do not add new
// strategies without a corresponding canonical-server route.
var AuthStrategy = struct {
	UNIVERSAL_MACHINE_IDENTITY AuthStrategyType
}{
	UNIVERSAL_MACHINE_IDENTITY: "UNIVERSAL_MACHINE_IDENTITY",
}

// SecretCrdType identifies which CRD owns a reconcile call. Used for
// type-safe casts in the auth handler.
type SecretCrdType string

var SecretCrd = struct {
	KMS_SECRET      SecretCrdType
	KMS_PUSH_SECRET SecretCrdType
}{
	KMS_SECRET:      "KMS_SECRET",
	KMS_PUSH_SECRET: "KMS_PUSH_SECRET",
}

// SecretAuthInput carries the CR + its kind into the auth handler.
type SecretAuthInput struct {
	Secret interface{}
	Type   SecretCrdType
}

// AuthenticationDetails is the result of HandleUniversalAuth: a fresh
// bearer token, the host that minted it, and the scope (org / env /
// path / keys) the caller asked for. Reconcilers consume this directly
// without re-resolving credentials.
type AuthenticationDetails struct {
	AuthStrategy         AuthStrategyType
	BearerToken          string
	Host                 string
	MachineIdentityScope v1alpha1.MachineIdentityScopeInWorkspace
	SecretType           SecretCrdType
}

// ErrAuthNotApplicable signals that the supplied CR does not configure
// the strategy under inspection. The reconciler retries the next
// strategy in its list. With only one strategy left, this just means
// "no universalAuth.credentialsRef configured".
var ErrAuthNotApplicable = errors.New("authentication not applicable")

// HandleUniversalAuth resolves credentials, performs login (cached),
// and returns a bearer ready to be used against the canonical surface.
//
// Hardening:
//   - credentialsRef MUST live in the same namespace as the
//     reconciling CR. Cross-namespace reads are refused — the operator
//     SA's RBAC may grant it cluster-wide secret reads, and a tenant CR
//     in namespace A must not be able to spec a credentialsRef in a
//     privileged namespace it does not own.
//   - clientId / clientSecret are scanned for control bytes before
//     they leave the cluster. NUL is the only way a malicious CR-author
//     who controls the credentials Secret could smuggle a payload past
//     a downstream log scrubber, so we reject it here.
//
// A nil kms.Client falls back to a fresh on-demand instance — the
// production code path always supplies one.
func HandleUniversalAuth(
	ctx context.Context,
	reconcilerClient client.Client,
	secretCrd SecretAuthInput,
	host string,
	kmsClient *kmsapi.Client,
) (AuthenticationDetails, error) {

	var (
		credRef v1alpha1.KubeSecretReference
		scope   v1alpha1.MachineIdentityScopeInWorkspace
	)

	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		kmsSecret, ok := secretCrd.Secret.(v1alpha1.KMSSecret)
		if !ok {
			return AuthenticationDetails{}, errors.New("HandleUniversalAuth: not a KMSSecret")
		}
		credRef = kmsSecret.Spec.Authentication.UniversalAuth.CredentialsRef
		scope = kmsSecret.Spec.Authentication.UniversalAuth.SecretsScope
	case SecretCrd.KMS_PUSH_SECRET:
		kmsPushSecret, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret)
		if !ok {
			return AuthenticationDetails{}, errors.New("HandleUniversalAuth: not a KMSPushSecret")
		}
		credRef = kmsPushSecret.Spec.Authentication.UniversalAuth.CredentialsRef
	default:
		return AuthenticationDetails{}, fmt.Errorf("HandleUniversalAuth: unsupported CRD type %q", secretCrd.Type)
	}

	if credRef.SecretName == "" || credRef.SecretNamespace == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}

	// Same-namespace enforcement. The CR's namespace is the only place
	// the operator will read credentials from.
	crNS := crNamespace(secretCrd)
	if crNS != "" && credRef.SecretNamespace != crNS {
		return AuthenticationDetails{}, fmt.Errorf(
			"credentialsRef cross-namespace refused: CR in '%s' cannot read Secret from '%s'",
			crNS, credRef.SecretNamespace,
		)
	}

	creds, err := GetKMSUniversalAuthFromKubeSecret(ctx, reconcilerClient, credRef)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("HandleUniversalAuth: load credentialsRef: %w", err)
	}
	if creds.ClientId == "" || creds.ClientSecret == "" {
		return AuthenticationDetails{}, ErrAuthNotApplicable
	}
	if kmsapi.ContainsUnsafeControl(creds.ClientId) || kmsapi.ContainsUnsafeControl(creds.ClientSecret) {
		return AuthenticationDetails{}, errors.New("HandleUniversalAuth: credentialsRef contains control bytes")
	}

	if kmsClient == nil {
		var newErr error
		kmsClient, newErr = kmsapi.New(kmsapi.Config{})
		if newErr != nil {
			return AuthenticationDetails{}, fmt.Errorf("HandleUniversalAuth: build kms client: %w", newErr)
		}
	}

	token, err := kmsClient.LoginCached(ctx, host, creds.ClientId, creds.ClientSecret)
	if err != nil {
		return AuthenticationDetails{}, fmt.Errorf("HandleUniversalAuth: login: %w", err)
	}

	return AuthenticationDetails{
		AuthStrategy:         AuthStrategy.UNIVERSAL_MACHINE_IDENTITY,
		BearerToken:          token,
		Host:                 kmsapi.NormaliseHost(host),
		MachineIdentityScope: scope,
		SecretType:           secretCrd.Type,
	}, nil
}

func crNamespace(secretCrd SecretAuthInput) string {
	switch secretCrd.Type {
	case SecretCrd.KMS_SECRET:
		if v, ok := secretCrd.Secret.(v1alpha1.KMSSecret); ok {
			return v.Namespace
		}
	case SecretCrd.KMS_PUSH_SECRET:
		if v, ok := secretCrd.Secret.(v1alpha1.KMSPushSecret); ok {
			return v.Namespace
		}
	}
	return ""
}

// ── Service-account token issuance retained for K8s integrations ──
//
// The serviceaccount-token issuance flow below is still used by other
// in-tree controllers (ClusterGenerator etc.) and is independent of
// the KMS auth flow. Left in place to avoid churn unrelated to the
// luxfi/kms port.

func GetServiceAccountToken(
	k8sClient client.Client,
	namespace string,
	serviceAccountName string,
	autoCreateServiceAccountToken bool,
	serviceAccountTokenAudiences []string,
) (string, error) {

	if autoCreateServiceAccountToken {
		restClient, err := GetRestClientFromClient()
		if err != nil {
			return "", fmt.Errorf("failed to get REST client: %w", err)
		}

		tokenRequest := &authenticationv1.TokenRequest{
			Spec: authenticationv1.TokenRequestSpec{
				ExpirationSeconds: ptr.Int64(600),
			},
		}
		if len(serviceAccountTokenAudiences) > 0 {
			tokenRequest.Spec.Audiences = serviceAccountTokenAudiences
		}

		result := &authenticationv1.TokenRequest{}
		err = restClient.
			Post().
			Namespace(namespace).
			Resource("serviceaccounts").
			Name(serviceAccountName).
			SubResource("token").
			Body(tokenRequest).
			Do(context.Background()).
			Into(result)

		if err != nil {
			return "", fmt.Errorf("failed to create token: %w", err)
		}

		return result.Status.Token, nil
	}

	serviceAccount := &corev1.ServiceAccount{}
	err := k8sClient.Get(context.TODO(), client.ObjectKey{Name: serviceAccountName, Namespace: namespace}, serviceAccount)
	if err != nil {
		return "", err
	}

	if len(serviceAccount.Secrets) == 0 {
		return "", fmt.Errorf("no secrets found for service account %s", serviceAccountName)
	}

	secretName := serviceAccount.Secrets[0].Name

	secret := &corev1.Secret{}
	err = k8sClient.Get(context.TODO(), client.ObjectKey{Name: secretName, Namespace: namespace}, secret)
	if err != nil {
		return "", err
	}

	return string(secret.Data["token"]), nil
}
