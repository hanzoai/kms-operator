// Package util/secrets.go: read-side helpers that turn a successful
// auth + scope into a slice of plaintext key/value pairs.
//
// The canonical luxfi/kms surface has no list endpoint — every value
// MUST be addressed by exact name. The caller therefore has to
// enumerate the expected keys on the CR via secretsScope.keys, and
// this helper fans out one GET per name. NotFound is treated as
// fatal: empty-fetch fail-closed, the controller refuses to project
// an empty Secret.
package util

import (
	"context"
	"errors"
	"fmt"

	"github.com/hanzoai/kms-operator/api/v1alpha1"
	"github.com/hanzoai/kms-operator/packages/kmsapi"
	"github.com/hanzoai/kms-operator/packages/model"
)

// GetPlainTextSecretsViaMachineIdentity fetches every key listed in
// secretsScope.keys from the canonical /v1/kms/orgs/{org}/secrets/...
// surface and returns them as a flat slice for the projection layer.
//
// Validation:
//   - secretsScope.keys MUST be non-empty (no list endpoint exists).
//   - Per-input bounds enforced via kmsapi.validateScope.
//   - Each value is scanned for control bytes; NUL or C0 fails the
//     entire reconcile rather than truncate downstream.
func GetPlainTextSecretsViaMachineIdentity(
	ctx context.Context,
	kmsClient *kmsapi.Client,
	host string,
	bearerToken string,
	scope v1alpha1.MachineIdentityScopeInWorkspace,
) ([]model.SingleEnvironmentVariable, error) {

	if kmsClient == nil {
		return nil, errors.New("GetPlainTextSecretsViaMachineIdentity: kms client is nil")
	}
	if bearerToken == "" {
		return nil, errors.New("GetPlainTextSecretsViaMachineIdentity: empty bearer token")
	}
	if scope.ProjectSlug == "" {
		return nil, errors.New("secretsScope.projectSlug is required")
	}
	if scope.EnvSlug == "" {
		return nil, errors.New("secretsScope.envSlug is required")
	}
	if len(scope.Keys) == 0 {
		return nil, errors.New(
			"secretsScope.keys is required (luxfi/kms has no list endpoint — enumerate explicitly)",
		)
	}
	if len(scope.Keys) > kmsapi.MaxKeysPerCR {
		return nil, fmt.Errorf("secretsScope.keys exceeds %d entries", kmsapi.MaxKeysPerCR)
	}

	scopePath := kmsapi.NormaliseScopePath(scope.SecretsPath)

	out := make([]model.SingleEnvironmentVariable, 0, len(scope.Keys))
	for _, key := range scope.Keys {
		if key == "" {
			return nil, errors.New("secretsScope.keys contains an empty entry")
		}
		resp, err := kmsClient.GetSecret(ctx, host, bearerToken, scope.ProjectSlug, scope.EnvSlug, scopePath, key)
		if err != nil {
			return nil, fmt.Errorf("fetch secret %q: %w", key, err)
		}
		out = append(out, model.SingleEnvironmentVariable{
			Key:        key,
			Value:      resp.Value,
			Type:       "shared",
			ID:         "", // canonical surface has no separate ID
			SecretPath: scope.SecretsPath,
		})
	}
	return out, nil
}
