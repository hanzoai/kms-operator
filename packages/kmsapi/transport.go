// Package kmsapi/transport.go defines the abstract transport contract
// shared by the HTTP and ZAP client implementations.
//
// This file is the seam Track B added so reconcilers can call a single
// Transport interface instead of a concrete *Client. The existing
// kmsapi.Client (HTTP/JSON) implements it; the kmszap.Client (ZAP
// binary) in packages/kmszap implements it too, with one carve-out:
//
//   - HTTP login: clientId/clientSecret -> bearer token via IAM proxy.
//     The Transport interface returns the bearer as a string.
//
//   - ZAP "login": there is no IAM bearer over ZAP. The peer identity
//     is the ZAP NodeID, fixed at handshake time, authorised via the
//     kmsd-side ACL (`KMS_ZAP_ACL`). Login() therefore returns a
//     synthetic token of the form "zap:<nodeID>" — present so the
//     reconciler's existing token-cache stays meaningful but otherwise
//     opaque. Subsequent GetSecret calls on the ZAP transport ignore
//     this token and rely on the underlying ZAP connection's NodeID.
//
// Why not unify behind one auth model: the ZAP wire format predates
// the IAM bridge and the bridge is "open" per ~/work/hanzo/kms/CLAUDE.md
// (the ZAP schema only formalises Health today). Adding IAM-over-ZAP is
// a wider IAM<->ZAP integration project; the operator can use the
// existing NodeID ACL model in the meantime, which is sufficient for
// in-cluster service-to-service.
package kmsapi

import (
	"context"
	"strings"
)

// Transport is the contract every kms client implementation satisfies.
// The HTTP-side methods on *Client (Login, LoginCached, GetSecret,
// CreateSecret, UpdateSecret, DeleteSecret, InvalidateToken) match
// this interface exactly; the ZAP-side wrapper in packages/kmszap
// adapts the ZAP opcodes to the same shape.
//
// All methods take an explicit context.Context. Implementations MUST
// honour ctx.Done() — operator reconciles cancel aggressively when
// the CR changes mid-flight.
type Transport interface {
	// Login mints a fresh bearer (HTTP) or returns a NodeID-bound
	// synthetic token (ZAP). The host argument is informational on
	// the ZAP path (the connection is already established).
	Login(ctx context.Context, host, clientID, clientSecret string) (LoginResponse, error)

	// LoginCached returns a token without minting if one is fresh
	// in the cache. Implementations MAY return the same opaque
	// string repeatedly for the lifetime of the underlying
	// transport handle.
	LoginCached(ctx context.Context, host, clientID, clientSecret string) (string, error)

	// InvalidateToken drops any cached bearer for (host, clientID,
	// clientSecret). ZAP implementations may make this a no-op since
	// the synthetic token has no expiry.
	InvalidateToken(host, clientID, clientSecret string)
	InvalidateBearer(host, token string)

	// GetSecret reads a secret at scope (org, env, path, name).
	// path may be empty (root scope).
	GetSecret(ctx context.Context, host, token, org, env, path, name string) (SecretResponse, error)

	// CreateSecret POST-upserts a secret. Returns the new version.
	CreateSecret(ctx context.Context, host, token, org, env, path, name, value string) (int64, error)

	// UpdateSecret PATCHes a secret with a CAS guard. expectedVersion
	// < 0 disables CAS (HTTP refuses; ZAP allows). Returns the new
	// version. HTTP returns ErrVersionConflict on 409.
	UpdateSecret(ctx context.Context, host, token, org, env, path, name, value string, expectedVersion int64) (int64, error)

	// DeleteSecret removes a secret. Returns ErrNotFound if absent.
	DeleteSecret(ctx context.Context, host, token, org, env, path, name string) error
}

// IsZAPHost reports whether host looks like a ZAP endpoint —
// "zap://kms.hanzo.svc:9999" or "zap+mdns://_kms._tcp". The HTTP
// client rejects these; the ZAP wrapper accepts them. Callers use
// this to pick the transport at reconcile time.
func IsZAPHost(host string) bool {
	h := strings.ToLower(strings.TrimSpace(host))
	return strings.HasPrefix(h, "zap://") || strings.HasPrefix(h, "zap+mdns://")
}

// Compile-time interface check for the HTTP client.
var _ Transport = (*Client)(nil)
