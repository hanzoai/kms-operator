package util

import (
	"context"
	"testing"

	secretsv1 "github.com/hanzoai/kms-operator/api/v1"
	"github.com/hanzoai/kms-operator/packages/kmsapi"
)

// fakeTransport serves canned values keyed by secret name.
type fakeTransport struct {
	values map[string]string
}

func (f *fakeTransport) Login(context.Context, string, string, string) (kmsapi.LoginResponse, error) {
	return kmsapi.LoginResponse{AccessToken: "t"}, nil
}
func (f *fakeTransport) LoginCached(context.Context, string, string, string) (string, error) {
	return "t", nil
}
func (f *fakeTransport) InvalidateToken(string, string, string) {}
func (f *fakeTransport) GetSecret(_ context.Context, _, _, _, _, _, name string) (kmsapi.SecretResponse, error) {
	v, ok := f.values[name]
	if !ok {
		return kmsapi.SecretResponse{}, kmsapi.ErrNotFound
	}
	return kmsapi.SecretResponse{Value: v, Version: 1}, nil
}
func (f *fakeTransport) CreateSecret(context.Context, string, string, string, string, string, string, string) (int64, error) {
	return 1, nil
}
func (f *fakeTransport) UpdateSecret(context.Context, string, string, string, string, string, string, string, int64) (int64, error) {
	return 1, nil
}
func (f *fakeTransport) DeleteSecret(context.Context, string, string, string, string, string, string) error {
	return nil
}

// TestB64KeysDecodeOnProjection pins the binary convention: a key named
// "X.b64" is fetched by that name, base64-decoded, and projected as "X"
// with the exact raw bytes — so managed Secrets keep the byte contract
// their consumers expect (e.g. a raw 32-byte BLS signer key).
func TestB64KeysDecodeOnProjection(t *testing.T) {
	raw := []byte{0x00, 0x01, 0x1f, 0xff, 0x7f, 0x80, 0x0a} // control bytes + high bytes
	ft := &fakeTransport{values: map[string]string{
		"staker-0.crt":     "-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n",
		"signer-0.key.b64": "AAEf/3+ACg==", // base64 of raw
	}}
	scope := secretsv1.MachineIdentityScopeInWorkspace{
		ProjectSlug: "lux",
		EnvSlug:     "testnet",
		SecretsPath: "/staking",
		Keys:        []string{"staker-0.crt", "signer-0.key.b64"},
	}
	out, err := GetPlainTextSecretsViaMachineIdentity(context.Background(), ft, "https://kms.example", "tok", scope)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := map[string]string{}
	for _, s := range out {
		got[s.Key] = s.Value
	}
	if _, exists := got["signer-0.key.b64"]; exists {
		t.Fatalf(".b64 suffix must be stripped on projection")
	}
	if got["signer-0.key"] != string(raw) {
		t.Fatalf("signer-0.key bytes mangled: got %q want %q", got["signer-0.key"], raw)
	}
	if got["staker-0.crt"] == "" {
		t.Fatalf("plain key must pass through unchanged")
	}
}

// TestB64KeyInvalidBase64FailsClosed pins fail-closed: a .b64 value that
// does not decode fails the whole fetch rather than projecting garbage.
func TestB64KeyInvalidBase64FailsClosed(t *testing.T) {
	ft := &fakeTransport{values: map[string]string{"signer-0.key.b64": "not!!base64"}}
	scope := secretsv1.MachineIdentityScopeInWorkspace{
		ProjectSlug: "lux",
		EnvSlug:     "testnet",
		SecretsPath: "/staking",
		Keys:        []string{"signer-0.key.b64"},
	}
	if _, err := GetPlainTextSecretsViaMachineIdentity(context.Background(), ft, "https://kms.example", "tok", scope); err == nil {
		t.Fatalf("expected error for invalid base64, got nil")
	}
}
