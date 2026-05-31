// Package kmszap tests focus on the pure helpers that do not need a
// live luxfi/zap node. Round-trip integration tests against a real
// kmsd ZAP server live in the kms-operator e2e suite.
package kmszap

import (
	"strings"
	"testing"

	"github.com/hanzoai/kms-operator/packages/kmsapi"
)

func TestParsePeerAddr(t *testing.T) {
	cases := []struct {
		name    string
		host    string
		want    string
		wantErr bool
	}{
		{name: "direct addr", host: "zap://kms.hanzo.svc.cluster.local:9999", want: "kms.hanzo.svc.cluster.local:9999"},
		{name: "ip + port", host: "zap://10.0.0.1:9999", want: "10.0.0.1:9999"},
		{name: "mdns sentinel", host: "zap+mdns://_kms._tcp", want: ""},
		{name: "case-insensitive scheme", host: "ZAP://Kms:9999", want: "Kms:9999"},
		{name: "missing scheme", host: "kms:9999", wantErr: true},
		{name: "empty", host: "", wantErr: true},
		{name: "wrong scheme", host: "http://kms:8443", wantErr: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parsePeerAddr(c.host)
			if c.wantErr {
				if err == nil {
					t.Fatalf("want error, got %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parsePeerAddr(%q) = err %v, want %q", c.host, err, c.want)
			}
			if got != c.want {
				t.Fatalf("parsePeerAddr(%q) = %q, want %q", c.host, got, c.want)
			}
		})
	}
}

func TestSyntheticToken(t *testing.T) {
	c := New(Config{NodeID: "my-op"})
	tok := c.syntheticToken()
	if tok != "zap:my-op" {
		t.Fatalf("syntheticToken = %q, want %q", tok, "zap:my-op")
	}
	anon := New(Config{}).syntheticToken()
	if anon != "zap:anonymous" {
		t.Fatalf("anon = %q, want %q", anon, "zap:anonymous")
	}
}

func TestValidateInputsRejectsBadScope(t *testing.T) {
	cases := []struct {
		name string
		org  string
		env  string
		path string
		key  string
		want string
	}{
		{name: "empty org", env: "prod", key: "k", want: "org is required"},
		{name: "empty env", org: "hanzo", key: "k", want: "env is required"},
		{name: "empty name", org: "hanzo", env: "prod", want: "name is required"},
		{name: "long org", org: strings.Repeat("a", kmsapi.MaxSlugLen+1), env: "prod", key: "k", want: "org > "},
		{name: "long env", org: "hanzo", env: strings.Repeat("a", kmsapi.MaxSlugLen+1), key: "k", want: "env > "},
		{name: "long path", org: "hanzo", env: "prod", path: strings.Repeat("a", kmsapi.MaxPathLen+1), key: "k", want: "path > "},
		{name: "long key", org: "hanzo", env: "prod", key: strings.Repeat("a", kmsapi.MaxKeyLen+1), want: "name > "},
		{name: "nul in org", org: "hanzo\x00", env: "prod", key: "k", want: "control bytes"},
		{name: "nul in env", org: "hanzo", env: "prod\x00", key: "k", want: "control bytes"},
		{name: "nul in path", org: "hanzo", env: "prod", path: "x\x00", key: "k", want: "control bytes"},
		{name: "nul in name", org: "hanzo", env: "prod", key: "k\x00", want: "control bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := validateInputs(c.org, c.env, c.path, c.key)
			if err == nil {
				t.Fatalf("want error, got nil")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err %q does not contain %q", err.Error(), c.want)
			}
		})
	}
}

func TestInvalidateTokenIsNoOp(t *testing.T) {
	c := New(Config{NodeID: "ut-node"})
	// Should not panic, should not change anything observable.
	c.InvalidateToken("any-host", "id", "secret")
	c.InvalidateToken("", "", "")
}

func TestInterfaceCompliance(t *testing.T) {
	var _ kmsapi.Transport = (*Client)(nil)
}

func TestCloseIsIdempotent(t *testing.T) {
	c := New(Config{})
	c.Close()
	c.Close() // second call should not panic
}
