package kmsapi

import (
	"testing"
)

func TestIsZAPHost(t *testing.T) {
	cases := []struct {
		host string
		want bool
	}{
		{"http://kms.hanzo.ai", false},
		{"https://kms.hanzo.ai/api", false},
		{"kms.hanzo.svc.cluster.local", false},
		{"", false},
		{"zap://kms.hanzo.svc:9999", true},
		{"ZAP://Kms.Hanzo.Svc:9999", true}, // case-insensitive
		{"zap+mdns://_kms._tcp", true},
		{"  zap://kms:9999  ", true}, // whitespace tolerated
	}
	for _, c := range cases {
		t.Run(c.host, func(t *testing.T) {
			if got := IsZAPHost(c.host); got != c.want {
				t.Fatalf("IsZAPHost(%q) = %v, want %v", c.host, got, c.want)
			}
		})
	}
}

func TestClientImplementsTransport(t *testing.T) {
	var _ Transport = (*Client)(nil)
}
