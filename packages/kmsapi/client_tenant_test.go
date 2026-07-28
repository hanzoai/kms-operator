package kmsapi

import (
	"strings"
	"testing"
)

// The URL names no org (the token carries it), and a write ships the SAME
// normalized coordinate a read resolves — the two halves of the coordinate
// split that had pushes "succeed" at "/x" while every read missed at "x".
func TestBuildSecretURL_TenantShape(t *testing.T) {
	u, err := buildSecretURL("http://cloud.hanzo.svc:8000", "hanzo", "/iam-service-token", "IAM_SERVICE_TOKEN", "prod")
	if err != nil {
		t.Fatalf("buildSecretURL: %v", err)
	}
	if strings.Contains(u, "/orgs/") {
		t.Fatalf("URL names an org: %s", u)
	}
	want := "http://cloud.hanzo.svc:8000/v1/kms/secrets/iam-service-token/IAM_SERVICE_TOKEN?env=prod"
	if u != want {
		t.Fatalf("url = %s, want %s", u, want)
	}
}
