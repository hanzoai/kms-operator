// Copyright 2026 Hanzo AI, Inc. All rights reserved.
// SPDX-License-Identifier: MIT

package bootstrap

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestGetCurrentValidators_UsesV1PChainPath pins the ROUTE, not just the constant.
//
// luxd is /v1-only: /v1/bc/P returns 404 and /v1/bc/P returns the validator set
// (verified against lux-mainnet). A 404 here is silent — GetCurrentValidators fails,
// the authority snapshot is never refreshed, and the only operator-visible symptom is
// a 401 "invalid credentials" on unrelated KMSSecret resources. lux-k8s sat that way
// with 50 of 53 secrets unsynced.
func TestGetCurrentValidators_UsesV1PChainPath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"validators":[{"nodeID":"NodeID-abc"}]}}`))
	}))
	defer srv.Close()

	c := &LuxdClient{BaseURL: srv.URL, HTTPClient: srv.Client()}
	got, err := c.GetCurrentValidators(context.Background())
	if err != nil {
		t.Fatalf("GetCurrentValidators: %v", err)
	}
	if gotPath != PChainPath {
		t.Fatalf("requested path = %q, want %q", gotPath, PChainPath)
	}
	if gotPath != "/v1/bc/P" {
		t.Fatalf("PChainPath = %q, want /v1/bc/P — /ext/* is dead on this luxd", gotPath)
	}
	if len(got) != 1 || got[0] != "NodeID-abc" {
		t.Fatalf("validators = %v, want [NodeID-abc]", got)
	}
}

// TestDefaultLuxdRPCURL_UsesMainnetHTTPPort pins the port. svc/luxd-headless in
// lux-mainnet publishes http:9630; 9650 is lux-DEVNET's port, so the old default could
// never connect and every reconcile logged "luxd unreachable".
func TestDefaultLuxdRPCURL_UsesMainnetHTTPPort(t *testing.T) {
	if !strings.HasSuffix(DefaultLuxdRPCURL, ":9630") {
		t.Fatalf("DefaultLuxdRPCURL = %q, want it to end :9630 (9650 is devnet)", DefaultLuxdRPCURL)
	}
	if strings.Contains(DefaultLuxdRPCURL, "9650") {
		t.Fatalf("DefaultLuxdRPCURL still points at the devnet port: %q", DefaultLuxdRPCURL)
	}
}
