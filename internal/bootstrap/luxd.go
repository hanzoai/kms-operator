// Copyright (C) 2026, Hanzo Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// luxd.go — minimal JSON-RPC client for the luxd Platform Chain.
// Pulls the current primary-network validator set so the kms-operator
// can stamp it into kms-consensus-authority as the read authority.
//
// Why not the LuxNetwork CRD? Two reasons:
//
//  1. LuxNetwork lives in the luxfi-operator chart and reflects the
//     desired state of the cluster (validator pods to run), not the
//     consensus authority (current NodeIDs accepting blocks). Reading
//     it would conflate desired with live.
//
//  2. The hanzo-k8s cluster does not run luxd; luxd runs on lux-k8s.
//     The KMS authority needs the LIVE validator set from luxd's P-Chain
//     RPC, which is reachable via the configured LUXD_RPC_URL.
//
// JSON-RPC method: platform.getCurrentValidators. Response shape:
//
//	{
//	  "result": {
//	    "validators": [
//	      {"nodeID": "NodeID-…", … },
//	      …
//	    ]
//	  }
//	}
//
// Anything else (HTTP failure, JSON parse failure, empty validator set)
// is propagated to the caller; the caller's fail-closed policy keeps
// the prior Secret untouched.

package bootstrap

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultLuxdRPCURL is the in-cluster default for the hanzo-side
// operator. Override at boot via LUXD_RPC_URL. PChainPath is appended
// automatically.
//
// Port 9630, not 9650: `svc/luxd-headless` in lux-mainnet publishes
// http:9630 and staking:9631. 9650 is lux-DEVNET's http port, so the
// previous default could never connect on mainnet — every reconcile
// logged "luxd unreachable" and kms-consensus-authority was left
// untouched from 2026-03 onward.
const DefaultLuxdRPCURL = "http://luxd-headless.lux-mainnet.svc.cluster.local:9630"

// PChainPath is luxd's P-Chain JSON-RPC route.
//
// NOT "/ext/bc/P". This luxd is /v1-only — every /ext path returns 404
// (verified live: /ext/bc/P -> 404, /v1/bc/P -> 200 with the validator
// set). A 404 here is silent: GetCurrentValidators fails, the authority
// snapshot is never refreshed, and the only symptom is a 401 on an
// unrelated KMSSecret.
const PChainPath = "/v1/bc/P"

// LuxdClient queries a luxd node's Platform Chain RPC.
//
// Single concrete impl: the operator does not need provider polymorphism
// here. Tests inject a stub luxd via the *http.Client field.
type LuxdClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

// NewLuxdClient returns a client configured for baseURL. Empty baseURL
// uses DefaultLuxdRPCURL.
func NewLuxdClient(baseURL string) *LuxdClient {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = DefaultLuxdRPCURL
	}
	return &LuxdClient{
		BaseURL: strings.TrimRight(baseURL, "/"),
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// rpcRequest matches the luxd JSON-RPC wire envelope.
type rpcRequest struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      int                    `json:"id"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type validatorEntry struct {
	NodeID string `json:"nodeID"`
}

type currentValidatorsResult struct {
	Validators []validatorEntry `json:"validators"`
}

type rpcResponse struct {
	JSONRPC string                  `json:"jsonrpc"`
	ID      int                     `json:"id"`
	Result  currentValidatorsResult `json:"result"`
	Error   *rpcError               `json:"error,omitempty"`
}

// GetCurrentValidators returns the NodeIDs of the primary-network's
// current validator set. The strings are returned as luxd reports them
// (e.g. "NodeID-abc…") and consumed verbatim by kmsd's
// ids.NodeIDFromString.
func (l *LuxdClient) GetCurrentValidators(ctx context.Context) ([]string, error) {
	url := l.BaseURL + PChainPath
	reqBody := rpcRequest{
		JSONRPC: "2.0",
		ID:      1,
		Method:  "platform.getCurrentValidators",
		Params:  map[string]interface{}{},
	}
	encoded, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("encode rpc request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(encoded))
	if err != nil {
		return nil, fmt.Errorf("build rpc request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := l.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("luxd unreachable at %s: %w", url, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read rpc response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("luxd rpc %s returned status %d: %s", url, resp.StatusCode, truncate(string(body), 256))
	}

	var decoded rpcResponse
	if err := json.Unmarshal(body, &decoded); err != nil {
		return nil, fmt.Errorf("decode rpc response: %w", err)
	}
	if decoded.Error != nil {
		return nil, fmt.Errorf("luxd rpc error %d: %s", decoded.Error.Code, decoded.Error.Message)
	}
	if len(decoded.Result.Validators) == 0 {
		return nil, errors.New("luxd reported zero validators (refusing to stamp empty authority)")
	}

	out := make([]string, 0, len(decoded.Result.Validators))
	for _, v := range decoded.Result.Validators {
		id := strings.TrimSpace(v.NodeID)
		if id == "" {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

// truncate clips s to n bytes for diagnostic error messages.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
