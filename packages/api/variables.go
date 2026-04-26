// Package api holds the cross-controller configuration shared by every
// reconciler — the canonical luxfi/kms host, an optional custom CA, and
// the User-Agent string sent on every outbound request.
//
// All HTTP work itself lives in packages/kmsapi, which targets the
// canonical /v1/kms/* surface served by ~/work/hanzo/kms cmd/kmsd. This
// package owns no transport state.
package api

import "os"

// USER_AGENT_NAME identifies the operator on every outbound request. KMS
// audit rows store this verbatim under the actor row.
const USER_AGENT_NAME = "kms-operator"

// API_HOST_URL is the canonical luxfi/kms endpoint. Override per-deployment
// via the KMS_API_HOST_URL env var, per-cluster via the kms-config
// ConfigMap, or per-resource via spec.hostAPI on the KMSSecret /
// KMSPushSecret CR.
//
// kmsd serves all routes at the root; the legacy "/api" suffix is stripped
// at use-site by kmsapi.NormaliseHost.
var API_HOST_URL string

// API_CA_CERTIFICATE is an optional PEM bundle trusted in addition to the
// system roots. Set per-resource via spec.tls.caRef.
var API_CA_CERTIFICATE string

func init() {
	if url := os.Getenv("KMS_API_HOST_URL"); url != "" {
		API_HOST_URL = url
	} else {
		API_HOST_URL = "https://kms.hanzo.ai"
	}
	if ca := os.Getenv("KMS_API_CA_CERTIFICATE"); ca != "" {
		API_CA_CERTIFICATE = ca
	}
}
