// Package util/transport.go: shared KMS transport selector.
//
// Both reconcilers (KMSSecret, KMSPushSecret) need to pick between the
// HTTP and ZAP transports at ResourceVariables construction time. The
// selection rule is identical, so the factory lives here instead of
// being duplicated per package.
package util

import (
	"os"
	"strings"

	"github.com/hanzoai/kms-operator/packages/kmsapi"
	"github.com/hanzoai/kms-operator/packages/kmszap"
)

// BuildTransport returns either a kmsapi.Client (HTTP) or a
// kmszap.Client (ZAP) depending on the host scheme.
//
// HTTP: any URL beginning with http:// or https:// (default).
// ZAP:  any URL beginning with zap:// (direct address) or zap+mdns://
//       (mDNS discovery).
//
// ZAP requires the operator to register its NodeID in the kmsd ACL
// (KMS_ZAP_ACL) with the appropriate role + path prefix; misconfigured
// ACL surfaces as forbidden on the first GetSecret call. The NodeID
// itself is read from KMS_OPERATOR_ZAP_NODE_ID, with a safe-by-default
// fallback that only works when the server runs in open mode.
//
// Returns kmsapi.Transport unconditionally — there is no nil-return
// path. CA-bundle parse failures fall back to a system-roots-only
// client; the subsequent request will surface the underlying problem
// via the controller's normal error reporting.
func BuildTransport(host, caCertPEM, userAgent string) kmsapi.Transport {
	if kmsapi.IsZAPHost(host) {
		return kmszap.New(kmszap.Config{
			NodeID: zapNodeIDFromEnv(),
		})
	}
	cli, err := kmsapi.New(kmsapi.Config{
		CACertPEM: caCertPEM,
		UserAgent: userAgent,
	})
	if err != nil {
		cli, _ = kmsapi.New(kmsapi.Config{UserAgent: userAgent})
	}
	return cli
}

// zapNodeIDFromEnv resolves the NodeID this operator presents on
// outbound ZAP connections. The ACL on the KMS server side binds this
// NodeID to (role, path-prefix). Defaults to "kms-operator" when the
// env var is unset — only safe when KMS_ZAP_ACL is also unset (open
// mode); production deployments MUST set both.
func zapNodeIDFromEnv() string {
	if id := strings.TrimSpace(os.Getenv("KMS_OPERATOR_ZAP_NODE_ID")); id != "" {
		return id
	}
	return "kms-operator"
}
