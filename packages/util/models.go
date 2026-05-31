// Package util/models.go: per-CR runtime variables shared across
// reconcile invocations.
package util

import (
	"context"

	"github.com/hanzoai/kms-operator/packages/kmsapi"
)

// ResourceVariables is the per-CR cached runtime state. It is keyed
// by CR UID and re-used across reconciles to keep the kmsapi token
// cache warm and avoid login storms on a 401 loop.
//
// KMSClient is the transport interface (HTTP or ZAP). The reconciler
// picks the concrete implementation based on host scheme:
//
//	"http(s)://…"             → kmsapi.Client (JSON over HTTP)
//	"zap://host:port" or
//	"zap+mdns://_kms._tcp"    → kmszap.Client (binary ZAP wire)
type ResourceVariables struct {
	KMSClient   kmsapi.Transport
	CancelCtx   context.CancelFunc
	AuthDetails AuthenticationDetails
}
