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
type ResourceVariables struct {
	KMSClient   *kmsapi.Client
	CancelCtx   context.CancelFunc
	AuthDetails AuthenticationDetails
}
