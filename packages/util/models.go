package util

import (
	"context"

	kmsSdk "github.com/luxfi/kms-go"
)

type ResourceVariables struct {
	KMSClient kmsSdk.KMSClientInterface
	CancelCtx       context.CancelFunc
	AuthDetails     AuthenticationDetails
}
