package api

import "os"

// API_HOST_URL is the default KMS API endpoint.
// Override per-deployment via KMS_API_HOST_URL env var,
// per-cluster via kms-config ConfigMap, or per-resource via spec.hostAPI.
var API_HOST_URL string
var API_CA_CERTIFICATE string

func init() {
	if url := os.Getenv("KMS_API_HOST_URL"); url != "" {
		API_HOST_URL = url
	} else {
		API_HOST_URL = "https://kms.hanzo.ai/api"
	}
	if ca := os.Getenv("KMS_API_CA_CERTIFICATE"); ca != "" {
		API_CA_CERTIFICATE = ca
	}
}
