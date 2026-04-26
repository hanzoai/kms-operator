// Package util/workspace.go was a thin wrapper over the legacy KMS
// /v1/workspace/{id} endpoint. The canonical luxfi/kms surface has no
// concept of a "workspace ID -> slug" lookup — orgs are addressed
// directly by slug under /v1/kms/orgs/{org}/secrets/...
//
// The file is intentionally empty in the package-level public API; it
// exists only to keep the package import path stable for
// any downstream consumers in the operator that import it
// transitively. Do not add new helpers here.
package util
