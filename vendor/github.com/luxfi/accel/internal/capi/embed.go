//go:build cgo

// Package capi — embed the public C header so `go mod vendor` carries it
// into downstream consumers' vendor trees. Without an embed reference, the
// vendor tool strips non-Go files from internal/capi/include/, breaking
// fresh-clone builds of vendored consumers (luxfi/kms, luxfi/node).
//
// The embedded file is the same physical header that capi.go's CFLAGS
// `-I${SRCDIR}/include` exposes to cgo; we just need the embed directive
// so the build system keeps it on disk after vendoring.
package capi

import _ "embed"

//go:embed include/lux/accel/c_api.h
var _cApiHeader string

var _ = _cApiHeader
