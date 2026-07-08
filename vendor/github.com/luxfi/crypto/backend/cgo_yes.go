// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package backend

// cgoLinked reports whether this package was built with CGO_ENABLED=1.
// When true, the C-backed dispatch paths in luxfi/crypto (libluxcrypto,
// libsecp256k1, blst, ckzg, ...) can be linked at runtime.
const cgoLinked = true
