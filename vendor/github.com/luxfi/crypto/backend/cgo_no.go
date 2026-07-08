// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo

package backend

// cgoLinked is false: CGO_ENABLED=0 at build time so no C-backed dispatch
// path is reachable in this binary. Resolve() will never return CGo.
const cgoLinked = false
