// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import "github.com/luxfi/crypto/internal/gpuhost"

// gpuLinked reports whether the GPU substrate is reachable right now.
// The first call triggers a one-time accel.Init() inside gpuhost; the
// answer is then cached for the lifetime of the process.
//
// Returns false when:
//   - the binary was built without cgo (accel.Init returns ErrNoBackends)
//   - accel initialised but found no Metal / CUDA / WebGPU device
//   - the accel.Session allocation failed (driver / permission / OOM)
func gpuLinked() bool { return gpuhost.Available() }
