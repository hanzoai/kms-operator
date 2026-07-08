// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package accel exposes the canonical CPU + GPU paths into luxcpp/crypto.
//
// luxcpp/crypto is the single source of truth for native cryptographic
// implementations across the Lux/Hanzo/Zoo ecosystem. Go callers use this
// package; it CGO-routes to the lux_crypto_<alg> static libraries.
//
// Phase 1: secp256k1 (ecrecover, address derivation). Future phases add
// bls12381, mldsa, mlkem, slhdsa, ringtail, frost, cggmp21, sha256,
// blake2b, blake3, kzg, hpke, ipa, lamport, ecies, etc.
//
// Build matrix:
//   * `go build` (no tag)            -> CPU-only, requires CGO + libluxcrypto
//   * `go build -tags accel_metal`   -> Metal GPU path (Apple)
//   * `go build -tags accel_cuda`    -> CUDA GPU path (Linux, future)

package accel
