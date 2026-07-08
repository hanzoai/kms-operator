# Lux Accel - GPU Acceleration for Chain Operations

High-level GPU acceleration package for blockchain and cryptographic operations.

## Architecture

```
lux/accel/
├── accel.go           # Public API
├── defaults.go        # (!cgo) No-GPU defaults
├── accel_c.go         # (cgo) CGO implementations
├── session.go         # (!cgo) Session impl
├── session_c.go       # (cgo) Session CGO
├── session_types.go   # Session types/interface
├── tensor.go          # (!cgo) Tensor impl
├── tensor_c.go        # (cgo) Tensor CGO
├── tensor_types.go    # Tensor types/interface
├── ops.go             # (!cgo) Ops interfaces
├── ops_c.go           # (cgo) Ops CGO
├── backend.go         # Backend types
├── capabilities.go    # (!cgo) Capabilities impl
├── capabilities_c.go  # (cgo) Capabilities CGO
└── ops/               # Specialized operations
    ├── crypto/        # Cryptographic operations
    ├── zk/            # Zero-knowledge proofs
    ├── fhe/           # Fully homomorphic encryption
    ├── lattice/       # Lattice-based crypto
    ├── dex/           # DEX operations
    └── consensus/     # Consensus acceleration
```

## Build Tags

| Suffix | Build Tag | Purpose |
|--------|-----------|---------|
| `foo.go` | `!cgo` | Pure Go implementation |
| `foo_c.go` | `cgo` | CGO/GPU acceleration |
| `foo_types.go` | (none) | Shared types, interfaces |
| `foo_default.go` | `!accel` | Falls back to CPU |
| `foo_gpu.go` | `accel` | GPU implementation |
| `foo_cpu.go` | (none) | CPU implementation |

## Backends

| Backend | Platform | Priority |
|---------|----------|----------|
| CUDA | Linux/Windows | 1 (highest) |
| Metal | macOS/iOS | 2 |
| WebGPU | All (Dawn) | 3 |
| CPU | All | 4 (fallback) |

## Operations

### Crypto (`ops/crypto`)
- Batch signature verification (ECDSA, Ed25519, BLS)
- Batch hashing (SHA256, Keccak256, Poseidon)
- MSM (Multi-Scalar Multiplication)
- BLS aggregation

### ZK (`ops/zk`)
- NTT/iNTT transforms
- Polynomial operations
- FFT/iFFT
- Field arithmetic (BN254)

### FHE (`ops/fhe`)
- BFV encryption/decryption
- CKKS encryption/decryption
- Homomorphic operations
- Bootstrapping
- Multi-GPU coordination

### Lattice (`ops/lattice`)
- Kyber key generation
- Kyber encapsulation/decapsulation
- Dilithium signing/verification
- Polynomial NTT/iNTT

### DEX (`ops/dex`)
- Constant product swaps
- Order matching
- TWAP computation
- Concentrated liquidity

### Consensus (`ops/consensus`)
- Batch signature verification
- Merkle tree construction
- Block validation acceleration

## Usage

```go
package main

import "github.com/luxfi/accel"

func main() {
    // Initialize
    if err := accel.Init(); err != nil {
        panic(err)
    }
    defer accel.Shutdown()

    // Check availability
    if !accel.Available() {
        println("No GPU available, using CPU")
    }

    // Batch BLS verification (GPU-accelerated)
    results, err := accel.BLSBatchVerify(pubkeys, sigs, msgs)
    if err == accel.ErrNotSupported {
        // Fall back to sequential verification
    }

    // Create session for advanced ops
    sess, err := accel.NewSession()
    if err != nil {
        panic(err)
    }
    defer sess.Close()

    // Use specialized operations
    zk := sess.ZK()
    err = zk.NTT(input, output, roots, modulus)
}
```

## Building

### Without CGO (no GPU)
```bash
CGO_ENABLED=0 go build ./...
# CPU fallbacks available for all operations
```

### With CGO (GPU support)
```bash
CGO_ENABLED=1 go build ./...
# Default build links against libluxgpu_hqc.a found via a hardcoded
# probe of standard install prefixes (see "Default build probe" below).
# Caller can prepend extra search paths via the standard cgo env vars:
#   CGO_CFLAGS="-I/my/install/include" \
#   CGO_LDFLAGS="-L/my/install/lib" \
#   CGO_ENABLED=1 go build ./...
```

### Default build probe (`code_cpu.go`)

The default build does NOT use pkg-config. Instead, `ops/code/code_cpu.go`
declares a fixed list of `#cgo CFLAGS: -I<dir>` and `#cgo LDFLAGS: -L<dir>`
directives covering every standard install prefix. The C compiler and
linker silently skip any `-I` / `-L` path that doesn't exist, so the
build "just works" as long as ONE prefix has the artefacts.

Search list compiled into `code_cpu.go` (in compiler/linker order):

1. `CGO_CFLAGS` / `CGO_LDFLAGS` env vars — appended AFTER the `#cgo`
   directives by go's cgo driver, so they take precedence on
   first-match-wins resolution.
2. `/usr/local/{include,lib}` — POSIX system install (cmake default).
3. `/opt/homebrew/{include,lib}` — Homebrew on Apple Silicon.
4. `/opt/homebrew/opt/lux-gpu/{include,lib}` — Homebrew keg-only install.
5. `/usr/local/opt/lux-gpu/{include,lib}` — Homebrew on Intel Mac.
6. `/opt/lux/{include,lib}` — Lux canonical prefix.
7. `${SRCDIR}/../../../mlx/{include,build}` — in-tree dev fallback.
   Resolves only when accel is checked out in a workspace next to
   `luxfi/mlx`; in the Go module cache this path doesn't exist and
   is silently skipped.

To target a non-listed prefix, set the standard cgo env vars at build
time (option 1 above). `LUX_GPU_PREFIX` is NOT consulted by the
default build directly — it is honored only by the runtime introspector
(`accel.GPUPaths()`) and by external build wrappers such as
`precompile/Makefile`, which translate it into `CGO_CFLAGS` /
`CGO_LDFLAGS` before invoking `go build`.

### Opt-in pkg-config mode (`-tags=lux_gpu_pkgconfig`)

`ops/code/code_cpu_pkgconfig.go` (gated on `//go:build cgo && lux_gpu_pkgconfig`)
substitutes a single `#cgo pkg-config: lux-gpu` directive for the
hardcoded probe. With this tag the build FAILS if `pkg-config` cannot
resolve `lux-gpu` — there is no fallback chain.

```bash
PKG_CONFIG_PATH=$HOME/.local/lib/pkgconfig \
  go build -tags=lux_gpu_pkgconfig ./...
```

This mode is intended for CI / build systems that have already
installed lux-gpu via `cmake --install` and want to assert the
pkg-config wiring is correct.

### Runtime introspection (`accel.GPUPaths()`)

`accel.GPUPaths()` (or `accel.Provenance{}.GPUPaths()`) returns a
`PathReport` naming which install prefix would resolve on the
current host. The introspector probes a SUPERSET of the default
build's search list — it ALSO checks `LUX_GPU_PREFIX` and runs
`pkg-config --cflags --libs lux-gpu` — so an env-var override
visible to the runtime introspector may not be the same prefix the
default build linked against. Use it as a diagnostic, not as a
contract.

The introspector's probe order:

1. `LUX_GPU_PREFIX` env var (back-compat: `LUX_MLX_PREFIX`).
2. `CGO_CFLAGS` / `CGO_LDFLAGS` env vars at runtime.
3. `pkg-config --cflags --libs lux-gpu` if the binary is on `$PATH`.
4. `/opt/homebrew/opt/lux-gpu/{include,lib}` — keg-only Homebrew.
5. `/usr/local/opt/lux-gpu/{include,lib}` — Intel-Mac Homebrew.
6. `/opt/homebrew/{include,lib}` — Apple-Silicon Homebrew.
7. `/usr/local/{include,lib}` — POSIX system install (cmake default).
8. `/opt/lux/{include,lib}` — Lux canonical prefix.
9. `${SRCDIR}/../mlx/{include,build}` — in-tree dev sibling repo
   (resolves only outside the Go module cache).

### With accel tag (full GPU ops)
```bash
go build -tags=accel ./...
# Enables GPU implementations in ops/*
```

## Related

- `lux/gpu` - Low-level GPU array operations
- `luxcpp/gpu` - C++ backend library
