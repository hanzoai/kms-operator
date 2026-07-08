// Package backend defines the runtime backend selector for luxfi/crypto.
//
// Every crypto package in this module has up to three implementations:
//
//   - vanilla: pure-Go reference (always available)
//   - cgo:     native C library binding (blst, libsecp256k1, ckzg, ...)
//   - gpu:     batch acceleration via github.com/luxfi/accel
//
// The package selects which implementation to run based on the value of
// Default(). Callers can override programmatically with SetDefault(),
// or globally with the CRYPTO_BACKEND environment variable.
//
// The default value is Auto — pick the most capable backend the binary
// was compiled and linked with, in the order GPU > CGo > Vanilla.
package backend

import (
	"os"
	"strings"
	"sync/atomic"
)

// Backend identifies a crypto implementation choice.
type Backend uint32

const (
	// Auto selects the best available backend automatically.
	Auto Backend = iota
	// Vanilla forces the pure-Go reference implementation.
	Vanilla
	// CGo forces the native C-library backed implementation when available.
	CGo
	// GPU forces routing through github.com/luxfi/accel when available.
	GPU
)

// String returns the canonical lowercase name of the backend.
func (b Backend) String() string {
	switch b {
	case Auto:
		return "auto"
	case Vanilla:
		return "vanilla"
	case CGo:
		return "cgo"
	case GPU:
		return "gpu"
	default:
		return "unknown"
	}
}

// Parse converts a string identifier to a Backend. Empty string returns Auto.
func Parse(s string) (Backend, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "auto":
		return Auto, true
	case "vanilla", "go", "pure":
		return Vanilla, true
	case "cgo", "c", "native":
		return CGo, true
	case "gpu", "accel":
		return GPU, true
	default:
		return Auto, false
	}
}

var current uint32 // atomic Backend

// envBackend reads CRYPTO_BACKEND from the environment.
func envBackend() (string, bool) {
	return os.LookupEnv("CRYPTO_BACKEND")
}

func init() {
	if v, ok := envBackend(); ok {
		if b, parsed := Parse(v); parsed {
			atomic.StoreUint32(&current, uint32(b))
		}
	}
}

// Default returns the active backend selection. The value is Auto unless
// SetDefault was called or CRYPTO_BACKEND was set in the environment.
func Default() Backend {
	return Backend(atomic.LoadUint32(&current))
}

// SetDefault overrides the active backend.
//
// Use the empty string or "auto" via Parse to revert to Auto behavior.
func SetDefault(b Backend) {
	atomic.StoreUint32(&current, uint32(b))
}

// CGoAvailable reports whether the binary was compiled with CGO_ENABLED=1.
// The answer is a compile-time constant: cgoLinked is set by cgo_yes.go
// when cgo is on and cgo_no.go when cgo is off.
func CGoAvailable() bool { return cgoLinked }

// GPUAvailable reports whether the luxfi/accel GPU substrate is reachable
// in this process. First call lazily initialises accel via gpuhost; the
// answer is cached afterwards. Returns false unconditionally when the
// GPU_DISABLE kill switch is set (see disable.go).
func GPUAvailable() bool {
	if gpuDisabled {
		return false
	}
	return gpuLinked()
}

// Available reports whether backend b is currently usable. Auto and Vanilla
// are always available; CGo requires CGO_ENABLED=1; GPU requires a live
// accel session with at least one device.
func Available(b Backend) bool {
	switch b {
	case Auto, Vanilla:
		return true
	case CGo:
		return CGoAvailable()
	case GPU:
		return GPUAvailable()
	default:
		return false
	}
}

// Resolved picks the concrete backend for the caller using the real
// CGo / GPU probes. This is the one-call shortcut for the common pattern:
//
//	if backend.Resolved() == backend.GPU {
//	    // dispatch GPU path
//	}
//
// Equivalent to Resolve(GPUAvailable(), CGoAvailable()).
func Resolved() Backend { return Resolve(GPUAvailable(), CGoAvailable()) }

// IsGPU reports whether Resolved() picks GPU. Algorithm dispatchers gate
// their GPU path with this:
//
//	if !backend.IsGPU() { return false, nil }
func IsGPU() bool { return Resolved() == GPU }

// IsCGo reports whether Resolved() picks CGo.
func IsCGo() bool { return Resolved() == CGo }

// IsVanilla reports whether Resolved() picks Vanilla. Useful for dispatchers
// whose accelerated path covers both GPU and CGo and only needs to bail out
// on explicit Vanilla selection (e.g. crypto/hqc batch entrypoints).
func IsVanilla() bool { return Resolved() == Vanilla }

// Resolve picks a concrete backend for the caller. If Default() is Auto the
// resolution falls back through GPU → CGo → Vanilla, choosing the first
// backend reported as available by the supplied probes.
//
// Prefer Resolved() / IsGPU() / IsCGo() / IsVanilla() — they call this
// function with the real probes from CGoAvailable() and GPUAvailable().
// The four-arg form remains exported for callers that already know the
// answer (tests, custom dispatchers with their own probes).
func Resolve(gpuAvailable, cgoAvailable bool) Backend {
	switch d := Default(); d {
	case Vanilla:
		return Vanilla
	case CGo:
		if cgoAvailable {
			return CGo
		}
		return Vanilla
	case GPU:
		if gpuAvailable {
			return GPU
		}
		if cgoAvailable {
			return CGo
		}
		return Vanilla
	default: // Auto
		if gpuAvailable {
			return GPU
		}
		if cgoAvailable {
			return CGo
		}
		return Vanilla
	}
}
