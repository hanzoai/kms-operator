// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import (
	"log"
	"sync"
	"sync/atomic"
)

// FallbackReason is the low-cardinality enum recorded by RecordFallback.
// Keeping the set small and closed is deliberate — these values land in
// counter labels and log lines, and dynamic strings there are an
// observability anti-pattern (label explosion in Prometheus, log noise).
type FallbackReason uint32

const (
	// FallbackDisabled — GPU_DISABLE is set; dispatcher routed to CPU.
	FallbackDisabled FallbackReason = iota
	// FallbackUnsupported — host driver reported no usable device
	// (cudaGetDeviceCount == 0, Metal device init failed, etc.).
	FallbackUnsupported
	// FallbackProbeFailed — first-use byte-equality probe rejected
	// the GPU path (e.g. FHE NTT (N,Q) convention mismatch).
	FallbackProbeFailed
	// FallbackBackendUnavailable — accel session itself failed to load
	// or the linked plugin returned LUX_NOT_SUPPORTED.
	FallbackBackendUnavailable
	// FallbackABIMismatch — a Go init() ABI-size/offset check would have
	// panicked, but a dispatcher recovered and downgraded to CPU. Should
	// never fire in a released build; included for completeness.
	FallbackABIMismatch

	numFallbackReasons
)

// String returns the canonical low-cardinality reason name. These are
// the strings that appear in metrics labels and log lines.
func (r FallbackReason) String() string {
	switch r {
	case FallbackDisabled:
		return "disabled"
	case FallbackUnsupported:
		return "unsupported"
	case FallbackProbeFailed:
		return "probe_failed"
	case FallbackBackendUnavailable:
		return "backend_unavailable"
	case FallbackABIMismatch:
		return "abi_mismatch"
	default:
		return "unknown"
	}
}

var (
	fallbackCounters [numFallbackReasons]uint64
	fallbackLogOnce  [numFallbackReasons]sync.Once
)

// RecordFallback increments the per-reason counter and emits exactly one
// log line per distinct (reason) over the lifetime of the process. The
// `where` string identifies the dispatcher site ("amm", "clob",
// "fhe_ntt") so an operator skimming the log can locate the surface
// that fell back without per-call spam.
func RecordFallback(reason FallbackReason, where string) {
	if reason >= numFallbackReasons {
		return
	}
	atomic.AddUint64(&fallbackCounters[reason], 1)
	fallbackLogOnce[reason].Do(func() {
		log.Printf("[crypto/backend] GPU fallback: reason=%s where=%s", reason, where)
	})
}

// FallbackCounters returns a snapshot of the per-reason counters keyed
// by the canonical reason name. Suitable for Prometheus / Grafana with
// `reason` as a label.
func FallbackCounters() map[string]uint64 {
	out := make(map[string]uint64, int(numFallbackReasons))
	for i := FallbackReason(0); i < numFallbackReasons; i++ {
		out[i.String()] = atomic.LoadUint64(&fallbackCounters[i])
	}
	return out
}

// resetFallbackForTest zeros every counter and reinitialises the
// once-per-reason log gate. Test-only; package-private.
func resetFallbackForTest() {
	for i := range fallbackCounters {
		atomic.StoreUint64(&fallbackCounters[i], 0)
		fallbackLogOnce[i] = sync.Once{}
	}
}
