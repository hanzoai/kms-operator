// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"sync/atomic"

	"github.com/luxfi/crypto/backend"
)

// DispatchTier identifies which path the ML-DSA batch dispatchers will
// reach when called right now. Mirrors slhdsa.DispatchTier — see the
// docstring there for the philosophy.
type DispatchTier int

const (
	TierUnknown DispatchTier = iota
	// TierGPUSubstrate: a plugin strongly overrides
	// lux_mldsa_{sign,verify}_batch (or the legacy Dilithium kernel
	// surface). Batch calls reach the Metal/CUDA/WGSL kernel.
	TierGPUSubstrate
	// TierAccelCPUFallback: accel session is live but the ML-DSA plugin
	// is not loaded. C ABI returns LUX_NOT_SUPPORTED; Go dispatcher
	// falls through to the goroutine-parallel CPU path.
	TierAccelCPUFallback
	// TierGoroutineParallelCPU: accel disabled (no cgo, vanilla
	// backend, or no device). CPU path with GOMAXPROCS workers.
	TierGoroutineParallelCPU
	// TierSerialCPU: batch below concurrentBatchThreshold; single
	// goroutine through cloudflare/circl ML-DSA.
	TierSerialCPU
)

func (t DispatchTier) String() string {
	switch t {
	case TierGPUSubstrate:
		return "gpu-substrate"
	case TierAccelCPUFallback:
		return "accel-cpu-fallback"
	case TierGoroutineParallelCPU:
		return "goroutine-parallel-cpu"
	case TierSerialCPU:
		return "serial-cpu"
	default:
		return "unknown"
	}
}

// Provenance is the auditable evidence record for the ML-DSA package.
// See slhdsa.Provenance — same shape, same purpose.
type Provenance struct {
	Tier                  DispatchTier
	AccelInitialised      bool
	DeviceAvailable       bool
	PluginStrongSymbol    bool
	BatchThresholdN       int
	ConcurrentThresholdN  int
}

// GetProvenance returns the current dispatch provenance.
//
// Default release builds (no plugin loaded) report
// TierAccelCPUFallback or TierGoroutineParallelCPU — the "GPU
// accelerated" claim is FALSE in those tiers and the binary says so
// at runtime. Once a real batch dispatch lands a strong-symbol
// observation, follow-up calls report TierGPUSubstrate.
func GetProvenance() Provenance {
	bp := backend.Probe()
	p := Provenance{
		// backend.Probe.GPU is the conjunction the prior gpuhost.Snapshot
		// tracked as (AccelInitialised && DeviceAvailable && SessionLive).
		// Surface it under both legacy field names for consumers that
		// already pattern-match on AccelInitialised / DeviceAvailable.
		AccelInitialised:     bp.GPU,
		DeviceAvailable:      bp.GPU,
		BatchThresholdN:      BatchThreshold,
		ConcurrentThresholdN: concurrentBatchThreshold,
	}
	if bp.Resolved != backend.GPU {
		p.Tier = TierGoroutineParallelCPU
		return p
	}
	p.PluginStrongSymbol = readPluginStrongSymbolCache()
	if p.PluginStrongSymbol {
		p.Tier = TierGPUSubstrate
	} else {
		p.Tier = TierAccelCPUFallback
	}
	return p
}

var pluginStrongSymbolCache atomic.Int32

func readPluginStrongSymbolCache() bool {
	return pluginStrongSymbolCache.Load() == 1
}

// recordPluginStrongSymbol is called by batchVerifyGPU / batchSignGPU
// after a successful C ABI dispatch. The cache only goes 0 → 1: once
// the strong symbol is observed, transient errors must not flip
// provenance back to "no plugin".
func recordPluginStrongSymbol(ok bool) {
	if ok {
		pluginStrongSymbolCache.Store(1)
	}
}
