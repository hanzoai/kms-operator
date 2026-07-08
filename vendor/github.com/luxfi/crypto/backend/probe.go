// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import (
	"fmt"
	"strings"

	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// Snapshot is the auditable, side-effect-free view of the backend layer at
// a single moment. Callers print one of these to make "GPU accelerated"
// claims falsifiable — the snapshot says exactly which substrate the
// dispatchers will reach for the next batch call.
type Snapshot struct {
	// Default is the user-selected backend (Auto / Vanilla / CGo / GPU).
	Default Backend
	// Resolved is the concrete backend Resolved() would return right now,
	// given the live CGo / GPU probes.
	Resolved Backend
	// CGo reports whether CGO_ENABLED was on at build time.
	CGo bool
	// GPU reports whether luxfi/accel found at least one device. Always
	// false when Disabled is true, regardless of the underlying probe.
	GPU bool
	// Disabled reflects the GPU_DISABLE operator kill switch.
	Disabled bool
	// GPUBackend names the active accel backend ("metal" / "cuda" /
	// "webgpu") or "" when no GPU is available.
	GPUBackend string
	// GPUDeviceCount is the number of devices visible to accel.
	GPUDeviceCount int
	// AccelVersion is the underlying accel library version string.
	AccelVersion string
	// Fallbacks is the per-reason fallback counter snapshot. Keys are
	// the low-cardinality strings returned by FallbackReason.String().
	Fallbacks map[string]uint64
}

// Probe returns the current backend Snapshot. Side-effect free except for
// the lazy accel.Init() inside the GPU probe — calling it before any
// algorithm dispatch is the canonical way to print "what would happen if
// I called Batch right now."
func Probe() Snapshot {
	s := Snapshot{
		Default:      Default(),
		Resolved:     Resolved(),
		CGo:          CGoAvailable(),
		GPU:          GPUAvailable(),
		Disabled:     GPUDisabled(),
		AccelVersion: accel.GetVersion(),
		Fallbacks:    FallbackCounters(),
	}
	if s.GPU {
		if sess := gpuhost.Session(); sess != nil {
			s.GPUBackend = sess.Backend().String()
		}
		s.GPUDeviceCount = len(accel.Devices())
	}
	return s
}

// String formats the snapshot as a single human-readable line suitable
// for startup banners and audit logs.
func (s Snapshot) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "backend{default=%s resolved=%s cgo=%t gpu=%t",
		s.Default, s.Resolved, s.CGo, s.GPU)
	if s.Disabled {
		b.WriteString(" disabled=true")
	}
	if s.GPU {
		fmt.Fprintf(&b, " gpu_backend=%s devices=%d", s.GPUBackend, s.GPUDeviceCount)
	}
	if s.AccelVersion != "" {
		fmt.Fprintf(&b, " accel=%s", s.AccelVersion)
	}
	// Only emit the fallbacks block if at least one counter is non-zero
	// so the common case stays one short line.
	any := false
	for _, v := range s.Fallbacks {
		if v > 0 {
			any = true
			break
		}
	}
	if any {
		b.WriteString(" fallbacks=[")
		first := true
		for _, name := range []string{"disabled", "unsupported", "probe_failed", "backend_unavailable", "abi_mismatch"} {
			v := s.Fallbacks[name]
			if v == 0 {
				continue
			}
			if !first {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%s=%d", name, v)
			first = false
		}
		b.WriteByte(']')
	}
	b.WriteByte('}')
	return b.String()
}
