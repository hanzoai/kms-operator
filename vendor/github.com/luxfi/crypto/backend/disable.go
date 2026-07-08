// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package backend

import (
	"os"
	"strings"
)

// GPU_DISABLE is the process-wide operator kill switch for GPU dispatch.
// Read exactly once at init; the value is then constant for the lifetime
// of the process. Set to a truthy value (1 / true / yes / on) to force
// every algorithm dispatcher to its CPU path regardless of whether a
// device is present.
//
// This is orthogonal to GPUAvailable() — that probe answers "is there a
// device", this knob answers "should we use it even if there is". Use
// cases: GPU driver regression in prod, A/B rollout where some racks
// stay on CPU, validators sharing a host with another tenant.
const envGPUDisable = "GPU_DISABLE"

var gpuDisabled = parseTruthy(os.Getenv(envGPUDisable))

// GPUDisabled reports whether the GPU_DISABLE kill switch is set. When
// true, GPUAvailable() returns false and IsGPU() therefore returns false,
// forcing every dispatcher onto its CPU path.
func GPUDisabled() bool { return gpuDisabled }

// parseTruthy mirrors the convention used by strconv.ParseBool but
// accepts a few extra human-friendly spellings. Empty / 0 / false / no /
// off → false; anything else → true.
func parseTruthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "0", "false", "no", "off":
		return false
	default:
		return true
	}
}
