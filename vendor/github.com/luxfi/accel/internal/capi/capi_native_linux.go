//go:build cgo && accel_native && linux

// Package capi — opt-in native-library link directives (Linux).
// See capi_native_darwin.go for the policy. Required host install:
//   /usr/local/lib/libluxaccel.so
// Plus a CUDA plugin under the configured LUX_PLUGIN_PATH.
//
// libluxaccel.so is self-contained: it does not require linking
// against libluxgpu or libluxcrypto at the Go consumer site. The
// luxcpp build links those statically into libluxaccel.so before
// install.

package capi

/*
#cgo linux LDFLAGS: -lluxaccel
*/
import "C"
