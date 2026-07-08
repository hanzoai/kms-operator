// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !lux_crypto_native
// +build !cgo !lux_crypto_native

package accel

import "errors"

// ErrCryptoNativeUnavailable indicates the lux_crypto native libraries are not
// linked into this build. Rebuild with `-tags=lux_crypto_native` and ensure
// liblux_crypto_secp256k1.a is on the linker path.
var ErrCryptoNativeUnavailable = errors.New("accel: lux_crypto native not built (use -tags=lux_crypto_native)")

// CryptoSecp256k1Ecrecover stub.
func CryptoSecp256k1Ecrecover(hash, r, s []byte, v byte) ([]byte, error) {
	return nil, ErrCryptoNativeUnavailable
}

// CryptoSecp256k1EcrecoverBatch stub.
func CryptoSecp256k1EcrecoverBatch(inputs []byte) (pubkeys, statuses []byte, err error) {
	return nil, nil, ErrCryptoNativeUnavailable
}
