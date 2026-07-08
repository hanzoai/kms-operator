// Copyright (C) 2024-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && lux_crypto_native
// +build cgo,lux_crypto_native

package accel

// CGO route into luxcpp/crypto secp256k1.
//
// Build with `-tags=lux_crypto_native` to opt in. Without the tag the
// CryptoSecp256k1Ecrecover function returns ErrNotSupported (see the
// non-cgo file).
//
// Linkage goes through the lux-crypto-secp256k1 pkg-config bundle, which
// exposes -lsecp256k1_cpu + -lkeccak_cpu from $LUXCPP_PREFIX/lib and the
// <lux/crypto/secp256k1.h> header from $LUXCPP_PREFIX/include. Build the
// archives + .pc once with:
//
//   cmake -S $HOME/work/luxcpp/crypto -B $HOME/work/luxcpp/crypto/build \
//         -DCMAKE_INSTALL_PREFIX=$HOME/work/luxcpp/install
//   cmake --build $HOME/work/luxcpp/crypto/build \
//         --target secp256k1_cpu keccak_cpu
//   cmake --install $HOME/work/luxcpp/crypto/build
//
// Then `export PKG_CONFIG_PATH=$HOME/work/luxcpp/install/lib/pkgconfig`.

/*
#cgo pkg-config: lux-crypto-secp256k1
#include <lux/crypto/secp256k1.h>
*/
import "C"

import (
	"errors"
	"unsafe"
)

// CryptoSecp256k1Ecrecover recovers the 64-byte uncompressed public key
// (X || Y, big-endian) from (hash, r, s, v).
//
// hash must be 32 bytes, r and s must be 32 bytes each, v in {0, 1, 27, 28}
// or EIP-155 chain-id encoding (the C ABI normalizes).
//
// Returns nil error and a 64-byte pubkey on success.
func CryptoSecp256k1Ecrecover(hash, r, s []byte, v byte) ([]byte, error) {
	if len(hash) != 32 || len(r) != 32 || len(s) != 32 {
		return nil, errors.New("accel: secp256k1 ecrecover: input length mismatch")
	}
	out := make([]byte, 64)
	st := C.secp256k1_ecrecover(
		(*C.uint8_t)(unsafe.Pointer(&hash[0])),
		(*C.uint8_t)(unsafe.Pointer(&r[0])),
		(*C.uint8_t)(unsafe.Pointer(&s[0])),
		C.uint8_t(v),
		(*C.uint8_t)(unsafe.Pointer(&out[0])),
	)
	if st != C.SECP256K1_OK {
		return nil, secp256k1Err(int(st))
	}
	return out, nil
}

// CryptoSecp256k1EcrecoverBatch runs ecrecover on n inputs concatenated as
// (hash || r || s || v_byte) tuples, 97 bytes each.
//
// Returns:
//   * pubkeys: n*64 bytes, recovered uncompressed public keys
//   * statuses: n bytes, 0 on success, nonzero error code per tuple
func CryptoSecp256k1EcrecoverBatch(inputs []byte) (pubkeys, statuses []byte, err error) {
	if len(inputs) == 0 {
		return nil, nil, nil
	}
	if len(inputs)%97 != 0 {
		return nil, nil, errors.New("accel: secp256k1 batch: inputs not multiple of 97 bytes")
	}
	n := len(inputs) / 97
	pubkeys = make([]byte, n*64)
	statuses = make([]byte, n)
	st := C.secp256k1_ecrecover_batch(
		(*C.uint8_t)(unsafe.Pointer(&inputs[0])),
		C.size_t(n),
		(*C.uint8_t)(unsafe.Pointer(&pubkeys[0])),
		(*C.uint8_t)(unsafe.Pointer(&statuses[0])),
	)
	if st != C.SECP256K1_OK {
		return nil, nil, secp256k1Err(int(st))
	}
	return pubkeys, statuses, nil
}

func secp256k1Err(st int) error {
	switch st {
	case 1:
		return errors.New("accel: secp256k1: invalid r")
	case 2:
		return errors.New("accel: secp256k1: invalid s")
	case 3:
		return errors.New("accel: secp256k1: invalid v")
	case 4:
		return errors.New("accel: secp256k1: no square root (point not on curve)")
	case 5:
		return errors.New("accel: secp256k1: recovered point is at infinity")
	case 6:
		return errors.New("accel: secp256k1: null argument")
	case 7:
		return errors.New("accel: secp256k1: buffer length")
	default:
		return errors.New("accel: secp256k1: unknown error")
	}
}
