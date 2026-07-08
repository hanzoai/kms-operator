// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

// BatchThreshold is the minimum batch length at which BatchEncapsulate /
// BatchDecapsulate will try to dispatch through github.com/luxfi/accel.
var BatchThreshold = 64

// BatchEncapsulate runs Encapsulate for a slice of public keys, returning the
// resulting (ciphertext, sharedSecret) pairs. All keys must be the same mode.
//
// When the batch is large enough and a GPU backend is available the
// computation runs on the GPU; otherwise it falls back to per-key
// Encapsulate calls. The output is byte-identical for the deterministic
// path; the streaming path uses fresh randomness either way.
func BatchEncapsulate(pubs []*PublicKey) (cts [][]byte, sss [][]byte, err error) {
	n := len(pubs)
	if n == 0 {
		return nil, nil, nil
	}
	mode := pubs[0].mode
	for i := 1; i < n; i++ {
		if pubs[i].mode != mode {
			return nil, nil, ErrInvalidKeySize
		}
	}

	cts = make([][]byte, n)
	sss = make([][]byte, n)

	if n >= BatchThreshold && mode == MLKEM768 {
		if ok, gerr := batchEncapsulateGPU(pubs, cts, sss); ok && gerr == nil {
			return cts, sss, nil
		}
	}

	for i, pk := range pubs {
		ct, ss, e := pk.Encapsulate()
		if e != nil {
			return nil, nil, e
		}
		cts[i] = ct
		sss[i] = ss
	}
	return cts, sss, nil
}

// BatchDecapsulate runs Decapsulate over a slice of (sk, ct) pairs.
func BatchDecapsulate(sks []*PrivateKey, cts [][]byte) (sss [][]byte, err error) {
	n := len(sks)
	if n != len(cts) {
		return nil, ErrInvalidKeySize
	}
	if n == 0 {
		return nil, nil
	}
	mode := sks[0].mode
	for i := 1; i < n; i++ {
		if sks[i].mode != mode {
			return nil, ErrInvalidKeySize
		}
	}
	sss = make([][]byte, n)
	if n >= BatchThreshold && mode == MLKEM768 {
		if ok, gerr := batchDecapsulateGPU(sks, cts, sss); ok && gerr == nil {
			return sss, nil
		}
	}
	for i, sk := range sks {
		ss, e := sk.Decapsulate(cts[i])
		if e != nil {
			return nil, e
		}
		sss[i] = ss
	}
	return sss, nil
}
