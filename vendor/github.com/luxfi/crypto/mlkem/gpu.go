// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mlkem

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// accel publishes Kyber768 batch kernels — the closest match to ML-KEM-768.
// Other modes fall through.

func batchEncapsulateGPU(pubs []*PublicKey, cts [][]byte, sss [][]byte) (bool, error) {
	if !backend.IsGPU() {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	n := len(pubs)
	pkSize := MLKEM768PublicKeySize
	ctSize := MLKEM768CiphertextSize
	ssSize := MLKEM768SharedKeySize

	pkFlat := make([]uint8, n*pkSize)
	for i, p := range pubs {
		b := p.Bytes()
		if len(b) != pkSize {
			return false, nil
		}
		copy(pkFlat[i*pkSize:(i+1)*pkSize], b)
	}

	pkT, err := accel.NewTensorWithData[uint8](sess, []int{n, pkSize}, pkFlat)
	if err != nil {
		return false, nil
	}
	defer pkT.Close()
	ctT, err := accel.NewTensor[uint8](sess, []int{n, ctSize})
	if err != nil {
		return false, nil
	}
	defer ctT.Close()
	ssT, err := accel.NewTensor[uint8](sess, []int{n, ssSize})
	if err != nil {
		return false, nil
	}
	defer ssT.Close()

	if err := sess.Lattice().KyberEncapsBatch(pkT.Untyped(), ctT.Untyped(), ssT.Untyped()); err != nil {
		return false, nil
	}
	ctBytes, err := ctT.ToSlice()
	if err != nil {
		return false, nil
	}
	ssBytes, err := ssT.ToSlice()
	if err != nil {
		return false, nil
	}
	for i := 0; i < n; i++ {
		c := make([]byte, ctSize)
		copy(c, ctBytes[i*ctSize:(i+1)*ctSize])
		cts[i] = c
		s := make([]byte, ssSize)
		copy(s, ssBytes[i*ssSize:(i+1)*ssSize])
		sss[i] = s
	}
	return true, nil
}

func batchDecapsulateGPU(sks []*PrivateKey, cts [][]byte, sss [][]byte) (bool, error) {
	if !backend.IsGPU() {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	n := len(sks)
	skSize := MLKEM768PrivateKeySize
	ctSize := MLKEM768CiphertextSize
	ssSize := MLKEM768SharedKeySize

	skFlat := make([]uint8, n*skSize)
	for i, s := range sks {
		b := s.Bytes()
		if len(b) != skSize {
			return false, nil
		}
		copy(skFlat[i*skSize:(i+1)*skSize], b)
	}
	ctFlat := make([]uint8, n*ctSize)
	for i, c := range cts {
		if len(c) != ctSize {
			return false, nil
		}
		copy(ctFlat[i*ctSize:(i+1)*ctSize], c)
	}

	skT, err := accel.NewTensorWithData[uint8](sess, []int{n, skSize}, skFlat)
	if err != nil {
		return false, nil
	}
	defer skT.Close()
	ctT, err := accel.NewTensorWithData[uint8](sess, []int{n, ctSize}, ctFlat)
	if err != nil {
		return false, nil
	}
	defer ctT.Close()
	ssT, err := accel.NewTensor[uint8](sess, []int{n, ssSize})
	if err != nil {
		return false, nil
	}
	defer ssT.Close()

	if err := sess.Lattice().KyberDecapsBatch(ctT.Untyped(), skT.Untyped(), ssT.Untyped()); err != nil {
		return false, nil
	}
	ssBytes, err := ssT.ToSlice()
	if err != nil {
		return false, nil
	}
	for i := 0; i < n; i++ {
		s := make([]byte, ssSize)
		copy(s, ssBytes[i*ssSize:(i+1)*ssSize])
		sss[i] = s
	}
	return true, nil
}
