// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// ML-DSA / Dilithium (FIPS 204) GPU dispatch.
//
// Dispatch path:
//
//   backend.IsGPU()
//     ⇒ Resolved() picks the GPU substrate after probing CGo + GPU availability
//     ⇒ accel.LatticeOps.MLDSAVerifyBatch / MLDSASignBatch on the shared session
//     ⇒ luxcpp/lux-accel C API lux_mldsa_{verify,sign}_batch (under development)
//     ⇒ when a backend plugin registers a strong substrate:
//         luxcpp/crypto/mldsa/gpu/{metal,cuda}/ kernel substrate
//     ⇒ otherwise the substrate returns NotSupported and we fall through to
//         per-element CPU verify (cloudflare/circl, FIPS 204-conformant).
//
// Mode dispatch:
//
//   ML-DSA-44 → C-API mode=2  (NIST L2, devnet, compat tier)
//   ML-DSA-65 → C-API mode=3  (NIST L3, canonical strict-PQ)
//   ML-DSA-87 → C-API mode=5  (NIST L5, high-value tier)
//
// Each mode has its own (pk_size, sig_size, sk_size) per FIPS 204:
//
//   44 :  pk=1312  sk=2560  sig=2420
//   65 :  pk=1952  sk=4032  sig=3309
//   87 :  pk=2592  sk=4896  sig=4627
//
// The kernel substrate uses NTT-resident batch verify pattern: a single
// NTT(t1) batch lift of the public-key matrix lattice followed by per-
// signature challenge polynomial samples (FIPS 204 §6.3 Verify steps 7-10).
// The intra-batch parallelism is along the n × (msg, sig, pk) dimension;
// each lane runs its own t1·NTT product without cross-lane data hazards.
//
// Equivalence: FIPS 204 verify is deterministic — given identical (msg, sig,
// pk) the substrate and circl reference produce byte-equal accept/reject
// decisions. Asserted by TestMLDSABatchEquivalence_CPU_GPU_{44,65,87}.

package mldsa

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/crypto/backend"
	"github.com/luxfi/crypto/internal/gpuhost"
)

// modeToCAPI maps an ML-DSA Mode to the FIPS 204 NIST level integer accepted
// by the lux-accel C ABI (mode = 2 / 3 / 5 for ML-DSA-44 / 65 / 87). Returns
// ok=false for modes not wired through GPU dispatch.
func modeToCAPI(m Mode) (int, bool) {
	switch m {
	case MLDSA44:
		return 2, true
	case MLDSA65:
		return 3, true
	case MLDSA87:
		return 5, true
	default:
		return 0, false
	}
}

// batchVerifyGPU dispatches a batch of ML-DSA verifications to the GPU
// substrate when available. Mode is per the first public key in the batch —
// callers MUST ensure all entries share the same mode (the public BatchVerify
// API enforces this; this entrypoint is internal and trusts the contract).
//
// Returns (true, nil) when the GPU path produced `out`. Returns (false, nil)
// in any of these cases:
//
//   - CRYPTO_BACKEND is not GPU
//   - gpuhost has no accel session
//   - the mode is not wired for GPU dispatch
//   - the substrate returns NotSupported (no plugin loaded)
//   - any tensor allocation or kernel dispatch failed (we fall through
//     silently to CPU; the caller's per-element loop is the safety net)
//
// `out` is only written when the function returns (true, nil).
func batchVerifyGPU(pubs []*PublicKey, msgs [][]byte, sigs [][]byte, out []bool) (bool, error) {
	if len(pubs) == 0 {
		return true, nil
	}
	if len(msgs) != len(pubs) || len(sigs) != len(pubs) || len(out) != len(pubs) {
		return false, nil
	}

	if !backend.IsGPU() {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	mode := pubs[0].mode
	capiMode, ok := modeToCAPI(mode)
	if !ok {
		return false, nil
	}
	for i := 1; i < len(pubs); i++ {
		if pubs[i].mode != mode {
			return false, nil
		}
	}

	pkSize := GetPublicKeySize(mode)
	sigSize := GetSignatureSize(mode)
	if pkSize == 0 || sigSize == 0 {
		return false, nil
	}

	n := len(pubs)
	width := 1
	for _, m := range msgs {
		if len(m) > width {
			width = len(m)
		}
	}

	mFlat := make([]uint8, n*width)
	for i, m := range msgs {
		copy(mFlat[i*width:(i+1)*width], m)
	}
	pFlat := make([]uint8, n*pkSize)
	for i, p := range pubs {
		if len(p.publicKey) != pkSize {
			return false, nil
		}
		copy(pFlat[i*pkSize:(i+1)*pkSize], p.publicKey)
	}
	sFlat := make([]uint8, n*sigSize)
	for i, s := range sigs {
		if len(s) != sigSize {
			return false, nil
		}
		copy(sFlat[i*sigSize:(i+1)*sigSize], s)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, width}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	sT, err := accel.NewTensorWithData[uint8](sess, []int{n, sigSize}, sFlat)
	if err != nil {
		return false, nil
	}
	defer sT.Close()
	pT, err := accel.NewTensorWithData[uint8](sess, []int{n, pkSize}, pFlat)
	if err != nil {
		return false, nil
	}
	defer pT.Close()
	rT, err := accel.NewTensor[uint8](sess, []int{n})
	if err != nil {
		return false, nil
	}
	defer rT.Close()

	// Try the new mode-aware MLDSAVerifyBatch first. When ML-DSA-65 is in use
	// fall back to the legacy DilithiumVerifyBatch for substrates that only
	// publish the Dilithium3 kernel (the original wiring).
	dispatchErr := sess.Lattice().MLDSAVerifyBatch(capiMode, mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped())
	if dispatchErr != nil && mode == MLDSA65 {
		dispatchErr = sess.Lattice().DilithiumVerifyBatch(mT.Untyped(), sT.Untyped(), pT.Untyped(), rT.Untyped())
	}
	if dispatchErr != nil {
		return false, nil
	}
	bytes, err := rT.ToSlice()
	if err != nil {
		return false, nil
	}
	// Successful C ABI dispatch means the plugin's strong override of
	// lux_mldsa_verify_batch is resolved (or the legacy Dilithium kernel
	// for ML-DSA-65, which is the same surface). GetProvenance can
	// honestly report TierGPUSubstrate from here on.
	recordPluginStrongSymbol(true)
	for i, b := range bytes {
		out[i] = b == 1
	}
	return true, nil
}

// batchSignGPU dispatches a batch of ML-DSA signing operations to the GPU
// substrate. Returns (dispatched, error) — see batchVerifyGPU for the
// fall-through contract.
//
// All privs MUST share the same mode. On success, `sigs[i]` is overwritten
// with the signature of `msgs[i]` under `privs[i]`.
func batchSignGPU(privs []*PrivateKey, msgs [][]byte, sigs [][]byte) (bool, error) {
	if len(privs) == 0 {
		return true, nil
	}
	if len(msgs) != len(privs) || len(sigs) != len(privs) {
		return false, nil
	}

	if !backend.IsGPU() {
		return false, nil
	}
	sess := gpuhost.Session()
	if sess == nil {
		return false, nil
	}

	mode := privs[0].mode
	capiMode, ok := modeToCAPI(mode)
	if !ok {
		return false, nil
	}
	for i := 1; i < len(privs); i++ {
		if privs[i].mode != mode {
			return false, nil
		}
	}

	skSize := GetPrivateKeySize(mode)
	sigSize := GetSignatureSize(mode)
	if skSize == 0 || sigSize == 0 {
		return false, nil
	}

	n := len(privs)
	width := 1
	for _, m := range msgs {
		if len(m) > width {
			width = len(m)
		}
	}

	mFlat := make([]uint8, n*width)
	for i, m := range msgs {
		copy(mFlat[i*width:(i+1)*width], m)
	}
	skFlat := make([]uint8, n*skSize)
	for i, p := range privs {
		if len(p.secretKey) != skSize {
			return false, nil
		}
		copy(skFlat[i*skSize:(i+1)*skSize], p.secretKey)
	}

	mT, err := accel.NewTensorWithData[uint8](sess, []int{n, width}, mFlat)
	if err != nil {
		return false, nil
	}
	defer mT.Close()
	skT, err := accel.NewTensorWithData[uint8](sess, []int{n, skSize}, skFlat)
	if err != nil {
		return false, nil
	}
	defer skT.Close()
	sigT, err := accel.NewTensor[uint8](sess, []int{n, sigSize})
	if err != nil {
		return false, nil
	}
	defer sigT.Close()

	if err := sess.Lattice().MLDSASignBatch(capiMode, mT.Untyped(), skT.Untyped(), sigT.Untyped()); err != nil {
		return false, nil
	}

	sigBytes, err := sigT.ToSlice()
	if err != nil {
		return false, nil
	}
	// See batchVerifyGPU.
	recordPluginStrongSymbol(true)
	for i := 0; i < n; i++ {
		sigs[i] = make([]byte, sigSize)
		copy(sigs[i], sigBytes[i*sigSize:(i+1)*sigSize])
	}
	return true, nil
}
