// Copyright (C) 2020-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mldsa

import (
	"crypto/rand"
	"errors"
	"io"
	"runtime"
	"sync"
)

// BatchThreshold is the minimum batch length at which BatchVerify will try
// to dispatch through github.com/luxfi/accel.
var BatchThreshold = 64

// concurrentBatchThreshold is the minimum batch length at which the CPU
// fallback parallelizes per-signature work across GOMAXPROCS goroutines.
// Below this threshold the goroutine overhead exceeds the parallelism gain.
// Tuned for the FIPS 204 verify cost (~200µs per ML-DSA-65 verify on M1 Max).
var concurrentBatchThreshold = 8

// BatchVerify verifies a slice of (pub, msg, sig) triples for the same
// ML-DSA mode. The result slice has one boolean per input.
//
// Dispatch ladder:
//
//   1. GPU substrate (accel.LatticeOps.MLDSAVerifyBatch) when n >= BatchThreshold
//      AND a backend plugin is loaded AND mode is in {44, 65, 87}.
//   2. Goroutine-parallel CPU verify when n >= concurrentBatchThreshold.
//      Scales to GOMAXPROCS without GPU substrate. Useful on hosts that
//      have CPU cores but no GPU plugin (Linux CI, no-Metal Macs, etc).
//   3. Serial CPU verify as the floor.
//
// All paths are byte-equal: each path ends in cloudflare/circl's
// FIPS 204-conformant Verify. The dispatch choice only affects throughput,
// never the accept/reject decision.
//
// All inputs must use the same mode; if pubs[i].mode differs from the
// first one, BatchVerify panics.
func BatchVerify(pubs []*PublicKey, msgs [][]byte, sigs [][]byte) []bool {
	n := len(pubs)
	if n != len(msgs) || n != len(sigs) {
		panic("mldsa.BatchVerify: pubs/msgs/sigs length mismatch")
	}
	out := make([]bool, n)
	if n == 0 {
		return out
	}
	mode := pubs[0].mode
	for i := 1; i < n; i++ {
		if pubs[i].mode != mode {
			panic("mldsa.BatchVerify: mixed modes not supported")
		}
	}

	// Tier 1: GPU substrate.
	if n >= BatchThreshold {
		if _, ok := modeToCAPI(mode); ok {
			if ok, err := batchVerifyGPU(pubs, msgs, sigs, out); ok && err == nil {
				return out
			}
		}
	}

	// Tier 2: Goroutine-parallel CPU. Each goroutine takes a contiguous slice
	// of the batch and runs serial verify on it; with GOMAXPROCS workers and
	// roughly equal work per signature the speedup approaches min(n, P).
	if n >= concurrentBatchThreshold {
		batchVerifyConcurrent(pubs, msgs, sigs, out)
		return out
	}

	// Tier 3: Serial floor.
	for i := range pubs {
		out[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
	}
	return out
}

// batchVerifyConcurrent runs FIPS 204 Verify in parallel across GOMAXPROCS
// goroutines. The verify operation is pure (no shared mutable state), so the
// goroutines need no synchronization beyond the wait-group barrier.
func batchVerifyConcurrent(pubs []*PublicKey, msgs, sigs [][]byte, out []bool) {
	n := len(pubs)
	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers < 2 {
		for i := range pubs {
			out[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
		}
		return
	}

	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * chunk
		if start >= n {
			break
		}
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				out[i] = pubs[i].VerifySignature(msgs[i], sigs[i])
			}
		}(start, end)
	}
	wg.Wait()
}

// ErrBatchLength is returned by BatchSign when the input slice lengths
// disagree.
var ErrBatchLength = errors.New("mldsa: batch input slices have inconsistent lengths")

// BatchSign signs `len(privs)` messages in parallel, returning one signature
// per input. All entries MUST share the same mode.
//
// FIPS 204 signing is randomized by default (per §3.4 hedged mode). The
// caller-supplied rand source is split deterministically across the workers
// so the function remains pure-output: same inputs + same rand stream ⇒
// same signatures.
//
// Dispatch ladder mirrors BatchVerify:
//
//   1. GPU substrate (accel.LatticeOps.MLDSASignBatch).
//   2. Goroutine-parallel CPU sign.
//   3. Serial CPU sign.
//
// For deterministic-mode signing (FIPS 204 § Algorithm 2 with rnd=0^256),
// callers can pass nil for randSource. The CPU path passes deterministic=true
// to circl.SignTo which removes the random oracle and produces byte-equal
// signatures across all dispatch tiers.
func BatchSign(randSource io.Reader, privs []*PrivateKey, msgs [][]byte) ([][]byte, error) {
	n := len(privs)
	if n != len(msgs) {
		return nil, ErrBatchLength
	}
	sigs := make([][]byte, n)
	if n == 0 {
		return sigs, nil
	}
	mode := privs[0].mode
	for i := 1; i < n; i++ {
		if privs[i].mode != mode {
			return nil, errors.New("mldsa.BatchSign: mixed modes not supported")
		}
	}

	// Tier 1: GPU substrate.
	if n >= BatchThreshold {
		if _, ok := modeToCAPI(mode); ok {
			if ok, err := batchSignGPU(privs, msgs, sigs); ok && err == nil {
				return sigs, nil
			}
		}
	}

	// Tier 2: Goroutine-parallel CPU.
	if n >= concurrentBatchThreshold {
		return batchSignConcurrent(randSource, privs, msgs)
	}

	// Tier 3: Serial floor.
	for i := range privs {
		sig, err := privs[i].SignCtx(randSource, msgs[i], nil)
		if err != nil {
			return nil, err
		}
		sigs[i] = sig
	}
	return sigs, nil
}

// batchSignConcurrent runs FIPS 204 Sign across GOMAXPROCS goroutines. Each
// worker reads from its own io.Reader so the global rand source is not a
// contention point. We fan a single io.Reader out by serializing it through
// a mutex when nil (default crypto/rand) — the cost is amortized over the
// sign operation which is ~1ms for ML-DSA-65.
func batchSignConcurrent(randSource io.Reader, privs []*PrivateKey, msgs [][]byte) ([][]byte, error) {
	n := len(privs)
	sigs := make([][]byte, n)
	errs := make([]error, n)

	workers := runtime.GOMAXPROCS(0)
	if workers > n {
		workers = n
	}
	if workers < 2 {
		for i := range privs {
			sig, err := privs[i].SignCtx(randSource, msgs[i], nil)
			if err != nil {
				return nil, err
			}
			sigs[i] = sig
		}
		return sigs, nil
	}

	rand := randSource
	if rand == nil {
		rand = newDefaultRand()
	}
	// Serialize the rand source across workers — circl.SignTo reads ~32 bytes
	// per sign in hedged mode, which is fast enough that mutex contention is
	// dwarfed by the sign latency.
	var randMu sync.Mutex
	readerWrap := &serialReader{r: rand, mu: &randMu}

	var wg sync.WaitGroup
	chunk := (n + workers - 1) / workers
	for w := 0; w < workers; w++ {
		start := w * chunk
		if start >= n {
			break
		}
		end := start + chunk
		if end > n {
			end = n
		}
		wg.Add(1)
		go func(lo, hi int) {
			defer wg.Done()
			for i := lo; i < hi; i++ {
				sig, err := privs[i].SignCtx(readerWrap, msgs[i], nil)
				if err != nil {
					errs[i] = err
					return
				}
				sigs[i] = sig
			}
		}(start, end)
	}
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			return nil, err
		}
	}
	return sigs, nil
}

// serialReader is a thread-safe wrapper around io.Reader for use by parallel
// signing workers when the caller passes a non-concurrent-safe rand source.
type serialReader struct {
	r  io.Reader
	mu *sync.Mutex
}

func (s *serialReader) Read(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.r.Read(p)
}

// newDefaultRand returns crypto/rand.Reader. Pulled into a helper so the test
// suite can replace it without packaging-level shadowing.
func newDefaultRand() io.Reader { return rand.Reader }
