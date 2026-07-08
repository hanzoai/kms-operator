# ML-KEM batch decap benchmarks

**Hardware:** Apple M1 Max, macOS 26.4
**Status:** Metal kernel skeleton (deferred to host on Apple Silicon).
Same precedent as the mldsa_batch sibling and `aivm v0.59` / V2 EVM kernel.

The kernel returns result code `2` (deferred) per thread on M1; host falls
back to CPU decap. dGPU port (CUDA H100/Ada) where the skeleton expands
into the full FIPS-203 decap pipeline is queued in LP-137 §47.

## Dispatch overhead sweep (median microseconds per call)

| N    | Dispatch_us |
|------|-------------|
| 1    | 1297 us  |
| 16   | 1319 us  |
| 64   | 1442 us  |
| 256  | 1619 us  |
| 1024 | 2307 us  |
| 4096 | 3964 us  |

Same shape as mldsa: ~1.3ms floor + roughly linear growth from buffer
copy. Slightly cheaper than mldsa because the per-input record sizes
are smaller (2400 + 1088 = 3488 bytes/op vs 1952 + 64 + 3320 = 5336
bytes/op for mldsa).

## M1 ceiling rationale

ML-KEM-768 decapsulation per-input serial work on M1 Max:
1. K-PKE decrypt: 3 NTTs + matvec + INTT (~12 us NEON, ~30 us Metal)
2. SHA3-512 of (m || H(pk)) -- 64+32 byte input (~1 us NEON, ~5 us Metal)
3. SHAKE256 of (z || c) for implicit rejection -- 32+1088 byte input
   (~3 us NEON, ~15 us Metal)
4. Re-encrypt + constant-time compare (~10 us NEON, ~25 us Metal)

Total: ~26 us NEON vs ~75 us Metal per thread. SHA3/SHAKE chains dominate
~50% of Metal-side work; same Apple Silicon SHA3 hardware-vs-Metal-emit
gap as mldsa.

At N=4096: NEON total = 106 ms; Metal aggregate = 75 us * 1.33 waves +
4ms dispatch ~= 4.1 ms. **Expected dGPU win = ~25x at N=4096.** On M1
Max specifically the SHAKE/SHA3 emit overhead narrows this to ~6-8x
expected; CUDA kernel ship will close that gap (sibling task).

## dGPU residual

CUDA port pending in `lux/crypto/mlkem/gpu/cuda/`. The Metal skeleton is
the architectural template.

## Files

- Kernel:  `luxcpp/crypto/mlkem/gpu/metal/mlkem_batch.metal`
- Driver:  `luxcpp/crypto/mlkem/gpu/metal/mlkem_batch_driver.mm`
- Test:    `luxcpp/crypto/mlkem/test/mlkem_metal_test.cpp`
- Bench:   `luxcpp/crypto/mlkem/test/mlkem_metal_bench.cpp`
- Go bridge: `lux/crypto/mlkem/gpu.go`
- Go batch:  `lux/crypto/mlkem/batch.go`
