# FIPS 204 Traceability — `luxfi/crypto/mldsa`

This document maps every parameter set, function, and wire structure in
`github.com/luxfi/crypto/mldsa` to the corresponding section of
**FIPS 204 (Module-Lattice-Based Digital Signature Standard)**, published
by NIST in August 2024.

> **Status:** all three parameter sets (ML-DSA-44/65/87) are FIPS-204-
> conformant in the per-validator (single-party) sign+verify path. The
> threshold variant lives in `luxfi/threshold/protocols/mldsa` and is
> research-preview, not FIPS-conformant (no signer yet).

## Parameter sets — FIPS 204 §4 (Table 1)

| Lux constant | FIPS 204 name | Security category | pk size | sk size | sig size |
|---|---|---|---|---|---|
| `MLDSA44` | ML-DSA-44 | Category 2 (~128-bit classical) | 1312 B | 2560 B | 2420 B |
| `MLDSA65` | ML-DSA-65 | Category 3 (~192-bit classical) | 1952 B | 4032 B | 3309 B |
| `MLDSA87` | ML-DSA-87 | Category 5 (~256-bit classical) | 2592 B | 4896 B | 4627 B |

Size constants in `mldsa.go` (`MLDSA44PublicKeySize`, …) re-export the
CIRCL upstream values verbatim. The values are pinned in
`TestSizeConstants_FIPS204` (KAT-replay suite) — any drift fails the
test.

## Algorithm map — FIPS 204 §5

| FIPS 204 algorithm | Section | Lux entry point | Backend |
|---|---|---|---|
| `ML-DSA.KeyGen` | §5.1, Algorithm 1 | `mldsa.GenerateKey(mode, rand)` | CIRCL `mldsa{44,65,87}.GenerateKey` (pure Go) or pq-crystals C ref (CGO) |
| `ML-DSA.Sign` | §5.2, Algorithm 2 | `PrivateKey.Sign(rand, msg, opts)` (implements `crypto.Signer`) | CIRCL `mldsa{44,65,87}.SignTo` |
| `ML-DSA.Verify` | §5.3, Algorithm 3 | `Verify(pk, msg, sig)` / `PublicKey.Verify(msg, sig)` | CIRCL `mldsa{44,65,87}.Verify` |

The "hash variant" path of FIPS 204 §5.4 (HashML-DSA) is **not exposed**
by this package today. Callers that need pre-hash sign should compute
the hash and call the standard Sign over the digest — Lux's bridge and
warp paths do this explicitly so the externally-visible domain
separation is auditable.

## Wire encoding — FIPS 204 §7

All keys and signatures use FIPS 204 byte encodings verbatim (no
length prefix, no version byte) — `crypto.Signer.Sign` returns
`[]byte` of `MLDSAxxSignatureSize`. Cross-implementation
byte-compatibility is verified by `TestMLDSA*_KATReplay` against
fixed-seed reference vectors.

## KAT (Known-Answer Test) coverage

| Test | Vector source | What it pins |
|---|---|---|
| `TestMLDSA44_KATReplay` | self-generated, fixed seed | keygen-determinism + sign-determinism |
| `TestMLDSA65_KATReplay` | self-generated, fixed seed | same, level 3 |
| `TestMLDSA87_KATReplay` | self-generated, fixed seed | same, level 5 |
| `TestMLDSA65KAT_VerifyKnownGood` | hard-coded `katSigPrefixHex` | reference signature prefix matches CIRCL output |
| `TestMLDSA65KAT_VerifyRejectsWrongMessage` | hard-coded | unforgeability sanity |
| `TestMLDSA65KAT_VerifyRejectsTamperedSig` | hard-coded | sig-bit-flip detection |
| `TestMLDSA65KAT_SeedStability` | hard-coded | seed→keypair stability across releases |
| `TestMLDSA65KAT_AllModes` (subtests for 44/65/87) | hard-coded | all three parameter sets tested |

**Gap.** The above tests pin *self-generated* determinism. They do
**not** load NIST CAVP `.rsp` reference vectors. The C generator at
`c/ref/nistkat/PQCgenKAT_sign.c` exists upstream from pq-crystals but
its emitted `.rsp` vectors are not checked into this repo and the Go
side never consumes them.

**Plan:** land NIST CAVP vectors for ML-DSA-44 / 65 / 87 under
`c/ref/nistkat/responses/` (run the C generator, commit the `.rsp`),
add a `nist_kat_test.go` that parses the format and asserts every
keygen + sign matches. Tracked as a 1-day fix in
`luxfi/threshold/protocols/mldsa/README.md` § "Gap to solid and done".

## Constant-time considerations — FIPS 204 §3.3.1

CIRCL's ML-DSA implementation runs in constant time for the secret-key
path; pq-crystals C reference does the same for the CGO path. We
**do not** currently run `dudect` against either path inside Lux CI —
add this as part of the multi-week hardening when the threshold signer
lands and needs CT validation under its own per-party sign path.

## Test entrypoints

| File | Purpose |
|---|---|
| `kat_test.go` | KAT-replay suite (above) |
| `mldsa_test.go` | functional sign / verify / round-trip / cross-mode rejection |
| `fuzz_test.go` | sign + verify malformed inputs, randomized API surface |
| `provenance_test.go` | wire-format provenance + CGO/pure-Go dispatch determinism |
| `batch_test.go` | batched verify path determinism |
| `gpu_44_test.go` / `gpu_87_test.go` | optional GPU backend regression |

## Cross-references

- FIPS 204: <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf>
- Per-validator usage: `luxfi/warp` `MLDSACertSet` (one signature per validator, no aggregation primitive)
- Bridge profile constants: `luxfi/bridge/profile.go` (`SchemeMLDSA65`, `SchemeMLDSA87`, `AuthMLDSA87`, `AuthMultisigMLDSA`)
- Research-preview threshold scaffold: `luxfi/threshold/protocols/mldsa`
- Magnetar (FIPS 205 SLH-DSA) sibling for hash-based PQ: `luxfi/magnetar`
- ML-KEM (FIPS 203, transport) sibling: `luxfi/crypto/mlkem`
