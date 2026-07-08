package accel

// LatticeOps provides GPU-accelerated lattice-based cryptography operations.
// Implements NIST post-quantum standards: ML-KEM (Kyber) and ML-DSA (Dilithium).
type LatticeOps interface {
	// KyberKeyGen generates Kyber (ML-KEM) key pair.
	// pk: [1184] bytes (Kyber768 public key)
	// sk: [2400] bytes (Kyber768 secret key)
	KyberKeyGen(pk, sk *UntypedTensor) error

	// KyberKeyGenBatch generates multiple key pairs in parallel.
	// pk: [N, 1184] bytes
	// sk: [N, 2400] bytes
	KyberKeyGenBatch(pk, sk *UntypedTensor) error

	// KyberEncaps encapsulates shared secret.
	// pk: [1184] bytes public key
	// ct: [1088] bytes ciphertext output
	// ss: [32] bytes shared secret output
	KyberEncaps(pk, ct, ss *UntypedTensor) error

	// KyberEncapsBatch performs batch encapsulation.
	// pk: [N, 1184] bytes
	// ct: [N, 1088] bytes
	// ss: [N, 32] bytes
	KyberEncapsBatch(pk, ct, ss *UntypedTensor) error

	// KyberDecaps decapsulates shared secret.
	// ct: [1088] bytes ciphertext
	// sk: [2400] bytes secret key
	// ss: [32] bytes shared secret output
	KyberDecaps(ct, sk, ss *UntypedTensor) error

	// KyberDecapsBatch performs batch decapsulation.
	// ct: [N, 1088] bytes
	// sk: [N, 2400] bytes
	// ss: [N, 32] bytes
	KyberDecapsBatch(ct, sk, ss *UntypedTensor) error

	// DilithiumKeyGen generates Dilithium (ML-DSA) key pair.
	// pk: [1952] bytes (Dilithium3 public key)
	// sk: [4016] bytes (Dilithium3 secret key)
	DilithiumKeyGen(pk, sk *UntypedTensor) error

	// DilithiumSign signs a message.
	// msg: [msg_len] bytes message
	// sk: [4016] bytes secret key
	// sig: [3293] bytes signature output
	DilithiumSign(msg, sk, sig *UntypedTensor) error

	// DilithiumSignBatch signs multiple messages in parallel.
	// msgs: [N, msg_len] bytes
	// sk: [4016] bytes (same key for all)
	// sigs: [N, 3293] bytes
	DilithiumSignBatch(msgs, sk, sigs *UntypedTensor) error

	// DilithiumVerify verifies a signature.
	// msg: [msg_len] bytes
	// sig: [3293] bytes
	// pk: [1952] bytes
	// Returns true if valid.
	DilithiumVerify(msg, sig, pk *UntypedTensor) (bool, error)

	// DilithiumVerifyBatch verifies multiple signatures.
	// msgs: [N, msg_len] bytes
	// sigs: [N, 3293] bytes
	// pks: [N, 1952] bytes
	// results: [N] uint8 (1 = valid, 0 = invalid)
	DilithiumVerifyBatch(msgs, sigs, pks, results *UntypedTensor) error

	// MLDSAVerifyBatch verifies a batch of ML-DSA / Dilithium signatures at the
	// given FIPS 204 NIST level. Unlike DilithiumVerifyBatch (which is pinned to
	// ML-DSA-65 / Dilithium3 for backwards compatibility), this entry point
	// accepts mode in {2, 3, 5} for ML-DSA-44, ML-DSA-65, ML-DSA-87 respectively.
	//
	// Tensor shapes (n = batch size, per FIPS 204):
	//   ML-DSA-44 : pk=1312  sig=2420
	//   ML-DSA-65 : pk=1952  sig=3309
	//   ML-DSA-87 : pk=2592  sig=4627
	//
	// msgs    : LUX_DTYPE_U8, shape [n, msg_width] (zero-padded right)
	// sigs    : LUX_DTYPE_U8, shape [n, sig_bytes]
	// pks     : LUX_DTYPE_U8, shape [n, pk_bytes]
	// results : LUX_DTYPE_U8, shape [n] (1 = valid, 0 = invalid)
	//
	// FIPS 204 verify is deterministic, so GPU and CPU paths produce
	// byte-identical accept/reject decisions per element. The results vector is
	// dense (no early abort) so callers can audit per-signer outcomes.
	MLDSAVerifyBatch(mode int, msgs, sigs, pks, results *UntypedTensor) error

	// MLDSASignBatch signs a batch of messages with ML-DSA / Dilithium at the
	// given FIPS 204 NIST level. mode in {2, 3, 5}.
	//
	// Sizes (FIPS 204):
	//   ML-DSA-44 : sk=2560  sig=2420
	//   ML-DSA-65 : sk=4032  sig=3309
	//   ML-DSA-87 : sk=4896  sig=4627
	//
	// msgs : [n, msg_width] bytes (zero-padded right)
	// sks  : [n, sk_bytes]  bytes
	// sigs : [n, sig_bytes] bytes
	//
	// ML-DSA signing is deterministic in hedged mode (per FIPS 204 §3.4) when
	// the deterministic flag is set; the GPU path must select the same hedging
	// mode as the caller-side CPU reference to remain byte-equal for KAT.
	MLDSASignBatch(mode int, msgs, sks, sigs *UntypedTensor) error

	// SLHDSASignBatch signs a batch of messages with SLH-DSA / Magnetar (FIPS 205).
	// mode encodes the parameter set:
	//   2  = SHA2-128f, 3  = SHA2-192f, 5  = SHA2-256f
	//   12 = SHAKE-128f, 13 = SHAKE-192f, 15 = SHAKE-256f
	// msgs: [N, msg_width] bytes (zero-padded right)
	// sks:  [N, sk_bytes]  bytes (per-mode: 64 / 96 / 128)
	// sigs: [N, sig_bytes] bytes (per-mode: 17088 / 35664 / 49856 for 'f')
	SLHDSASignBatch(mode int, msgs, sks, sigs *UntypedTensor) error

	// SLHDSAVerifyBatch verifies a batch of SLH-DSA / Magnetar (FIPS 205)
	// signatures. mode encoding as for SLHDSASignBatch. Results vector is
	// dense (no early abort) so callers can audit per-signer outcomes.
	// msgs:    [N, msg_width] bytes
	// sigs:    [N, sig_bytes] bytes
	// pks:     [N, pk_bytes]  bytes (per-mode: 32 / 48 / 64)
	// results: [N] uint8 (1 = valid, 0 = invalid)
	SLHDSAVerifyBatch(mode int, msgs, sigs, pks, results *UntypedTensor) error

	// PolynomialNTT performs NTT in lattice polynomial ring.
	// Operates on polynomials in Z_q[X]/(X^256 + 1).
	PolynomialNTT(input, output *UntypedTensor, q uint32) error

	// PolynomialINTT performs inverse NTT.
	PolynomialINTT(input, output *UntypedTensor, q uint32) error

	// PolynomialMul multiplies polynomials in NTT domain.
	PolynomialMul(a, b, c *UntypedTensor, q uint32) error

	// PolynomialAdd adds polynomials.
	PolynomialAdd(a, b, c *UntypedTensor, q uint32) error
}
