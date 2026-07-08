// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause
//
// lux/accel/c_api.h - C ABI for lux-accel
//
// This is the ONLY public interface for Go/FFI consumers.
// All symbols are exported with C linkage and stable ABI.

#ifndef LUX_ACCEL_C_API_H
#define LUX_ACCEL_C_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Symbol visibility
// =============================================================================

#if defined(_WIN32) || defined(__CYGWIN__)
  #ifdef LUX_ACCEL_BUILDING
    #define LUX_API __declspec(dllexport)
  #else
    #define LUX_API __declspec(dllimport)
  #endif
#elif defined(__GNUC__) || defined(__clang__)
  #define LUX_API __attribute__((visibility("default")))
#else
  #define LUX_API
#endif

// =============================================================================
// Opaque handles
// =============================================================================

typedef struct lux_session_t* lux_session;
typedef struct lux_tensor_t* lux_tensor;
typedef struct lux_buffer_t* lux_buffer;

// =============================================================================
// Status codes
// =============================================================================

typedef enum lux_status {
    LUX_OK = 0,
    LUX_ERROR = 1,
    LUX_OUT_OF_MEMORY = 2,
    LUX_INVALID_ARGUMENT = 3,
    LUX_NOT_SUPPORTED = 4,
    LUX_NO_BACKEND = 5,
    LUX_KERNEL_ERROR = 6,
    LUX_DISPATCH_FAILED = 7,
} lux_status;

// =============================================================================
// Backend types
// =============================================================================

typedef enum lux_backend_type {
    LUX_BACKEND_AUTO = 0,
    LUX_BACKEND_METAL = 1,
    LUX_BACKEND_WEBGPU = 2,
    LUX_BACKEND_CUDA = 3,
} lux_backend_type;

// =============================================================================
// Data types
// =============================================================================

typedef enum lux_dtype {
    LUX_DTYPE_F32 = 0,
    LUX_DTYPE_F16 = 1,
    LUX_DTYPE_F64 = 2,
    LUX_DTYPE_I32 = 3,
    LUX_DTYPE_I64 = 4,
    LUX_DTYPE_U8 = 5,
    LUX_DTYPE_U32 = 6,
    LUX_DTYPE_U64 = 7,
} lux_dtype;

// =============================================================================
// Device info
// =============================================================================

typedef struct lux_device_info {
    const char* name;
    const char* vendor;
    lux_backend_type backend;
    int is_discrete;
    int is_unified_memory;
    uint64_t total_memory;
    uint32_t max_workgroup_size;
    uint32_t simd_width;
} lux_device_info;

// =============================================================================
// Library initialization
// =============================================================================

// Initialize the library (call once at startup)
LUX_API lux_status lux_init(void);

// Shutdown and release all resources
LUX_API void lux_shutdown(void);

// Get library version string
LUX_API const char* lux_version(void);

// Get last error message (thread-local)
LUX_API const char* lux_get_error(void);

// =============================================================================
// Backend management
// =============================================================================

// Load a backend plugin from path (e.g., "liblux-metal.dylib")
LUX_API lux_status lux_load_backend(const char* path);

// Get number of available backends
LUX_API int lux_backend_count(void);

// Get backend type at index
LUX_API lux_backend_type lux_backend_type_at(int index);

// Get number of devices for a backend
LUX_API int lux_device_count(lux_backend_type backend);

// Get device info
LUX_API lux_status lux_get_device_info(lux_backend_type backend, int index, lux_device_info* info);

// =============================================================================
// Session management
// =============================================================================

// Create session with auto-detected best backend
LUX_API lux_status lux_session_create(lux_session* session);

// Create session with specific backend
LUX_API lux_status lux_session_create_with_backend(lux_backend_type backend, lux_session* session);

// Create session with specific device
LUX_API lux_status lux_session_create_with_device(lux_backend_type backend, int device_index, lux_session* session);

// Destroy session
LUX_API void lux_session_destroy(lux_session session);

// Synchronize all pending operations
LUX_API lux_status lux_session_sync(lux_session session);

// Get session device info
LUX_API lux_status lux_session_get_device_info(lux_session session, lux_device_info* info);

// =============================================================================
// Tensor operations
// =============================================================================

// Create tensor with shape
LUX_API lux_status lux_tensor_create(lux_session session, lux_dtype dtype,
                                      const size_t* shape, size_t ndim,
                                      lux_tensor* tensor);

// Create tensor with data
LUX_API lux_status lux_tensor_create_with_data(lux_session session, lux_dtype dtype,
                                                const size_t* shape, size_t ndim,
                                                const void* data, size_t data_bytes,
                                                lux_tensor* tensor);

// Destroy tensor
LUX_API void lux_tensor_destroy(lux_tensor tensor);

// Get tensor shape
LUX_API size_t lux_tensor_ndim(lux_tensor tensor);
LUX_API size_t lux_tensor_shape(lux_tensor tensor, size_t dim);
LUX_API size_t lux_tensor_numel(lux_tensor tensor);
LUX_API size_t lux_tensor_bytes(lux_tensor tensor);
LUX_API lux_dtype lux_tensor_dtype(lux_tensor tensor);

// Copy data to/from tensor
LUX_API lux_status lux_tensor_to_host(lux_tensor tensor, void* dst, size_t dst_bytes);
LUX_API lux_status lux_tensor_from_host(lux_tensor tensor, const void* src, size_t src_bytes);

// =============================================================================
// ML operations
// =============================================================================

LUX_API lux_status lux_matmul(lux_session session, lux_tensor a, lux_tensor b, lux_tensor c);
LUX_API lux_status lux_relu(lux_session session, lux_tensor input, lux_tensor output);
LUX_API lux_status lux_gelu(lux_session session, lux_tensor input, lux_tensor output);
LUX_API lux_status lux_softmax(lux_session session, lux_tensor input, lux_tensor output, int axis);
LUX_API lux_status lux_layer_norm(lux_session session, lux_tensor input,
                                   lux_tensor gamma, lux_tensor beta,
                                   lux_tensor output, float eps);
LUX_API lux_status lux_attention(lux_session session, lux_tensor q, lux_tensor k, lux_tensor v,
                                  lux_tensor output, float scale);

// =============================================================================
// Crypto operations
// =============================================================================

LUX_API lux_status lux_sha256(lux_session session, lux_tensor input, lux_tensor output);
LUX_API lux_status lux_keccak256(lux_session session, lux_tensor input, lux_tensor output);
LUX_API lux_status lux_poseidon(lux_session session, lux_tensor input, lux_tensor output);
LUX_API lux_status lux_ecdsa_verify_batch(lux_session session, lux_tensor messages,
                                           lux_tensor signatures, lux_tensor pubkeys,
                                           lux_tensor results);
LUX_API lux_status lux_ed25519_verify_batch(lux_session session, lux_tensor messages,
                                             lux_tensor signatures, lux_tensor pubkeys,
                                             lux_tensor results);
LUX_API lux_status lux_bls_verify_batch(lux_session session, lux_tensor messages,
                                         lux_tensor signatures, lux_tensor pubkeys,
                                         lux_tensor results);
LUX_API lux_status lux_merkle_root(lux_session session, lux_tensor leaves, lux_tensor root);

// =============================================================================
// ZK operations
// =============================================================================

LUX_API lux_status lux_ntt(lux_session session, lux_tensor input, lux_tensor output,
                            lux_tensor roots, uint64_t modulus);
LUX_API lux_status lux_intt(lux_session session, lux_tensor input, lux_tensor output,
                             lux_tensor inv_roots, uint64_t modulus);
LUX_API lux_status lux_msm(lux_session session, lux_tensor scalars, lux_tensor bases,
                            lux_tensor result);
LUX_API lux_status lux_poly_mul(lux_session session, lux_tensor a, lux_tensor b,
                                 lux_tensor c, uint64_t modulus);

// =============================================================================
// Lattice crypto operations
// =============================================================================

LUX_API lux_status lux_kyber_keygen(lux_session session, lux_tensor pk, lux_tensor sk);
LUX_API lux_status lux_kyber_encaps(lux_session session, lux_tensor pk,
                                     lux_tensor ct, lux_tensor ss);
LUX_API lux_status lux_kyber_decaps(lux_session session, lux_tensor ct,
                                     lux_tensor sk, lux_tensor ss);
LUX_API lux_status lux_dilithium_sign(lux_session session, lux_tensor msg,
                                       lux_tensor sk, lux_tensor sig);
LUX_API lux_status lux_dilithium_verify(lux_session session, lux_tensor msg,
                                         lux_tensor sig, lux_tensor pk, int* valid);

// =============================================================================
// SLH-DSA / Magnetar (FIPS 205) operations
// =============================================================================
//
// SLH-DSA is a stateless hash-based signature scheme (FIPS 205, formerly
// SPHINCS+). The Magnetar protocol slot (`0x012207`) lifts SLH-DSA into Lux's
// PQ-GPU dispatch path: public-DKG + Pedersen VSS for distributed key
// generation, MPC signing keeps the secret state distributed, and the
// per-validator verify side is batched across the cert quorum.
//
// Mode encoding mirrors the luxcpp/crypto/slhdsa C ABI:
//   2  -> SLH-DSA-SHA2-128f  (NIST L1)
//   3  -> SLH-DSA-SHA2-192f  (NIST L3)   <-- canonical for Magnetar profile
//   5  -> SLH-DSA-SHA2-256f  (NIST L5)
//   12 -> SLH-DSA-SHAKE-128f (NIST L1)
//   13 -> SLH-DSA-SHAKE-192f (NIST L3)
//   15 -> SLH-DSA-SHAKE-256f (NIST L5)
//
// Tensor shapes (n = batch size):
//   msgs    : LUX_DTYPE_U8, shape [n, msg_width]
//   sigs    : LUX_DTYPE_U8, shape [n, sig_bytes]   (sig_bytes per mode)
//   pks     : LUX_DTYPE_U8, shape [n, pk_bytes]    (pk_bytes per mode)
//   results : LUX_DTYPE_U8, shape [n]              (1 = valid, 0 = invalid)
//
// Batch verify dispatches the FIPS 205 verify per element. Result vector is
// dense (no early abort) so consumers can audit per-signer failures. Sign
// batch is provided symmetrically; deterministic per FIPS 205 (no nonces).

LUX_API lux_status lux_slhdsa_sign_batch(lux_session session, int mode,
                                          lux_tensor msgs, lux_tensor sks,
                                          lux_tensor sigs);
LUX_API lux_status lux_slhdsa_verify_batch(lux_session session, int mode,
                                            lux_tensor msgs, lux_tensor sigs,
                                            lux_tensor pks, lux_tensor results);

// =============================================================================
// FHE operations
// =============================================================================

LUX_API lux_status lux_bfv_encrypt(lux_session session, lux_tensor plaintext,
                                    lux_tensor pk, lux_tensor ciphertext);
LUX_API lux_status lux_bfv_decrypt(lux_session session, lux_tensor ciphertext,
                                    lux_tensor sk, lux_tensor plaintext);
LUX_API lux_status lux_bfv_add(lux_session session, lux_tensor ct1,
                                lux_tensor ct2, lux_tensor result);
LUX_API lux_status lux_bfv_multiply(lux_session session, lux_tensor ct1,
                                     lux_tensor ct2, lux_tensor relin_key,
                                     lux_tensor result);

// =============================================================================
// DEX operations
// =============================================================================

LUX_API lux_status lux_constant_product_swap(lux_session session,
                                              lux_tensor reserve_x, lux_tensor reserve_y,
                                              lux_tensor amount_in, int x_to_y,
                                              lux_tensor amount_out, float fee);
LUX_API lux_status lux_compute_twap(lux_session session, lux_tensor prices,
                                     lux_tensor timestamps, uint64_t start, uint64_t end,
                                     lux_tensor twap);
LUX_API lux_status lux_match_orders(lux_session session, lux_tensor bids, lux_tensor asks,
                                     lux_tensor matches, lux_tensor prices, lux_tensor amounts);

#ifdef __cplusplus
}
#endif

#endif // LUX_ACCEL_C_API_H
