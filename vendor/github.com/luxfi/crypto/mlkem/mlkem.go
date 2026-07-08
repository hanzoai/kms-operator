// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mlkem provides a wrapper around github.com/cloudflare/circl/kem/mlkem
// for ML-KEM (Module-Lattice-based Key Encapsulation Mechanism) support.
package mlkem

import (
	"crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/mlkem/mlkem1024"
	"github.com/cloudflare/circl/kem/mlkem/mlkem512"
	"github.com/cloudflare/circl/kem/mlkem/mlkem768"
)

// Mode represents different security levels of ML-KEM
type Mode int

const (
	// MLKEM512 provides 128-bit security
	MLKEM512 Mode = iota
	// MLKEM768 provides 192-bit security
	MLKEM768
	// MLKEM1024 provides 256-bit security
	MLKEM1024
)

// String returns the string representation of the mode
func (m Mode) String() string {
	switch m {
	case MLKEM512:
		return "ML-KEM-512"
	case MLKEM768:
		return "ML-KEM-768"
	case MLKEM1024:
		return "ML-KEM-1024"
	default:
		return "unknown"
	}
}

// Key size constants for ML-KEM-512
const (
	MLKEM512PublicKeySize  = mlkem512.PublicKeySize
	MLKEM512PrivateKeySize = mlkem512.PrivateKeySize
	MLKEM512CiphertextSize = mlkem512.CiphertextSize
	MLKEM512SharedKeySize  = mlkem512.SharedKeySize
)

// Key size constants for ML-KEM-768
const (
	MLKEM768PublicKeySize  = mlkem768.PublicKeySize
	MLKEM768PrivateKeySize = mlkem768.PrivateKeySize
	MLKEM768CiphertextSize = mlkem768.CiphertextSize
	MLKEM768SharedKeySize  = mlkem768.SharedKeySize
)

// Key size constants for ML-KEM-1024
const (
	MLKEM1024PublicKeySize  = mlkem1024.PublicKeySize
	MLKEM1024PrivateKeySize = mlkem1024.PrivateKeySize
	MLKEM1024CiphertextSize = mlkem1024.CiphertextSize
	MLKEM1024SharedKeySize  = mlkem1024.SharedKeySize
)

// PublicKey represents a ML-KEM public key
type PublicKey struct {
	key  kem.PublicKey
	mode Mode
}

// PrivateKey represents a ML-KEM private key
type PrivateKey struct {
	key  kem.PrivateKey
	mode Mode
}

// Bytes returns the byte representation of the public key
func (pk *PublicKey) Bytes() []byte {
	if pk.key == nil {
		return nil
	}
	data, _ := pk.key.MarshalBinary()
	return data
}

// Bytes returns the byte representation of the private key
func (sk *PrivateKey) Bytes() []byte {
	if sk.key == nil {
		return nil
	}
	data, _ := sk.key.MarshalBinary()
	return data
}

// Equal reports whether pk and other represent the same public key
func (pk *PublicKey) Equal(other *PublicKey) bool {
	if pk.mode != other.mode {
		return false
	}
	if pk.key == nil || other.key == nil {
		return pk.key == other.key
	}
	return pk.key.Equal(other.key)
}

// Equal reports whether sk and other represent the same private key
func (sk *PrivateKey) Equal(other *PrivateKey) bool {
	if sk.mode != other.mode {
		return false
	}
	if sk.key == nil || other.key == nil {
		return sk.key == other.key
	}
	return sk.key.Equal(other.key)
}

// PublicKey returns the public key corresponding to this private key
func (sk *PrivateKey) PublicKey() *PublicKey {
	if sk.key == nil {
		return nil
	}
	return &PublicKey{
		key:  sk.key.Public(),
		mode: sk.mode,
	}
}

// ErrInvalidKeySize is returned when a key has an incorrect size
var ErrInvalidKeySize = errors.New("invalid key size")

// ErrInvalidCiphertextSize is returned when a ciphertext has an incorrect size
var ErrInvalidCiphertextSize = errors.New("invalid ciphertext size")

// GetPublicKeySize returns the size of a public key for the given mode
func GetPublicKeySize(mode Mode) int {
	switch mode {
	case MLKEM512:
		return MLKEM512PublicKeySize
	case MLKEM768:
		return MLKEM768PublicKeySize
	case MLKEM1024:
		return MLKEM1024PublicKeySize
	default:
		return 0
	}
}

// GetPrivateKeySize returns the size of a private key for the given mode
func GetPrivateKeySize(mode Mode) int {
	switch mode {
	case MLKEM512:
		return MLKEM512PrivateKeySize
	case MLKEM768:
		return MLKEM768PrivateKeySize
	case MLKEM1024:
		return MLKEM1024PrivateKeySize
	default:
		return 0
	}
}

// GetCiphertextSize returns the size of a ciphertext for the given mode
func GetCiphertextSize(mode Mode) int {
	switch mode {
	case MLKEM512:
		return MLKEM512CiphertextSize
	case MLKEM768:
		return MLKEM768CiphertextSize
	case MLKEM1024:
		return MLKEM1024CiphertextSize
	default:
		return 0
	}
}

// getScheme returns the appropriate KEM scheme for the mode
func getScheme(mode Mode) kem.Scheme {
	switch mode {
	case MLKEM512:
		return mlkem512.Scheme()
	case MLKEM768:
		return mlkem768.Scheme()
	case MLKEM1024:
		return mlkem1024.Scheme()
	default:
		return nil
	}
}

// GenerateKeyPair generates a new ML-KEM key pair with a specific reader
func GenerateKeyPair(reader io.Reader, mode Mode) (*PublicKey, *PrivateKey, error) {
	scheme := getScheme(mode)
	if scheme == nil {
		return nil, nil, errors.New("invalid mode")
	}

	if reader == nil {
		reader = rand.Reader
	}

	seed := make([]byte, scheme.SeedSize())
	if _, err := io.ReadFull(reader, seed); err != nil {
		return nil, nil, err
	}

	pubKey, privKey := scheme.DeriveKeyPair(seed)

	return &PublicKey{
			key:  pubKey,
			mode: mode,
		}, &PrivateKey{
			key:  privKey,
			mode: mode,
		}, nil
}

// GenerateKey generates a new ML-KEM key pair using crypto/rand
func GenerateKey(mode Mode) (*PublicKey, *PrivateKey, error) {
	return GenerateKeyPair(rand.Reader, mode)
}

// Encapsulate generates a shared secret and ciphertext
func (pk *PublicKey) Encapsulate(reader ...io.Reader) ([]byte, []byte, error) {
	if pk == nil || pk.key == nil {
		return nil, nil, errors.New("nil public key")
	}

	var r io.Reader = rand.Reader
	if len(reader) > 0 && reader[0] != nil {
		r = reader[0]
	}

	scheme := getScheme(pk.mode)
	if scheme == nil {
		return nil, nil, errors.New("invalid mode")
	}

	seed := make([]byte, scheme.EncapsulationSeedSize())
	if _, err := io.ReadFull(r, seed); err != nil {
		return nil, nil, err
	}

	ciphertext, sharedKey, err := scheme.EncapsulateDeterministically(pk.key, seed)
	if err != nil {
		return nil, nil, err
	}
	return ciphertext, sharedKey, nil
}

// Decapsulate recovers the shared secret from a ciphertext
func (sk *PrivateKey) Decapsulate(ciphertext []byte) ([]byte, error) {
	if sk == nil || sk.key == nil {
		return nil, errors.New("nil private key")
	}

	expectedSize := GetCiphertextSize(sk.mode)
	if len(ciphertext) != expectedSize {
		return nil, ErrInvalidCiphertextSize
	}

	scheme := getScheme(sk.mode)
	if scheme == nil {
		return nil, errors.New("invalid mode")
	}

	sharedKey, err := scheme.Decapsulate(sk.key, ciphertext)
	if err != nil {
		return nil, err
	}
	return sharedKey, nil
}

// PublicKeyFromBytes creates a public key from its byte representation
func PublicKeyFromBytes(data []byte, mode Mode) (*PublicKey, error) {
	scheme := getScheme(mode)
	if scheme == nil {
		return nil, errors.New("invalid mode")
	}

	if len(data) != GetPublicKeySize(mode) {
		return nil, ErrInvalidKeySize
	}

	pubKey, err := scheme.UnmarshalBinaryPublicKey(data)
	if err != nil {
		return nil, err
	}

	return &PublicKey{
		key:  pubKey,
		mode: mode,
	}, nil
}

// PrivateKeyFromBytes creates a private key from its byte representation
func PrivateKeyFromBytes(data []byte, mode Mode) (*PrivateKey, error) {
	scheme := getScheme(mode)
	if scheme == nil {
		return nil, errors.New("invalid mode")
	}

	if len(data) != GetPrivateKeySize(mode) {
		return nil, ErrInvalidKeySize
	}

	privKey, err := scheme.UnmarshalBinaryPrivateKey(data)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		key:  privKey,
		mode: mode,
	}, nil
}
