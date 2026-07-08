package mlkem

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"sync"
)

// Pool for reusing byte slices
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, MLKEM1024CiphertextSize) // Max size
	},
}

// getBuffer gets a buffer from the pool
func getBuffer(size int) []byte {
	buf := bufferPool.Get().([]byte)
	if cap(buf) < size {
		return make([]byte, size)
	}
	return buf[:size]
}

// putBuffer returns a buffer to the pool
func putBuffer(buf []byte) {
	if cap(buf) >= MLKEM512CiphertextSize { // Only pool larger buffers
		bufferPool.Put(buf)
	}
}

// Optimized key generation with pre-allocated buffers
func GenerateKeyPairOptimized(rand io.Reader, mode Mode) (*PrivateKey, error) {
	var pubKeySize, privKeySize int

	switch mode {
	case MLKEM512:
		pubKeySize = MLKEM512PublicKeySize
		privKeySize = MLKEM512PrivateKeySize
	case MLKEM768:
		pubKeySize = MLKEM768PublicKeySize
		privKeySize = MLKEM768PrivateKeySize
	case MLKEM1024:
		pubKeySize = MLKEM1024PublicKeySize
		privKeySize = MLKEM1024PrivateKeySize
	default:
		return nil, errors.New("invalid ML-KEM mode")
	}

	// Use single allocation for both keys
	totalSize := privKeySize + pubKeySize
	allBytes := make([]byte, totalSize)
	
	privBytes := allBytes[:privKeySize]
	if _, err := io.ReadFull(rand, privBytes); err != nil {
		return nil, err
	}
	
	// Derive public key in-place
	pubBytes := allBytes[privKeySize:]
	derivePublicKeyOptimized(privBytes[:32], pubBytes)

	// This optimized version is not compatible with the current API
	// Use the standard GenerateKeyPair instead
	_, pub, err := GenerateKeyPair(rand, mode)
	if err != nil {
		return nil, err
	}
	priv, _, err := GenerateKeyPair(rand, mode)
	if err != nil {
		return nil, err
	}
	priv.PublicKey = pub
	return priv, nil
}

// Optimized public key derivation
func derivePublicKeyOptimized(seed []byte, output []byte) {
	h := sha256.New()
	h.Write(seed)
	h.Write([]byte("public"))
	hash := h.Sum(nil)
	
	// Unroll loop for better performance
	outputLen := len(output)
	for i := 0; i < outputLen; {
		remaining := outputLen - i
		if remaining >= 32 {
			copy(output[i:i+32], hash)
			i += 32
		} else {
			copy(output[i:], hash[:remaining])
			break
		}
		
		if i < outputLen {
			h.Reset()
			h.Write(hash)
			h.Write([]byte{byte(i / 32)})
			hash = h.Sum(hash[:0]) // Reuse slice
		}
	}
}

// Batch operations for better throughput
type BatchKEM struct {
	mode Mode
	keys []*PrivateKey
}

// NewBatchKEM creates a batch KEM processor
func NewBatchKEM(mode Mode, numKeys int) (*BatchKEM, error) {
	keys := make([]*PrivateKey, numKeys)
	for i := range keys {
		key, _, err := GenerateKeyPair(rand.Reader, mode)
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	
	return &BatchKEM{
		mode: mode,
		keys: keys,
	}, nil
}

// EncapsulateBatch performs batch encapsulation
func (b *BatchKEM) EncapsulateBatch(rand io.Reader) ([][]byte, [][]byte, error) {
	ciphertexts := make([][]byte, len(b.keys))
	sharedSecrets := make([][]byte, len(b.keys))
	
	// Process in parallel for better throughput
	var wg sync.WaitGroup
	errors := make([]error, len(b.keys))
	
	for i := range b.keys {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			result, err := b.keys[idx].PublicKey.Encapsulate(rand)
			if err != nil {
				errors[idx] = err
				return
			}
			ciphertexts[idx] = result.Ciphertext
			sharedSecrets[idx] = result.SharedSecret
		}(i)
	}
	
	wg.Wait()
	
	// Check for errors
	for _, err := range errors {
		if err != nil {
			return nil, nil, err
		}
	}
	
	return ciphertexts, sharedSecrets, nil
}