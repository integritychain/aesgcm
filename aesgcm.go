package aesgcm

import (
	"crypto/rand"
	"io"
)

type aesgcm struct {
	ready bool
	eKey  [60]uint32 // Expanded key
	nk    int        // Number of words in key
	nr    int        // Number of rounds
	state [4][4]byte // State
}

const (
	nonceSize int = 12 // 12-byte, 96-bit nonce size
	overhead  int = 16 // 16-byte, 128-bit tag size
)

// NewAESGCM returns an instance of the simplest, strongest and fastest cipher configuration
// Internally generate 96-bit nonce, require 256-bit AES key and return 128-bit tag
func NewAESGCM(key []byte) *aesgcm {
	if len(key) != 32 {
		panic("Key length must be 32-bytes (256-bits)")
	}
	var newAESGCM = new(aesgcm)
	newAESGCM.Key(key)
	return newAESGCM
}

// NonceSize returns the size in bytes of the nonce that must be passed to Seal and Open.
func (aesgcm aesgcm) NonceSize() int {
	return nonceSize
}

// Overhead returns the maximum difference in bytes between the lengths of a plaintext and its ciphertext.
func (aesgcm aesgcm) Overhead() int {
	return overhead
}

func (aesgcm aesgcm) Seal(dst, nonce, plaintext, additionalData []byte) []byte { // What does this return????
	// magic here! what does it return?
	return nil
}

// Generate nonce, encrypt plaintext and authenticate additional data
// Return nonce || ciphertext || tag
func (aesgcm aesgcm) SimpleSeal(plaintext, additionalData []byte) []byte {
	var ciphertext = make([]byte, nonceSize+len(plaintext)+overhead)
	if _, err := io.ReadFull(rand.Reader, ciphertext[0:nonceSize]); err != nil {
		panic(err.Error())
	}
	aesgcm.Seal(ciphertext[nonceSize:nonceSize+len(plaintext)], ciphertext[0:nonceSize], plaintext, additionalData)
	return ciphertext
}

func (aesgcm aesgcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	// Magic here!
	return nil, nil
}

// Reuses buffer, consumes nonce
func (aesgcm aesgcm) SimpleOpen(nonce, message, additionalData []byte) error {
	return nil
}
