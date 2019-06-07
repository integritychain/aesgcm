package aesgcm

import (
	"bytes"
	"crypto/cipher"
	"errors"
)

// TODO:
//  1. Get all the tests working (again)
//  1. Benchmark vs Golang
//  2. SIMPLIFY, TUNE!!!

type aesgcm struct {
	expandedAesKey [60]uint32
	nr             int // Number of rounds
	state          [4][4]byte
	h              blockWord
	icb            blockWord
	eky0           blockWord
	lenAlenC       blockWord
	runningTag     blockWord
	//M              [16][256]blockWord
}

const (
	defaultNonceSize int = 12 // 12-byte, 96-bit nonce size (minimum?)
	defaultTagSize   int = 16 // 16-byte, 128-bit tag size
)

func NewAESGCM(key []byte) cipher.AEAD {
	if (len(key) != 16) && (len(key) != 24) && (len(key) != 32) {
		panic("Aesgcm does not support key lengths other than 128, 192 or 256 bits")
	}
	var aesgcm = new(aesgcm)
	aesgcm.expandAesKey(key)
	aesgcm.initGcmH(key)
	return aesgcm
}

// NonceSize returns the size in bytes of the nonce that must be passed to Seal and Open.
func (aesgcm *aesgcm) NonceSize() int {
	return defaultNonceSize
}

// Overhead returns the difference in bytes between the lengths of a plaintext and its ciphertext (e.g. tag size).
func (aesgcm *aesgcm) Overhead() int {
	return defaultTagSize
}

func (aesgcm *aesgcm) Seal(dst []byte, nonce []byte, plaintext, additionalData []byte) []byte {
	if len(nonce) != defaultNonceSize {
		panic("Nonce must be 12 bytes")
	} // Check for nil dst and subtle overlap
	dst = growAsNeeded(dst, len(plaintext)+defaultTagSize)
	aesgcm.initGcmY0(len(additionalData), len(plaintext), nonce)
	aesgcm.runningTag = aesgcm.gHash(additionalData, blockWord{0, 0})
	aesgcm.cipherBlocks(plaintext, dst)
	aesgcm.runningTag = aesgcm.gHash(dst[:len(plaintext)], aesgcm.runningTag)
	xx1 := bwXor(aesgcm.runningTag, aesgcm.lenAlenC)
	xx2left, xx2right := gMul(xx1.left, xx1.right, aesgcm.h.left, aesgcm.h.right)
	aesgcm.runningTag.left = xx2left
	aesgcm.runningTag.right = xx2right
	aesgcm.runningTag = bwXor(aesgcm.runningTag, aesgcm.eky0)
	copy(dst[len(plaintext):], bWord2Bytes(aesgcm.runningTag))
	return dst
}

func (aesgcm aesgcm) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != defaultNonceSize {
		panic("Nonce must be 12 bytes")
	} // Check for nil dst and subtle overlap
	dst = growAsNeeded(dst, len(ciphertext)-defaultTagSize)
	aesgcm.initGcmY0(len(additionalData), len(ciphertext)-defaultTagSize, nonce)
	aesgcm.runningTag = aesgcm.gHash(additionalData, blockWord{0, 0})
	aesgcm.runningTag = aesgcm.gHash(ciphertext[:len(ciphertext)-defaultTagSize], aesgcm.runningTag)
	xx1 := bwXor(aesgcm.runningTag, aesgcm.lenAlenC)
	xx2left, xx2right := gMul(xx1.left, xx1.right, aesgcm.h.left, aesgcm.h.right)
	aesgcm.runningTag.left = xx2left
	aesgcm.runningTag.right = xx2right
	aesgcm.runningTag = bwXor(aesgcm.runningTag, aesgcm.eky0)
	if !bytes.Equal(ciphertext[len(ciphertext)-defaultTagSize:], bWord2Bytes(aesgcm.runningTag)) {
		dst = nil
		return nil, errors.New("cipher: message authentication failed")
	}
	aesgcm.cipherBlocks(ciphertext[:len(ciphertext)-defaultTagSize], dst)
	return dst, nil
}

func growAsNeeded(slice []byte, length int) []byte {
	if cap(slice) >= length {
		return slice[:length]
	} else {
		return append(slice, make([]byte, length-len(slice))...)
	}
}
