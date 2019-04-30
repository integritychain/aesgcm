package aesgcm

import (
	"crypto/rand"
	"encoding/binary"
	"io"
)

// TODO:
//  2. Figure out spec for returned ciphertext, IV, Tag
//  3. Run code coverage on unit test - any dead code that can be backed off
//  4. Name internal variables to match spec
//  5. Build solid plaintext only
//  6. Add associated data
//  7. SIMPLIFY!!!
//  8. Figure out how to parse CAVP testcases

type aesgcm struct {
	ready      bool
	eKey       [60]uint32 // Expanded expandKey
	nk         int        // Number of words in expandKey
	nr         int        // Number of rounds
	state      [4][4]byte // State
	h          bWord
	icb        bWord
	eky0       bWord
	lenAlenC   bWord
	runningTag bWord
}

const (
	nonceSize int = 12 // 12-byte, 96-bit nonce size
	overhead  int = 16 // 16-byte, 128-bit tag size
)

// Maybe add AEAD New ; then need to adapt nonceSize and overhead?

func NewAESGCM(key []byte) *aesgcm {
	var keyLength = len(key) // Bytes
	if (keyLength != 16) && (keyLength != 24) && (keyLength != 32) {
		panic("expandKey length must be 128, 192 or 256 bits")
	}
	var newAESGCM = new(aesgcm)
	newAESGCM.expandKey(key)
	newAESGCM.initH(key)
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

func (aesgcm *aesgcm) Seal(dst []byte, nonce []byte, plaintext, additionalData []byte) []byte { // What does this return????
	if len(nonce) != 12 {
		panic("Nonce must be 12 bytes")
	}
	// Ultimately push a bunch of this into gcm.go
	aesgcm.lenAlenC.left = uint64(len(additionalData)) * 8
	aesgcm.lenAlenC.right = uint64(len(plaintext)) * 8
	aesgcm.genICB(nonce)
	aesgcm.calcEky0() // Do not remove until everything works!
	var cipher = make([]byte, len(plaintext)+(len(plaintext)%16)+overhead)
	var index = 0

	for len(plaintext) > index {

		aesgcm.icb = incM32(aesgcm.icb)
		var xx = make([]byte, 16)

		binary.BigEndian.PutUint64(xx[0:8], aesgcm.icb.left)
		binary.BigEndian.PutUint64(xx[8:16], aesgcm.icb.right)
		var result = aesgcm.encrypt(xx)
		for i := 0; i < min(16, len(plaintext)-index); i++ {
			cipher[i+index] = plaintext[i+index] ^ result[i]
		}
		var bC = bytes2bWord(cipher[index : index+16])
		var X = bXor(aesgcm.runningTag, bC)
		aesgcm.runningTag = xMuly(X, aesgcm.h)
		index += 16
	}

	aesgcm.runningTag = xMuly(bXor(aesgcm.runningTag, aesgcm.lenAlenC), aesgcm.h)
	aesgcm.runningTag = bXor(aesgcm.runningTag, aesgcm.eky0)
	//fmt.Printf("tag: %x", aesgcm.runningTag)
	copy(cipher[len(plaintext):len(plaintext)+overhead], bWord2Bytes(aesgcm.runningTag))
	return cipher[0 : len(plaintext)+overhead]
}

// Generate nonce, encrypt plaintext and authenticate additional data
// Return nonce || ciphertext || tag
func (aesgcm aesgcm) SimpleSeal(plaintext, additionalData []byte) []byte {
	var ciphertext = make([]byte, nonceSize+len(plaintext)+overhead)
	if _, err := io.ReadFull(rand.Reader, ciphertext[0:nonceSize]); err != nil {
		panic(err.Error())
	}
	///oooga	aesgcm.Seal(ciphertext[nonceSize:nonceSize+len(plaintext)], ciphertext[0:nonceSize], plaintext, additionalData)
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
