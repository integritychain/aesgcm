package aesgcm

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

// TODO:
//  0. Clean-up code further...
//  1. Name internal variables to match spec
//  2. Add associated data
//  3. Pass all CAVP tests
//  4. Sprinkle some fails into CAVP dataset
//  5. Consider supporting longer IVs
//  6. Run code coverage on unit test - any dead code that can be backed off
//  7. SIMPLIFY!!!

type aesgcm struct {
	ready      bool
	eKey       [60]uint32 // Expanded expandKey
	nk         int        // Number of words in expandKey
	nr         int        // Number of rounds
	state      [4][4]byte // State
	h          blockWord
	icb        blockWord
	eky0       blockWord
	lenAlenC   blockWord
	runningTag blockWord
}

const (
	nonceSize int = 12 // 12-byte, 96-bit nonce size (minimum?)
	overhead  int = 16 // 16-byte, 128-bit tag size
)

func NewAESGCM(key []byte) *aesgcm {
	var keyLength = len(key) // Bytes
	if (keyLength != 16) && (keyLength != 24) && (keyLength != 32) {
		panic("Key length must be 128, 192 or 256 bits")
	}
	var newAESGCM = new(aesgcm)
	newAESGCM.expandKey(key)
	newAESGCM.initializeH(key)
	return newAESGCM
}

// NonceSize returns the size in bytes of the nonce that must be passed to Seal and Open.
func (aesgcm aesgcm) NonceSize() int {
	return nonceSize
}

// Overhead returns the difference in bytes between the lengths of a plaintext and its ciphertext (e.g. tag size).
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
	aesgcm.calcEky0()                                               // Do not remove until everything works!
	var cipher = make([]byte, 16*((len(plaintext)+15)/16)+overhead) // not exactly right?
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
		index += 16
	}

	var freshAAD = make([]byte, 16*((len(additionalData)+15)/16))
	copy(freshAAD, additionalData)

	aesgcm.runningTag = aesgcm.gHash(append(freshAAD, cipher[0:16*((len(plaintext)+15)/16)]...))

	aesgcm.runningTag = bwXMulY(bwXor(aesgcm.runningTag, aesgcm.lenAlenC), aesgcm.h)
	aesgcm.runningTag = bwXor(aesgcm.runningTag, aesgcm.eky0)
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
	if len(nonce) != 12 {
		panic("Nonce must be 12 bytes")
	}
	// Ultimately push a bunch of this into gcm.go
	lenCiphertext := len(ciphertext) - overhead
	var ctTag = make([]byte, overhead)
	copy(ctTag, ciphertext[lenCiphertext:])
	for index := lenCiphertext; index < len(ciphertext); index++ {
		ciphertext[index] = 0
	}
	aesgcm.lenAlenC.left = uint64(len(additionalData)) * 8
	aesgcm.lenAlenC.right = uint64(lenCiphertext) * 8 // adjust for tag
	aesgcm.genICB(nonce)
	aesgcm.calcEky0()                                     // Do not remove until everything works!
	var cipher = make([]byte, 16*((lenCiphertext+15)/16)) // not exactly right?
	var index = 0

	for lenCiphertext > index {

		aesgcm.icb = incM32(aesgcm.icb)
		var xx = make([]byte, 16)

		binary.BigEndian.PutUint64(xx[0:8], aesgcm.icb.left)
		binary.BigEndian.PutUint64(xx[8:16], aesgcm.icb.right)
		var result = aesgcm.encrypt(xx)
		for i := 0; i < min(16, lenCiphertext-index); i++ {
			cipher[i+index] = ciphertext[i+index] ^ result[i]
		}
		index += 16
	}

	var freshAAD = make([]byte, 16*((len(additionalData)+15)/16))
	copy(freshAAD, additionalData)

	//var xx []byte
	//xx = make([]byte, 16*((lenCiphertext+15)/16))
	//copy(xx, ciphertext[0:lenCiphertext])  //COPY THE TAG OUT OF THE CTEXT THEN ZERO THE TRAILING BIT THEN SEND THAT TO GHASH
	aesgcm.runningTag = aesgcm.gHash(append(freshAAD, ciphertext[0:16*((lenCiphertext+15)/16)]...)) // IF ORIG CIPHERTEXT IS LESS THAN A FULL BLOCK -> PROBS!!!!

	aesgcm.runningTag = bwXMulY(bwXor(aesgcm.runningTag, aesgcm.lenAlenC), aesgcm.h)
	aesgcm.runningTag = bwXor(aesgcm.runningTag, aesgcm.eky0)
	//copy(cipher[len(ciphertext):len(ciphertext)-overhead], bWord2Bytes(aesgcm.runningTag))
	var errOpen error
	var tag = bWord2Bytes(aesgcm.runningTag)
	if !bytes.Equal(tag, ctTag) {
		errOpen = errors.New("cipher: message authentication failed")
	}
	return cipher[0 : len(ciphertext)-overhead], errOpen
}

// Reuses buffer, consumes nonce
func (aesgcm aesgcm) SimpleOpen(nonce, message, additionalData []byte) error {
	return nil
}
