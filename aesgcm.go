package aesgcm

import (
	"bytes"
	"encoding/binary"
	"errors"
)

// TODO:
//  2. Name internal variables to match spec
//  3. Clean-up code further...
//  4. Benchmark vs Golang
//  6. SIMPLIFY, TUNE!!!

type Aesgcm interface {
	Encrypt(additionalData, message []byte) (initVector, tag []byte, err error)
	DecryptAndVerify(initVector, tag []byte, additionalData, message []byte) (err error)
	IVSizeBytes() (size uint)
	SetIVSizeBytes(size uint)
	SetIV(iv []byte)
	TagSizeBytes() (size uint)
}

type aesgcm struct {
	iv          []byte
	ready       bool
	ivSize      uint
	tagSize     uint
	cb          []blockWord
	expandedKey [60]uint32
	nk          int // Number of words in expandKey
	nr          int // Number of rounds
	state       [4][4]byte
	h           blockWord
	icb         blockWord
	eky0        blockWord
	lenAlenC    blockWord
	runningTag  blockWord
}

func New(key []byte) Aesgcm {
	if (len(key) != 16) && (len(key) != 24) && (len(key) != 32) {
		panic("Aesgcm does not support key lengths other than 128, 192 or 256 bits")
	}
	var aesgcm = new(aesgcm)
	aesgcm.ivSize = 12
	aesgcm.tagSize = 16
	aesgcm.expandKey(key) // aes
	aesgcm.initH(key)     // gcm
	return aesgcm
}

func (aesgcm *aesgcm) IVSizeBytes() (size uint) {
	size = aesgcm.ivSize
	return size
}

func (aesgcm *aesgcm) TagSizeBytes() (size uint) {
	size = aesgcm.tagSize
	return size
}

func (aesgcm *aesgcm) SetIVSizeBytes(size uint) {
	if size < 12 {
		panic("Aesgcm does not support IV sizes less than 96 bits")
	} // Better add logic to compute longer IVs
	aesgcm.ivSize = size
}

func (aesgcm *aesgcm) SetIV(iv []byte) {
	if len(iv) != 12 {
		panic("Aesgcm iv must be 12 bytes")
	}
	aesgcm.iv = iv
}

func (aesgcm *aesgcm) Encrypt(additionalData, message []byte) (initVector, tag []byte, err error) {
	initVector = aesgcm.initGCM(len(additionalData), len(message))

	//var partial []byte
	var numBlocks = len(message) / 16                // Number of full blocks in play
	var maxThreads = 6                               // Max number of threads we can throw at it
	var numThreads = min(maxThreads, numBlocks/10+1) // No sense in kicking off a large number of tiny threads; require 10 blocks before doing anything more
	var blocksPerThread = numBlocks / numThreads     // Each thread has to handle this many blocks (the last will have extra fractional work)

	// Simulate kicking off multiple threads for now // PROBABLY WANT TO KICK OFF AAD FIRST?
	for index := 0; index < numThreads-1; index++ {
		aesgcm.doBlocks(message[index*blocksPerThread*16:(index+1)*blocksPerThread*16], index*blocksPerThread+1)
	}
	var lastFullBlock = len(message) - len(message)%16
	if lastFullBlock > 0 {
		aesgcm.doBlocks(message[(numThreads-1)*blocksPerThread*16:lastFullBlock], (numThreads-1)*blocksPerThread+1)
	}
	var remaining = len(message) % 16
	var xx []byte
	if remaining > 0 {
		xx = make([]byte, 16)
		aesgcm.doBlocks(xx, len(message)/16+1)
	}
	for index := 0; index < remaining; index++ {
		message[16*(len(message)/16)+index] = message[16*(len(message)/16)+index] ^ xx[index]
	}
	// calc tag
	return initVector, nil, nil
}

func (aesgcm *aesgcm) doBlocks(message []byte, cbStart int) (partial []byte) {
	var xx []byte
	partial = make([]byte, 16)

	var result []byte
	for index := 0; index < len(message); index = index + 16 {
		xx = bWord2Bytes(aesgcm.cb[index/16+cbStart])
		result = aesgcm.encrypt(xx)
		for i := 0; i < min(16, len(message)-index); i++ {
			message[i+index] = message[i+index] ^ result[i]
		}
	}
	for i := 16 * (len(message) / 16); i < len(message); i++ {
		partial[i%16] = result[i%16]
	}

	return partial
}

func (aesgcm *aesgcm) DecryptAndVerify(initVector, tag []byte, additionalData, message []byte) (err error) {
	panic("implement me")
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
	newAESGCM.initH(key)
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

	aesgcm.runningTag = aesgcm.gHash(append(freshAAD, ciphertext[0:16*((lenCiphertext+15)/16)]...)) // IF ORIG CIPHERTEXT IS LESS THAN A FULL BLOCK -> PROBS!!!!

	aesgcm.runningTag = bwXMulY(bwXor(aesgcm.runningTag, aesgcm.lenAlenC), aesgcm.h)
	aesgcm.runningTag = bwXor(aesgcm.runningTag, aesgcm.eky0)
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
