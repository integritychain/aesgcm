package aesgcm

// go test -bench .

// go test -run=x -bench=BenchmarkSeal1
// go test -run=^$ -bench=BenchmarkSeal1 -cpuprofile=cpu.out
// go tool pprof aesgcm.test cpu.out
// web

import (
	"crypto/aes"
	"crypto/cipher"
	"math/rand"
	"testing"
)

var additionalData, plaintext, nonce, key, dst []byte
var instance1, instanceG cipher.AEAD

func init() {
	additionalData = make([]byte, 8192)
	plaintext = make([]byte, 16)
	nonce = make([]byte, 12)
	dst = make([]byte, 16+16)
	key = make([]byte, 16)
	rand.Read(key)
	rand.Read(additionalData)
	rand.Read(plaintext)
	rand.Read(nonce)
	instance1 = NewAESGCM(key)
	block, _ := aes.NewCipher(key)
	instanceG, _ = cipher.NewGCM(block)
}

func BenchmarkSeal1(b *testing.B) {

	for n := 0; n < b.N; n++ {
		instance1.Seal(dst, nonce, plaintext, additionalData)
	}
}

func BenchmarkSealG(b *testing.B) {

	for n := 0; n < b.N; n++ {
		instanceG.Seal(dst, nonce, plaintext, additionalData)
	}
}
