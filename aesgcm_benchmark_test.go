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

var additionalData, plaintext, nonce, key, dst, dstG, dst1 []byte
var instance1, instanceG cipher.AEAD

func init1() {
	additionalData = make([]byte, 8192)
	plaintext = make([]byte, 16)
	nonce = make([]byte, 12)
	dst = make([]byte, 16+16)
	key = make([]byte, 16)
	rand.Read(key)
	rand.Read(additionalData)
	rand.Read(plaintext)
	rand.Read(nonce)
	dst1 = make([]byte, 16+16)
	dstG = make([]byte, 16+16)

}

func BenchmarkSealG(b *testing.B) {
	init1()

	block, _ := aes.NewCipher(key)
	instanceG, _ = cipher.NewGCM(block)
	for n := 0; n < b.N; n++ {
		dstG = instanceG.Seal(dst1, nonce, plaintext, additionalData)
	}
}

func BenchmarkSeal1(b *testing.B) {
	init1()

	instance1 = NewAESGCM(key)
	for n := 0; n < b.N; n++ {
		dst1 = instance1.Seal(dstG, nonce, plaintext, additionalData)
	}
}
