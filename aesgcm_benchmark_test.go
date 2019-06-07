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
	additionalData = make([]byte, 100000)
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

// Initial condition   BenchmarkSeal1-8   	     300	   5378404 ns/op
// rough Mul           BenchmarkSeal1-8   	    1000	   1511050 ns/op
// take key from loop  BenchmarkSeal1-8   	   10000	    214809 ns/op
// NOW:
// BenchmarkSealG-8   	  200000	      8418 ns/op
// BenchmarkSeal1-8   	   10000	    214944 ns/op  -> 25X slower
// Flatten loop
// BenchmarkSeal1-8   	   10000	    140629 ns/op  -> 17X slower
// shift then xor
// BenchmarkSeal1-8   	   10000	    134772 ns/op  -> 16X slower
// Constant time
// BenchmarkSeal1-8   	    3000	    419957 ns/op

func BenchmarkSeal1(b *testing.B) {
	init1()
	instance1 = NewAESGCM(key)
	for n := 0; n < b.N; n++ {
		dst1 = instance1.Seal(dstG, nonce, plaintext, additionalData)
	}
}
