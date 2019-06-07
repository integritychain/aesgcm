package aesgcm

import (
	"fmt"
	"math/rand"
	"testing"
)

func assertEquals(t *testing.T, expected uint64, actual uint64) {
	if expected != actual {
		t.Error(fmt.Sprintf("\nExpected   %x\nActual --> %x\n", expected, actual))
	}
}

func rev64(x uint64) uint64 {
	var result = x
	result = ((result & 0x5555555555555555) << 1) | ((result >> 1) & 0x5555555555555555)
	result = ((result & 0x3333333333333333) << 2) | ((result >> 2) & 0x3333333333333333)
	result = ((result & 0x0F0F0F0F0F0F0F0F) << 4) | ((result >> 4) & 0x0F0F0F0F0F0F0F0F)
	result = ((result & 0x00FF00FF00FF00FF) << 8) | ((result >> 8) & 0x00FF00FF00FF00FF)
	result = ((result & 0x0000FFFF0000FFFF) << 16) | ((result >> 16) & 0x0000FFFF0000FFFF)
	result = (result << 32) | (result >> 32)
	return result
}

func Test_rev64(t *testing.T) {
	var z = rev64(0x0101010101010101)
	assertEquals(t, 0x8080808080808080, z)
	for index := 0; index < 1000; index++ {
		z = rand.Uint64()
		assertEquals(t, z, rev64(rev64(z)))
	}

}

// 64-bit carry-less multiplication
func bmul64(x, y uint64) uint64 {
	x0 := x & 0x1111111111111111
	x1 := x & 0x2222222222222222
	x2 := x & 0x4444444444444444
	x3 := x & 0x8888888888888888
	y0 := y & 0x1111111111111111
	y1 := y & 0x2222222222222222
	y2 := y & 0x4444444444444444
	y3 := y & 0x8888888888888888
	z0 := x0*y0 ^ x1*y3 ^ x2*y2 ^ x3*y1
	z1 := x0*y1 ^ x1*y0 ^ x2*y3 ^ x3*y2
	z2 := x0*y2 ^ x1*y1 ^ x2*y0 ^ x3*y3
	z3 := x0*y3 ^ x1*y2 ^ x2*y1 ^ x3*y0
	z0 &= 0x1111111111111111
	z1 &= 0x2222222222222222
	z2 &= 0x4444444444444444
	z3 &= 0x8888888888888888
	return z0 | z1 | z2 | z3
}

// Slower scheme to cross-compare result equivalence to above
func xMul64(x, y uint64) uint64 {
	var result uint64
	sOperand := y
	for shift := uint(0); shift < 64; shift++ {
		if sOperand&0x0000000000000001 != 0 {
			result = result ^ (x << shift)
		}
		sOperand = sOperand >> 1
	}
	return result
}

func Test_bmul64(t *testing.T) {

	var x uint64 = 0x0000000012300088
	var y uint64 = 0x0000000012300022
	assertEquals(t, bmul64(x, y), xMul64(x, y))
	for index := 0; index < 1000; index++ {
		x = rand.Uint64() // May "overflow"...
		y = rand.Uint64()
		assertEquals(t, bmul64(x, y), xMul64(x, y))
	}
}

func bmul128t256(x1, x0, y1, y0 uint64) (uint64, uint64, uint64, uint64) {

	// Algorithm 2 from https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

	// See https://en.wikipedia.org/wiki/Karatsuba_algorithm  // Note: Thomas' z2/z1 names are swapped

	// This gives us low-order 64 bits
	z0 := bmul64(x0, y0)
	z2 := bmul64(x1, y1)
	z1 := bmul64(x1^x0, y1^y0) ^ z2 ^ z0

	// Bit-reverse the operands
	x0r := rev64(x0)
	x1r := rev64(x1)
	y0r := rev64(y0) // When this is set to H, the rev64's will not be needed
	y1r := rev64(y1)

	// This gives us (bit-reversed) high-order bits
	z0r := bmul64(x0r, y0r)
	z2r := bmul64(x1r, y1r)
	z1r := bmul64(x1r^x0r, y1r^y0r) ^ z2r ^ z0r

	// Un-reverse the high-order bits and fix bit 63 that was created twice
	z0h := rev64(z0r) >> 1
	z1h := rev64(z1r) >> 1
	z2h := rev64(z2r) >> 1

	// Merge sets of 64-bit results into "single" 256-bit result
	v0 := z0
	v1 := z0h ^ z1
	v2 := z2 ^ z1h
	v3 := z2h

	// Shift left one to fix into high order bit; TODO merge with above shifts
	v3 = (v3 << 1) | (v2 >> 63)
	v2 = (v2 << 1) | (v1 >> 63)
	v1 = (v1 << 1) | (v0 >> 63)
	v0 = v0 << 1

	return v3, v2, v1, v0

}

func saMul128t256(x1, x0, y1, y0 uint64) (uint64, uint64, uint64, uint64) {
	var r0, r1, r2, r3 uint64 // results  high index (3) = MSB
	var x2, x3 uint64
	for shift := 0; shift < 128; shift++ {
		if y0&0x0000000000000001 > 0 {
			r0 ^= x0
			r1 ^= x1
			r2 ^= x2
			r3 ^= x3
		}
		x3 = (x3 << 1) | (x2 >> 63)
		x2 = (x2 << 1) | (x1 >> 63)
		x1 = (x1 << 1) | (x0 >> 63)
		x0 = x0 << 1
		y0 = (y0 >> 1) | (y1 << 63)
		y1 = y1 >> 1
	}

	return r3, r2, r1, r0

}

func noTest_fuzz_saMul128t256(t *testing.T) { // Note: bMul shift has to be disabled
	var x1, x0 uint64 = 0x0000000000000A00, 0x00000000000000AA
	var y1, y0 uint64 = 0x1000000000100001, 0x0000000000100001

	act3, act2, act1, act0 := bmul128t256(x1, x0, y1, y0)
	fmt.Printf("%016x - %016x - %016x - %016x\n", act3, act2, act1, act0)
	act3, act2, act1, act0 = saMul128t256(x1, x0, y1, y0)
	fmt.Printf("%016x - %016x - %016x - %016x\n", act3, act2, act1, act0)

	for iteration := 0; iteration < 10000; iteration++ {
		x1 = rand.Uint64()
		x0 = rand.Uint64()
		y1 = rand.Uint64()
		y0 = rand.Uint64()
		b3, b2, b1, b0 := bmul128t256(x1, x0, y1, y0)
		s3, s2, s1, s0 := saMul128t256(x1, x0, y1, y0)
		assertEquals(t, b3, s3)
		assertEquals(t, b2, s2)
		assertEquals(t, b1, s1)
		assertEquals(t, b0, s0)

	}
}

func gHash(x1, x0 uint64, h1, h0 uint64) (uint64, uint64) {

	h0r := h0 //rev64(h1)
	h1r := h1 // rev64(h0)

	v3, v2, v1, v0 := bmul128t256(x1, x0, h1r, h0r)

	v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
	v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
	v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
	v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)

	y0 := v2
	y1 := v3

	return y1, y0
}

func Test_ghash(t *testing.T) {

	// Test case 4 on page 29 of http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
	// A = feedfacedeadbeeffeedfacedeadbeef
	// H = b83b533708bf535d0aa6e52980d53b78
	// X1 = ed56aaf8a72d67049fdb9228edba1322

	var a1, a0 uint64 = 0xfeedfacedeadbeef, 0xfeedfacedeadbeef
	var h1, h0 uint64 = 0xb83b533708bf535d, 0x0aa6e52980d53b78

	x1, x0 := gHash(a1, a0, h1, h0)
	fmt.Println("ed56aaf8a72d6704 - 9fdb9228edba1322")
	fmt.Printf("%016x - %016x\n", x1, x0)

}
