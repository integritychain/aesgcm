package aesgcm

import (
	"encoding/binary"
)

// 128-bit block word, aligned on 64-bit boundary
type blockWord struct {
	left  uint64
	right uint64
}

func (aesgcm *aesgcm) initGcmH(key []byte) *aesgcm { // init via New
	var hBlock []byte // 16
	hBlock = aesgcm.encrypt([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	aesgcm.h.left = binary.BigEndian.Uint64(hBlock[0:8])
	aesgcm.h.right = binary.BigEndian.Uint64(hBlock[8:16])
	aesgcm.hr.left = rev64(aesgcm.h.left)
	aesgcm.hr.right = rev64(aesgcm.h.right)
	return aesgcm
}

func (aesgcm *aesgcm) initGcmY0(lenA, lenC int, iv []byte) { // init via Seal/Open
	aesgcm.lenAlenC.left = uint64(lenA) * 8
	aesgcm.lenAlenC.right = uint64(lenC) * 8
	aesgcm.icb.left = binary.BigEndian.Uint64(iv[0:8])
	aesgcm.icb.right = (uint64(binary.BigEndian.Uint32(iv[8:12])) << 32) | 0x01
	aesgcm.eky0 = bytes2bWord(aesgcm.encrypt(bWord2Bytes(aesgcm.icb)))
}

func (aesgcm *aesgcm) cipherBlocks(message, dst []byte) {
	var Y = make([]byte, 16)
	var result []byte
	for index := 0; index < len(message); index = index + 16 {
		Y = bWord2Bytes(plusM32(aesgcm.icb, uint32(1+index/16)))
		result = aesgcm.encrypt(Y)
		for i := 0; i < min(16, len(message)-index); i++ {
			dst[i+index] = message[i+index] ^ result[i]
		}
	}
}

func (aesgcm *aesgcm) gHash(blocks []byte, yIn blockWord) blockWord {

	yOut := yIn
	for index := 0; index < 16*(len(blocks)/16); index = index + 16 {
		yOut = aesgcm.gMul(bwXor(yOut, bytes2bWord(blocks[index:index+16])))
	}
	if len(blocks)%16 > 0 {
		var tempData = make([]byte, 16)
		copy(tempData, blocks[16*(len(blocks)/16):])
		yOut = aesgcm.gMul(bwXor(yOut, bytes2bWord(tempData)))
	}
	return yOut
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

func bwXor(a, b blockWord) blockWord {
	a.right = a.right ^ b.right
	a.left = a.left ^ b.left
	return a
}

func bWord2Bytes(x blockWord) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], x.left)
	binary.BigEndian.PutUint64(b[8:16], x.right)
	return b
}

func bytes2bWord(x []byte) blockWord {
	var result blockWord
	result.left = binary.BigEndian.Uint64(x[0:8])
	result.right = binary.BigEndian.Uint64(x[8:16])
	return result
}

func plusM32(x blockWord, y uint32) blockWord {
	var z blockWord
	z = x
	z.right = (0xFFFFFFFF00000000 & z.right) | (0x00000000FFFFFFFF & (z.right + uint64(y)))
	return z
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

// 64-bit carry-less multiplication
func bMul64(x, y uint64) uint64 {
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

func (aesgcm *aesgcm) gMul(x blockWord) blockWord {
	var result blockWord

	// Algorithm 2 from https://software.intel.com/sites/default/files/managed/72/cc/clmul-wp-rev-2.02-2014-04-20.pdf

	// See https://en.wikipedia.org/wiki/Karatsuba_algorithm  // Note: Thomas' z2/z1 names are swapped

	// This gives us low-order 64 bits
	z0 := bMul64(x.right, aesgcm.h.right)
	z2 := bMul64(x.left, aesgcm.h.left)
	z1 := bMul64(x.left^x.right, aesgcm.h.left^aesgcm.h.right) ^ z2 ^ z0

	// Bit-reverse the operands
	x0r := rev64(x.right)
	x1r := rev64(x.left)
	y0r := aesgcm.hr.right
	y1r := aesgcm.hr.left

	// This gives us (bit-reversed) high-order bits
	z0r := bMul64(x0r, y0r)
	z2r := bMul64(x1r, y1r)
	z1r := bMul64(x1r^x0r, y1r^y0r) ^ z2r ^ z0r

	// Un-reverse the high-order bits and fix bit 63 that was created twice
	z0h := rev64(z0r) >> 1
	z1h := rev64(z1r) >> 1
	z2h := rev64(z2r) >> 1

	// Merge sets of 64-bit results into "single" 256-bit result
	v0 := z0
	v1 := z0h ^ z1
	v2 := z2 ^ z1h
	v3 := z2h

	// Shift left one to fix into high order bit
	v3 = (v3 << 1) | (v2 >> 63)
	v2 = (v2 << 1) | (v1 >> 63)
	v1 = (v1 << 1) | (v0 >> 63)
	v0 = v0 << 1

	// Reduction
	v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
	v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
	v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7)
	v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57)

	result.right = v2
	result.left = v3

	return result
}
