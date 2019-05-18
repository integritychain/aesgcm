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
	aesgcm.genTable()
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

// Algorithm 2: GHASH function on pg 12
func (aesgcm *aesgcm) gHash(blocks []byte, yIn blockWord) blockWord {

	yOut := yIn
	for index := 0; index < 16*(len(blocks)/16); index = index + 16 {
		yOut = aesgcm.bwXMulY2(bwXor(yOut, bytes2bWord(blocks[index:index+16])), aesgcm.h)

	}
	if len(blocks)%16 > 0 {
		var tempData = make([]byte, 16)
		copy(tempData, blocks[16*(len(blocks)/16):])
		yOut = aesgcm.bwXMulY2(bwXor(yOut, bytes2bWord(tempData)), aesgcm.h)
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

func bwXor2(a *blockWord, b blockWord) {
	a.right = a.right ^ b.right
	a.left = a.left ^ b.left
}

func bwRightShift1(a blockWord) blockWord {
	a.right = a.right >> 1
	if a.left&0x01 != 0 { // left LSB will move across
		a.right = a.right | (1 << 63)
	}
	a.left = a.left >> 1
	return a
}

// Note that indexing is swapped (bit 0 on left)
func bwTestBit(a blockWord, index uint) bool {
	if index < 64 {
		return a.left&(1<<(63-index)) != 0
	} else {
		return a.right&(1<<(127-index)) != 0
	}
}

// Algorithm 1: X * Y on pg 11-12
func bwXMulY(x, y blockWord) blockWord {
	var R = blockWord{0xe1 << (120 - 64), 0} // faster to have R as local var
	var z = blockWord{0, 0}
	var v = y // To stay consistent with spec naming
	for index := uint(0); index < 128; index++ {
		if bwTestBit(x, index) {
			z = bwXor(z, v)
		}
		if bwTestBit(v, 127) { // Index 127 is LSB
			v = bwXor(bwRightShift1(v), R)
		} else {
			v = bwRightShift1(v)
		}
	}
	return z
}

func (aesgcm *aesgcm) bwXMulY2(x, y blockWord) blockWord {
	var actual1, actual2 blockWord
	actual1 = bwXor(actual1, aesgcm.M[15][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[7][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[14][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[6][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[13][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[5][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[12][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[4][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[11][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[3][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[10][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[2][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[9][byte(x.right)])
	x.right = x.right >> 8
	actual2 = bwXor(actual2, aesgcm.M[1][byte(x.left)])
	x.left = x.left >> 8
	actual1 = bwXor(actual1, aesgcm.M[8][byte(x.right)])
	actual2 = bwXor(actual2, aesgcm.M[0][byte(x.left)])
	return bwXor(actual1, actual2)
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

func (aesgcm *aesgcm) genTable() {
	h := aesgcm.h

	for outer := uint(0); outer < 128; outer = outer + 8 {
		for i := 0; i < 256; i++ {
			var a blockWord
			if outer > 56 {
				a.right = uint64(i << (120 - outer))
			} else {
				a.left = uint64(i << (56 - outer))
			}
			aesgcm.M[outer/8][i] = bwXMulY(a, h)
		}
	}
}
