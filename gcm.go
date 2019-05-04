package aesgcm

import (
	"encoding/binary"
)

// 128-bit block word
type blockWord struct {
	left  uint64
	right uint64
}

func (aesgcm *aesgcm) initializeH(key []byte) *aesgcm {
	var hBlock []byte // 16
	hBlock = aesgcm.encrypt([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	aesgcm.h.left = binary.BigEndian.Uint64(hBlock[0:8])
	aesgcm.h.right = binary.BigEndian.Uint64(hBlock[8:16])
	return aesgcm
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

func bwXor(a, b blockWord) blockWord {
	var c blockWord
	c.right = a.right ^ b.right
	c.left = a.left ^ b.left
	return c
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
	var R = blockWord{0xe1 << (120 - 64), 0}
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

// Algorithm 2: GHASH function on pg 12 -- note currently unused
//func (aesgcm *aesgcm) gHash(blocks []blockWord) blockWord {
func (aesgcm *aesgcm) gHash(blocks []byte) blockWord {

	var y blockWord
	for index := 0; index < len(blocks); index = index + 16 {
		y = bwXMulY(bwXor(y, bytes2bWord(blocks[index:index+16])), aesgcm.h)
	}
	return y
}

// generate ICB - currently hardcoded for 12-byte IV
func (aesgcm *aesgcm) genICB(iv []byte) {
	var j0 blockWord
	j0.left = binary.BigEndian.Uint64(iv[0:8])
	j0.right = (uint64(binary.BigEndian.Uint32(iv[8:12])) << 32) | 0x01
	aesgcm.icb = j0 // incM32(j0)
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

func incM32(x blockWord) blockWord {
	var z blockWord
	z.left = x.left
	var inc = uint32(x.right + 1) // chop off lower right side and increment
	z.right = (x.right & 0xffffffff00000000) | uint64(inc)
	return z
}

func (aesgcm *aesgcm) calcEky0() {
	aesgcm.eky0 = bytes2bWord(aesgcm.encrypt(bWord2Bytes(aesgcm.icb)))
}
