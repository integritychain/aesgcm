package aesgcm

import (
	"encoding/binary"
	"fmt"
	"strconv"
)

type bWord struct {
	left  uint64
	right uint64
}

func min(x, y int) int {
	if x > y {
		return y
	}
	return x
}

func bXor(a, b bWord) bWord {
	var c bWord
	c.right = a.right ^ b.right
	c.left = a.left ^ b.left
	return c
}

func rShift1(a bWord) bWord { // shift to right
	var c bWord
	c.right = a.right >> 1
	if a.left&0x01 != 0 { // lsBit will move across
		c.right = c.right | (1 << 63)
	}
	c.left = a.left >> 1
	return c
}

func bTest(a bWord, i uint) bool { // leftmost bit is bit 0
	if i < 64 {
		return a.left&(1<<(63-i)) != 0
	} else {
		return a.right&(1<<(127-i)) != 0
	}
}

// Algorithm 1: X * Y
func xMuly(x, y bWord) bWord {
	var R = bWord{0xe1 << (120 - 64), 0}
	var z = bWord{0, 0}
	var v = x
	for index := uint(0); index < 128; index++ {
		if bTest(y, index) {
			z = bXor(z, v)
		}
		if bTest(v, 127) {
			v = bXor(rShift1(v), R)
		} else {
			v = rShift1(v)
		}
	}
	return z
}

func (aesgcm *aesgcm) initH(key []byte) *aesgcm {
	res := aesgcm.encrypt([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	var state = fmt.Sprintf("%32x", res)
	//fmt.Println(state)
	left, err := strconv.ParseUint(state[0:16], 16, 64)
	if err != nil {
		panic("Prob 1")
	}
	right, err := strconv.ParseUint(state[16:32], 16, 64)
	if err != nil {
		panic("Prob 2")
	}
	aesgcm.h.left, aesgcm.h.right = left, right
	return aesgcm
}

// Algorithm2: GHASH
func (aesgcm *aesgcm) gHash(blocks []bWord) bWord {
	var y bWord
	for index := 0; index < len(blocks); index++ {
		y = xMuly(bXor(y, blocks[index]), aesgcm.h)
	}
	return y
}

var icb bWord

// generate ICB
func (aesgcm *aesgcm) genICB(iv [3]uint32) {
	var j0 bWord
	j0.left = (uint64(iv[0]) << 32) | uint64(iv[1])
	j0.right = (uint64(iv[2]) << 32) | 0x01
	aesgcm.icb = j0 // incM32(j0)
}

func bWord2Bytes(x bWord) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], x.left)
	binary.BigEndian.PutUint64(b[8:16], x.right)
	return b
}

func bytes2bWord(x []byte) bWord {
	var result bWord
	result.left = binary.BigEndian.Uint64(x[0:8])
	result.right = binary.BigEndian.Uint64(x[8:16])
	return result
}

func incM32(x bWord) bWord {
	var z bWord
	z.left = x.left
	var inc = uint32(x.right + 1) // chop off lower right side and increment
	z.right = (x.right & 0xffffffff00000000) | uint64(inc)
	return z
}

func (aesgcm *aesgcm) calcEky0() {
	aesgcm.eky0 = bytes2bWord(aesgcm.encrypt(bWord2Bytes(aesgcm.icb)))
}
