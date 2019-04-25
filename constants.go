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

var H bWord

func initH(key []byte) {
	//var left, right
	var instance = New().Key(key)
	res := instance.Encrypt([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	var state = fmt.Sprintf("%32x", res)
	//fmt.Println(state)
	left, err := strconv.ParseUint(state[0:15], 16, 64)
	if err != nil {
		LogFatal("Prob 1")
	}
	right, err := strconv.ParseUint(state[16:32], 16, 64)
	if err != nil {
		LogFatal("Prob 2")
	}
	H.left, H.right = left, right
}

// Algorithm2: GHASH
func gHash(blocks []bWord) bWord {
	var y bWord
	for index := 0; index < len(blocks); index++ {
		y = xMuly(bXor(y, blocks[index]), H)
	}
	return y
}

var icb bWord

// generate ICB
func genICB(iv [3]uint32) {
	var j0 bWord
	j0.left = (uint64(iv[0]) << 32) | uint64(iv[1])
	j0.right = (uint64(iv[2]) << 32) | 0x01
	icb = j0 // incM32(j0)
}

func bWord2Bytes(x bWord) []byte {
	b := make([]byte, 16)
	binary.BigEndian.PutUint64(b[0:8], x.left)
	binary.BigEndian.PutUint64(b[8:16], x.right)
	return b
}

func eKY0() { // Test case 3
	var keyW = bWord{0xfeffe9928665731c, 0x6d6a8f9467308308}
	var key = bWord2Bytes(keyW)
	var instance = New().Key(key)
	genICB([3]uint32{0xcafebabe, 0xfacedbad, 0xdecaf888})
	result := instance.Encrypt(bWord2Bytes(icb))
	fmt.Printf("%x", result)
}

// Algorithm 3: GCTR ................ not yet ......

func incM32(x bWord) bWord {
	var z bWord
	z.left = x.left
	var inc = uint32(x.right + 1) // chop off lower right side and increment
	z.right = (x.right & 0xffffffff00000000) | uint64(inc)
	return z
}