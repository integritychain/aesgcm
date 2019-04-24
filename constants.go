package aesgcm

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

func algorithm1(x, y bWord) bWord {
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

func incM32(x bWord) bWord {
	var z bWord
	z.left = x.left
	var inc = uint32(x.right + 1) // chop off lower right side and increment
	z.right = (x.right & 0xffffffff00000000) | uint64(inc)
	return z
}
