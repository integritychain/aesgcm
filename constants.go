package aesgcm

var rMSB uint64 = 0xe1 << (120 - 64) // 0b11100001
var rLSB uint64
var one uint64 = 1

type bWord struct {
	msb uint64
	lsb uint64
}

func bXor(a, b bWord) bWord {
	var c bWord
	c.lsb = a.lsb ^ b.lsb
	c.msb = a.msb ^ b.msb
	return c
}

func bShift1(a bWord) bWord { // shift to right
	var c bWord
	c.lsb = a.lsb >> 1
	if a.msb&0x01 != 0 { // lsBit will move across
		c.lsb = c.lsb | (1 << 63)
	}
	c.msb = a.msb >> 1
	return c
}

func bTest(a bWord, i uint) bool {
	if i > 63 {
		return a.msb&(1<<(i-64)) != 0
	} else {
		return a.lsb&(1<<i) != 0
	}
}

func algorithm1(x, y bWord) bWord {
	var R = bWord{0xe1 << (120 - 64), 0}
	var z = bWord{0, 0}
	var v = y
	for index := uint(0); index < 128; index++ {
		if bTest(x, index) {
			z = bXor(z, v)
		}
		if bTest(v, 0) {
			v = bXor(bShift1(v), R)
		} else {
			v = bShift1(v)
		}
	}
	return z
}

func add12(x, y uint32) uint32 {
	if rMSB+rMSB < rMSB { // A carry out happened
		x = x + 1
	}
	return x + y + 1
}
