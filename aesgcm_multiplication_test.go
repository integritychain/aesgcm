package aesgcm

import (
	"fmt"
	"math/rand"
	"testing"
)

func bwPrint(name string, x blockWord) {
	fmt.Printf("%3v %016x\n", name, x)
}

func bwShiftRight8(x blockWord) blockWord {
	var z blockWord
	z.right = x.right >> 8
	z.right = z.right | ((x.left & 0x000000FF) << 56)
	z.left = x.left >> 8
	return z
}

func TestAesgcm_XMulY(t *testing.T) {

	var M [16][256]blockWord
	key := make([]byte, 16)
	rand.Read(key)
	instance := NewAESGCM(key)
	h := instance.(*aesgcm).h

	for outer := uint(0); outer < 128; outer = outer + 8 {
		for i := 0; i < 256; i++ {
			var a blockWord
			if outer > 56 {
				a.right = uint64(i << (120 - outer))
			} else {
				a.left = uint64(i << (56 - outer))
			}
			M[outer/8][i] = bwXMulY(a, h)
		}
	}

	fmt.Println("done with table, man!")

	operandA := blockWord{0xFFEEDDCCBBAA9988, 0X7766554433221100}
	//operandA :=blockWord{0x8899000000000000, 0X0000000000000000}

	var actual blockWord
	for outer := uint(0); outer < 128; outer = outer + 8 {
		var x byte
		if outer > 56 {
			x = byte(operandA.right >> (120 - outer))
			actual = bwXor(actual, M[outer/8][x])
		} else {
			x = byte(operandA.left >> (56 - outer))
			actual = bwXor(actual, M[outer/8][x])
			bwPrint(" ac", actual)
		}
		fmt.Printf("%02x", x)
	}

	//operandA := blockWord{uint64(0x99880000) << 32, 0}
	bwPrint("opA", operandA)
	//bwPrint("  h", h)
	expected := bwXMulY(operandA, h)
	//t0 := M[0x99]
	//bwPrint(" t0", t0)
	//t1 := M1[0x88] //bwShiftRight8(M1[0x88])
	//bwPrint(" t1", t1)
	//actual := bwXor(t0, t1)
	bwPrint("act", actual)
	bwPrint("exp", expected)
	//
	//
	//if expected == actual {
	//	fmt.Println("it works man")
	//}

}
