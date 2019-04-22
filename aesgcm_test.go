package aesgcm

import (
	"fmt"
	"runtime/debug"
	"testing"
)

// TODO
// 1. Test xtime and mulmod; annotate appedix C in cipher check; check test coverage
// 2. Implement inverse cipher (and key expansion?)

//
// Utils
//

func assertEquals(t *testing.T, expected uint32, actual uint32, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

func prettyPrintState(instance *aesgcm) {
	for i := 0; i < 4; i++ {
		fmt.Printf(" %02x %02x %02x %02x\n", instance.state[i][0], instance.state[i][1],
			instance.state[i][2], instance.state[i][3])
	}
}

//
// Key expansion internals - Appendix A.1, A.2 and A.3
//

func Example_rotWord() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	var x = rotWord(initKey[3])
	fmt.Printf("Rot: input %08x  --  output %08x\n", initKey[3], x)
	// Output: Rot: input 09cf4f3c  --  output cf4f3c09
}

func Example_subWord() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	var x = subWord(initKey[0])
	fmt.Printf("Sub: input %08x  --  output %08x\n", initKey[0], x)
	// Output: Sub: input 2b7e1516  --  output f1f35947
}

//
// Key expansion - Appendix A.1, A.2 and A.3
//

func ExampleNewKey128() {
	var instance = New().Key([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15,
		0x88, 0x09, 0xcf, 0x4f, 0x3c})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[43])
	// Output: 09cf4f3c - b6630ca6
}

func ExampleNewKey192() {
	var instance = New().Key([]byte{0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3,
		0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[51])
	// Output: 809079e5 - 01002202
}
func ExampleNewKey256() {
	var instance = New().Key([]byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae,
		0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10,
		0xa3, 0x09, 0x14, 0xdf, 0xf4})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[59])
	// Output: 857d7781 - 706c631e
}

//
// Cipher internals - Appendix B
//

////////////////////// Test xtime and mulMod here/////////////////////

func Example_subBytes() {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x19, 0xa0, 0x9a, 0xe9}, {0x3d, 0xf4, 0xc6, 0xf8}, {0xe3, 0xe2, 0x8d, 0x48}, {0xbe, 0x2b, 0x2a, 0x08}}
	instance.subBytes()
	prettyPrintState(instance)
	// Output: d4 e0 b8 1e
	//  27 bf b4 41
	//  11 98 5d 52
	//  ae f1 e5 30
}

func Example_shiftRows() {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0x27, 0xbf, 0xb4, 0x41}, {0x11, 0x98, 0x5d, 0x52}, {0xae, 0xf1, 0xe5, 0x30}}
	instance.shiftRows()
	prettyPrintState(instance)
	// Output: d4 e0 b8 1e
	//  bf b4 41 27
	//  5d 52 11 98
	//  30 ae f1 e5
}

func Example_mixColumns() {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0xd4, 0xe0, 0xb8, 0x1e}, {0xbf, 0xb4, 0x41, 0x27}, {0x5d, 0x52, 0x11, 0x98}, {0x30, 0xae, 0xf1, 0xe5}}
	instance.mixColumns()
	prettyPrintState(instance)
	// Output: 04 e0 48 28
	//  66 cb f8 06
	//  81 19 d3 26
	//  e5 9a 7a 4c
}

func Example_addRoundKey() {
	var instance = new(aesgcm)
	instance.state = [4][4]byte{{0x04, 0xe0, 0x48, 0x28}, {0x66, 0xcb, 0xf8, 0x06}, {0x81, 0x19, 0xd3, 0x26}, {0xe5, 0x9a, 0x7a, 0x4c}}
	instance.eKey[4], instance.eKey[5], instance.eKey[6], instance.eKey[7] = 0xa0fafe17, 0x88542cb1, 0x23a33939, 0x2a6c7605
	instance.addRoundKey(1)
	prettyPrintState(instance)
	// Output: a4 68 6b 02
	//  9c 9f 5b 6a
	//  7f 35 ea 50
	//  f2 2b 43 49
}

func ExampleAesgcm_Encrypt128() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f})
	result := instance.Encrypt([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff})
	fmt.Printf("%x", result)
	// Output: 69c4e0d86a7b0430d8cdb78070b4c55a
}

func ExampleAesgcm_Encrypt192() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17})
	result := instance.Encrypt([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff})
	fmt.Printf("%x", result)
	// Output: dda97ca4864cdfe06eaf70a0ec0d7191
}

func ExampleAesgcm_Encrypt256() {
	var instance = New().Key([]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
		0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a,
		0x1b, 0x1c, 0x1d, 0x1e, 0x1f})
	result := instance.Encrypt([]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff})
	fmt.Printf("%x", result)
	// Output: 8ea2b7ca516745bfeafc49904b496089
}
