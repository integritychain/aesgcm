package aesgcm

import (
	"fmt"
	"runtime/debug"
	"testing"
)

func assertEquals(t *testing.T, expected uint32, actual uint32, message interface{}) {
	if expected != actual {
		t.Error(fmt.Sprintf("Expected %v,\n    got %v\n %v", expected, actual, message))
		t.Logf(string(debug.Stack()))
	}
}

func ExampleNewInit128() {
	var instance = New().Init([]byte{0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[43])
	// Output: 09cf4f3c - b6630ca6
}

func ExampleNewInit192() {
	var instance = New().Init([]byte{0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b,
		0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[51])
	// Output: 809079e5 - 01002202
}
func ExampleNewInit256() {
	var instance = New().Init([]byte{0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d,
		0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4})
	fmt.Printf("%08x - %08x", instance.eKey[3], instance.eKey[59])
	// Output: 857d7781 - 706c631e
}

//
// Key expansion internals
//

func ExampleExpandKey() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	SetKey(initKey)
	ExpandKey()
	fmt.Printf("w[43] = %04x", w[43])
	// Output: w[43] = b6630ca6
}

func ExampleRotWord() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	var x = RotWord(initKey[3])
	fmt.Printf("Rot: input %08x  --  output %08x\n", initKey[3], x)
	// Output: Rot: input 09cf4f3c  --  output cf4f3c09
}

func ExampleSubWord() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	var x = SubWord(initKey[0])
	fmt.Printf("Sub: input %08x  --  output %08x\n", initKey[0], x)
	// Output: Sub: input 2b7e1516  --  output f1f35947
}

//
// Cipher internals
//

func ExampleSubBytes() {
	state = [4][4]byte{{0x00, 0x01, 0x02, 0x03}, {0x10, 0x11, 0x12, 0x13},
		{0x20, 0x21, 0x22, 0x23}, {0x30, 0x31, 0x32, 0x33}}
	SubBytes()
	prettyPrintState() // Following output is a bit oversensitive to spacing
	// Output: 63 7c 77 7b
	//  ca 82 c9 7d
	//  b7 fd 93 26
	//  04 c7 23 c3
}

func ExampleShiftRows() {
	state = [4][4]byte{{0x00, 0x01, 0x02, 0x03}, {0x10, 0x11, 0x12, 0x13},
		{0x20, 0x21, 0x22, 0x23}, {0x30, 0x31, 0x32, 0x33}}
	ShiftRows()
	prettyPrintState() // Following output is a bit oversensitive to spacing
	// Output: 00 01 02 03
	//  11 12 13 10
	//  22 23 20 21
	//  33 30 31 32
}

func ExampleMixColumns() {
	state = [4][4]byte{
		{0xd4, 0xe0, 0xb8, 0x1e},
		{0xbf, 0xb4, 0x41, 0x27},
		{0x5d, 0x52, 0x11, 0x98},
		{0x30, 0xae, 0xf1, 0xe5}}
	MixColumns()
	prettyPrintState()
	// Output: 04 e0 48 28
	//  66 cb f8 06
	//  81 19 d3 26
	//  e5 9a 7a 4c
}

func ExampleAddRoundKey() {
	state = [4][4]byte{
		{0xd4, 0xe0, 0xb8, 0x1e},
		{0xbf, 0xb4, 0x41, 0x27},
		{0x5d, 0x52, 0x11, 0x98},
		{0x30, 0xae, 0xf1, 0xe5}}
	MixColumns()
	AddRoundKey(1)
	prettyPrintState()
	// Output: a4 68 6b 02
	//  9c 9f 5b 6a
	//  7f 35 ea 50
	//  f2 2b 43 49
}

func ExampleRound() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	SetKey(initKey)
	ExpandKey()
	state = [4][4]byte{ // Round 1
		{0x19, 0xa0, 0x9a, 0xe9},
		{0x3d, 0xf4, 0xc6, 0xf8},
		{0xe3, 0xe2, 0x8d, 0x48},
		{0xbe, 0x2b, 0x2a, 0x08},
	}
	SubBytes()
	ShiftRows()
	MixColumns()
	AddRoundKey(1)
	prettyPrintState()
	// Output: a4 68 6b 02
	//  9c 9f 5b 6a
	//  7f 35 ea 50
	//  f2 2b 43 49
}

func ExampleEncrypt() {
	var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}
	var data = [4][4]byte{
		{0x32, 0x88, 0x31, 0xe0},
		{0x43, 0x5a, 0x31, 0x37},
		{0xf6, 0x30, 0x98, 0x07},
		{0xa8, 0x8d, 0xa2, 0x34},
	}
	Encrypt(data, initKey)
	prettyPrintState()
	// Output: 39 02 dc 19
	//  25 dc 11 6a
	//  84 09 85 0b
	//  1d fb 97 32
}
