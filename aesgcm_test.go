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

func prettyPrintState(state [4][4]byte) {
	for i := 0; i < 4; i++ {
		fmt.Printf(" %02x %02x %02x %02x\n", state[i][0], state[i][1], state[i][2], state[i][3])
	}
}

func ExampleRotWord() {
	var x = RotWord(initKey[3])
	fmt.Printf("Rot: input %08x  --  output %08x\n", initKey[3], x)
	// Output: Rot: input 09cf4f3c  --  output cf4f3c09
}

func ExampleSubWord() {
	var x = SubWord(initKey[0])
	fmt.Printf("Sub: input %08x  --  output %08x\n", initKey[0], x)
	// Output: Sub: input 2b7e1516  --  output f1f35947
}

func ExampleMath() {
	fmt.Printf("%02x", byte(MulMod(0x49, 0x02)^MulMod(0xdb, 0x03)^0x87^0x3b))
	fmt.Printf("%02x", byte(MulMod(0xd4, 0x02)^MulMod(0xbf, 0x03)^0x5d^0x30))
	// Output: 5804

}

func ExampleMixColumns() {
	var initState = [4][4]byte{
		{0xd4, 0xe0, 0xb8, 0x1e},
		{0xbf, 0xb4, 0x41, 0x27},
		{0x5d, 0x52, 0x11, 0x98},
		{0x30, 0xae, 0xf1, 0xe5}}
	nextState := MixColumns(initState)
	prettyPrintState(nextState)
	// Output: 04 e0 48 28
	//  66 cb f8 06
	//  81 19 d3 26
	//  e5 9a 7a 4c

}

func ExampleAddRoundKey() {
	var initState = [4][4]byte{
		{0xd4, 0xe0, 0xb8, 0x1e},
		{0xbf, 0xb4, 0x41, 0x27},
		{0x5d, 0x52, 0x11, 0x98},
		{0x30, 0xae, 0xf1, 0xe5}}
	interState := MixColumns(initState)
	nextState := AddRoundKey(interState, 1)
	prettyPrintState(nextState)
	// Output: a4 68 6b 02
	//  9c 9f 5b 6a
	//  7f 35 ea 50
	//  f2 2b 43 49
}

func ExampleRound() {
	SetKey(initKey)
	ExpandKey()
	var initState = [4][4]byte{ // Round 1
		{0x19, 0xa0, 0x9a, 0xe9},
		{0x3d, 0xf4, 0xc6, 0xf8},
		{0xe3, 0xe2, 0x8d, 0x48},
		{0xbe, 0x2b, 0x2a, 0x08},
	}
	afterSub := SubBytes(initState)
	afterShift := ShiftRows(afterSub)
	afterMix := MixColumns(afterShift)
	nextState := AddRoundKey(afterMix, 1)
	prettyPrintState(nextState)
	// Output: a4 68 6b 02
	//  9c 9f 5b 6a
	//  7f 35 ea 50
	//  f2 2b 43 49

}

var initKey = [4]uint32{0x2b7e1516, 0x28aed2a6, 0xabf71588, 0x09cf4f3c}

func TestSetKey(t *testing.T) {
	SetKey(initKey)
	assertEquals(t, initKey[0], w[0], "bad key 0")
	assertEquals(t, initKey[1], w[1], "bad key 1")
	assertEquals(t, initKey[2], w[2], "bad key 2")
	assertEquals(t, initKey[3], w[3], "bad key 3")
}

func TestExpandKey(t *testing.T) {
	SetKey(initKey)
	ExpandKey()
	assertEquals(t, 0xb6630ca6, w[43], fmt.Sprintf("Key 43 was %08x", w[43]))
}

func ExampleShiftRows() {
	var initState = [4][4]byte{{0x00, 0x01, 0x02, 0x03}, {0x10, 0x11, 0x12, 0x13},
		{0x20, 0x21, 0x22, 0x23}, {0x30, 0x31, 0x32, 0x33}}
	nextState := ShiftRows(initState)
	prettyPrintState(nextState) // Following output is a bit oversensitive to spacing
	// Output: 00 01 02 03
	//  11 12 13 10
	//  22 23 20 21
	//  33 30 31 32

}
