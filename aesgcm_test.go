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
	var x = SubBytes(initKey[0])
	fmt.Printf("Sub: input %08x  --  output %08x\n", initKey[0], x)
	// Output: Sub: input 2b7e1516  --  output f1f35947
}

func ExampleMixColumns() {
	var initState = [4][4]byte{
		{0xd4, 0xe0, 0xb8, 0x1e},
		{0xbf, 0xb4, 0x41, 0x27},
		{0x5d, 0x52, 0x11, 0x98},
		{0x30, 0xae, 0xf1, 0xe5}}
	nextState := MixColumns(initState)
	prettyPrintState(nextState)

	t0 := (0xd4 * 0x02) % 17
	t1 := (0xbf * 0x03) % 17
	t2 := 0x5d
	t3 := 0x30
	fmt.Printf("%x", t0^t1^t2^t3)
	// Output: asdf
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
	//  23 20 21 22

}
