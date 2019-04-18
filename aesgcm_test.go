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
