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
