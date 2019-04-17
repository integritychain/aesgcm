package aesgcm

import (
	"fmt"
)

func ExampleRotWord() {
	var x = RotWord(initKey[3])
	fmt.Printf("Rot: before: %v\nafter:  %v\n", initKey[3], x)
	// Output: asf
}

func ExampleSubWord() {
	var x = SubWord(initKey[0])
	fmt.Printf("Sub: before: %v\nafter:  %v", initKey, x)
	// Output: asdf
}
